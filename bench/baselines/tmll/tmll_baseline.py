#!/usr/bin/env python3
"""TMLL + LLM baseline on the symptom bench, adapted from the CASCON experiment
(../cascon_original/tmll_baseline; its sources are on the CASCON repo's `tmll` branch).

TMLL analyses the whole kernel trace through a plain Trace Compass Trace Server (no
TraceAssist plug-in); an LLM reads TMLL's structured results and answers one question per call.
The LLM does not choose tools or investigate further.

Changes from CASCON, and nothing else:
  - the traces are the bench's 56 runs (runs/<id>/trace/kernel), labelled by run id;
  - the "workload" whose threads get the full detail is the program the questions name (every
    bench question names its program, the run id's prefix): its process, its threads, and its
    child processes, read from TMLL's Thread Status. CASCON had batch_server's thread names
    hard-coded;
  - every bench question is asked, with the verdict line (verdict.py), one call per pair, and
    each answer is saved where score.py reads it: results/tmll/run1/<id>.json;
  - the model is gpt-6-luna, as for TraceAssist.

  ../.venv/bin/python tmll_baseline.py prepare [--trace <run id> ...]   # TMLL evidence, no API
  ../.venv/bin/python tmll_baseline.py run --dry-run
  ../.venv/bin/python tmll_baseline.py run                              # results/tmll/run1/

prepare needs the CASCON TMLL checkout and environment (--tmll-source, --tmll-python) and a
Trace Server (default localhost:8080). Only trace/kernel is imported. No ground truth, program
log, answer key, RAG document or other system's answer is read.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common  # noqa: E402  (the bench baselines' shared code)

EVIDENCE_DIR = HERE / "evidence"
SYSTEM = "tmll"
# Plain upstream TMLL (eclipse-tmll/tmll at 61d408b, as in the prototype study), not TraceAssist's
# fork: clone it to <repo>/third_party/tmll-upstream with its own .venv, or set TMLL_UPSTREAM.
TMLL_UPSTREAM = Path(os.environ.get("TMLL_UPSTREAM", HERE.parents[2] / "third_party" / "tmll-upstream"))
# Same answering instruction as llm_baseline and RAG_baseline; only the input differs.
SYSTEM_PROMPT = (
    "You are an expert in Linux kernel tracing and performance analysis. The user message "
    "contains structured results from TMLL analyses of an LTTng kernel trace (Trace Compass "
    "trace server outputs, sampled at the resolutions they state), followed by one question "
    "about it. Answer the question using only these results. Be specific: name processes and "
    "threads (with their TIDs), CPUs, system calls and durations where relevant. If the "
    "results are not enough to answer with confidence, say so and explain what is missing, "
    "then give your best answer."
)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sample_indices(length, limit):
    if length <= limit:
        return list(range(length))
    if limit == 1:
        return [length // 2]
    return [i * (length - 1) // (limit - 1) for i in range(limit)]


# The workload's thread names. Set per trace by set_focus() (the program the questions name and
# its threads); CASCON had r"batch_server|worker-\d+|flusher" here.
FOCUS_PATTERN = re.compile(r"(?!x)x")
PROGRAM = None
# Thread groups: when the program has more threads of one name than the per-output entity limit
# (jobrunner-d890 has 2,998 job-worker threads), only that many of them, evenly spread by TID,
# get full detail; the others are left out one by one and summed as a group (group_state_totals,
# group_tree_totals). Set only while build_evidence runs, so collection is unchanged; in every
# other trace no thread name is that common, so their evidence is unchanged too.
GROUP_TIDS = {}           # tid -> name, every thread of a grouped name (shown or not)
GROUPED_OUT = frozenset()  # the grouped threads that are not shown one by one


def set_focus(program, thread_names=()):
    """Make `program` and the named threads the workload: they keep full detail in the evidence."""
    global FOCUS_PATTERN, PROGRAM
    PROGRAM = program
    names = sorted({program, *thread_names}, key=len, reverse=True)
    FOCUS_PATTERN = re.compile("|".join(rf"(?<![\w-]){re.escape(n)}(?![\w-])" for n in names))
CPU_ENTRY = re.compile(r"^CPU \d+( Threads| States)?$")
HISTOGRAM_EDGES_MS = (0, 1, 2, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 80, 100, 200, 500, 1000)


def workload_threads(names):
    """{tid: name} for the workload's threads, from Thread Status entry names
    ("<name> <tid> <pid> <ppid>"): every thread of a process whose main thread is named PROGRAM,
    and of its child processes (and theirs). The program's threads may have any names (calc-0,
    client-1, ...), so they are found by process id, not by name."""
    entries = []
    for name in names:
        parts = str(name).split()
        if len(parts) >= 4 and all(p.isdigit() for p in parts[-3:]):
            entries.append((" ".join(parts[:-3]), *parts[-3:]))
    pids = {pid for thread, tid, pid, _ in entries if thread == PROGRAM and tid == pid}
    while True:  # child processes: a main thread whose parent is one of ours
        more = {pid for _, tid, pid, ppid in entries if tid == pid and ppid in pids} - pids
        if not more:
            break
        pids |= more
    return {tid: thread for thread, tid, pid, _ in entries if pid in pids}


def thread_groups(threads, limit):
    """{name: sorted tids} for thread names with more than `limit` threads, and the tids that
    keep full detail: `limit` per name, evenly spread by TID."""
    by_name = {}
    for tid, name in threads.items():
        by_name.setdefault(name, []).append(tid)
    groups = {name: sorted(tids, key=int) for name, tids in by_name.items() if len(tids) > limit}
    shown = {name: [tids[i] for i in sample_indices(len(tids), limit)] for name, tids in groups.items()}
    return groups, shown


def grouped_out(text):
    return bool(GROUPED_OUT) and any(n in GROUPED_OUT for n in re.findall(r"\d+", str(text)))


def group_key(text):
    """The name with every grouped thread's TID replaced by '*': "job-worker (660438)" ->
    "job-worker (*)". None if the text names no grouped thread."""
    text = str(text).strip()
    if not GROUP_TIDS or not any(n in GROUP_TIDS for n in re.findall(r"\d+", text)):
        return None
    return re.sub(r"\d+", lambda m: "*" if m.group() in GROUP_TIDS else m.group(), text)


def thread_status_tids(outputs):
    for output in outputs:
        if output.get("descriptor", {}).get("name") == "Thread Status":
            return frozenset(workload_threads(n.get("name", "") for n in output.get("tree", {}).get("nodes", [])))
    return frozenset()


def focus_from_raw(raw):
    """Set the focus for a saved TMLL result: its program, then the program's thread names."""
    set_focus(raw["program"])
    threads = raw.get("workload_threads") or {}
    set_focus(raw["program"], threads.values())


def is_workload(name, tids=frozenset()):
    """Workload entries are named after the threads in the questions, or by their bare TID
    (e.g. futex waiters)."""
    name = str(name).strip()
    return (bool(FOCUS_PATTERN.search(name)) or name in tids) and not grouped_out(name)


def mentions_workload(label, tids=frozenset()):
    """State labels such as Resources Status "worker-2 (159975)"."""
    label = str(label)
    return ((bool(FOCUS_PATTERN.search(label)) or any(n in tids for n in re.findall(r"\d+", label)))
            and not grouped_out(label))


def keep_entity(name, tids=frozenset()):
    # Per-CPU entries are few and say where the workload ran, so they are never sampled out.
    return is_workload(name, tids) or bool(CPU_ENTRY.match(str(name).strip()))


def select_entities(items, limit, label, tids=frozenset()):
    """Prefer workload threads (by name or TID) and CPUs, then sample the remainder."""
    if len(items) <= limit:
        return list(items)
    focused = [i for i, item in enumerate(items) if keep_entity(label(item), tids)]
    focused_set = set(focused)
    other = [i for i in range(len(items)) if i not in focused_set]
    # Keep every named workload entity even if it exceeds the nominal limit.
    remaining = max(0, limit - len(focused))
    indices = sorted(focused + [other[i] for i in sample_indices(len(other), remaining)]) if remaining else focused
    return [items[i] for i in indices]


def duration_stats(durations):
    durations = sorted(durations)
    histogram = {}
    for d in durations:
        upper = next((e for e in HISTOGRAM_EDGES_MS if d < e), None)
        lower = max((e for e in HISTOGRAM_EDGES_MS if e <= d), default=0)
        key = f"{lower}-{upper}" if upper is not None else f">={lower}"
        histogram[key] = histogram.get(key, 0) + 1
    pick = lambda q: durations[min(len(durations) - 1, int(q * len(durations)))]
    return {"count": len(durations), "total_ms": round(sum(durations), 3),
            "mean_ms": round(statistics.fmean(durations), 3), "p50_ms": round(pick(0.5), 3),
            "p90_ms": round(pick(0.9), 3), "min_ms": round(durations[0], 3),
            "max_ms": round(durations[-1], 3), "duration_histogram_ms": histogram}


def state_name(style, value):
    if isinstance(style, dict) and style.get("parentKey"):
        return style["parentKey"]
    return value if value is not None else style


def state_totals(output, tids):
    """Per-state totals for workload entries, computed from every returned state rather than
    the displayed examples. Plain sums of TMLL output; no diagnosis."""
    source = "workload_data" if isinstance(output.get("workload_data"), dict) else "data"
    data = output.get(source)
    if not (isinstance(data, dict) and data.get("kind") == "dataframe" and "entry_id" in data["columns"]):
        return None
    col = {name: i for i, name in enumerate(data["columns"])}
    get = lambda row, name: row[col[name]] if name in col else None
    names = {n["id"]: n.get("name", "") for n in output.get("tree", {}).get("nodes", [])}
    groups, seen = {}, set()
    grouped, grouped_threads = {}, {}
    for row in data["rows"]:
        entry, label = get(row, "entry_id"), get(row, "label")
        name = str(names.get(entry, get(row, "entry_name") or entry)).strip()
        name_key = group_key(name)
        label_key = group_key(label) if label is not None else None
        workload = is_workload(name, tids) or (label is not None and mentions_workload(label, tids))
        if not (workload or name_key or label_key):
            continue
        start, end = get(row, "start_time"), get(row, "end_time")
        if start is None or end is None or (entry, start, end, label) in seen:
            continue  # States spanning two requests are returned twice.
        seen.add((entry, start, end, label))
        state = json.dumps(state_name(get(row, "style"), get(row, "value")))
        if workload:
            groups.setdefault((name, state, label), []).append((end - start) / 1e6)
        if name_key or label_key:
            key = (name_key or name, state, label_key or label)
            grouped.setdefault(key, []).append((end - start) / 1e6)
            found = [n for n in re.findall(r"\d+", f"{name} {label}") if n in GROUP_TIDS]
            grouped_threads.setdefault(key, set()).update(found[:1])
    rows = [{"entry": name, "state": json.loads(state), **({"label": label} if label is not None else {}),
             **duration_stats(durations)} for (name, state, label), durations in groups.items()]
    rows.sort(key=lambda r: (r["entry"], str(r.get("label")), -r["total_ms"]))
    group_rows = [{"entry": name, "state": json.loads(state), **({"label": label} if label is not None else {}),
                   "threads": len(grouped_threads[(name, state, label)]), **duration_stats(durations)}
                  for (name, state, label), durations in grouped.items()
                  if len(grouped_threads[(name, state, label)]) >= 2]  # a one-thread row is no group
    group_rows.sort(key=lambda r: (r["entry"], str(r.get("label")), -r["total_ms"]))
    if not rows and not group_rows:
        return None
    sampling = output.get("workload_sampling") or output.get("collection_sampling") or {}
    return {"computed_from": f"all states returned in '{source}'",
            "resample_freq": sampling.get("resample_freq"),
            "note": "Durations of every returned state per workload entry and state; states "
                    "shorter than the sampling step may be missing.",
            "rows": rows,
            **({"group_rows": group_rows,
                "group_note": "Thread groups (presentation.thread_groups): every state of every thread "
                              "in the group, shown or not, summed; '*' stands for any thread of the "
                              "group, and 'threads' is how many of them had that state."}
               if group_rows else {})}


def arrow_totals(output, tids):
    arrows = output.get("arrows")
    if not isinstance(arrows, list) or not arrows:
        return None
    names = {n["id"]: str(n.get("name", "")).strip() for n in output.get("tree", {}).get("nodes", [])}
    pairs, seen = {}, set()
    for arrow in arrows:
        key = (arrow.get("source_id"), arrow.get("target_id"), arrow.get("start"), arrow.get("end"))
        if key in seen:
            continue  # Arrows spanning two requests are returned twice.
        seen.add(key)
        pair = (names.get(arrow.get("source_id"), arrow.get("source_id")),
                names.get(arrow.get("target_id"), arrow.get("target_id")))
        pairs.setdefault(pair, []).append((arrow.get("end", 0) - arrow.get("start", 0)) / 1e6)
    rows = [{"source": s, "target": t, **duration_stats(d)} for (s, t), d in pairs.items()
            if is_workload(s, tids) or is_workload(t, tids)]
    return sorted(rows, key=lambda r: -r["count"]) or None


TREE_STAT = re.compile(r"\s+([\d.]+) %\s+([\d.]+) (ns|µs|us|ms|s)$")
TO_MS = {"ns": 1e-6, "µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1e3}


def tree_group_totals(output):
    """Per thread group, for trees whose entry names end with "<percent> % <time>" (CPU Usage):
    how many entries, and the sum of those numbers; plain sums of the names TMLL returned."""
    if not GROUPED_OUT:
        return None
    totals = {}
    for node in output.get("tree", {}).get("nodes", []):
        name = str(node.get("name", "")).strip()
        stat = TREE_STAT.search(name)
        key = group_key(name[:stat.start()]) if stat else None
        if key is None:
            continue
        row = totals.setdefault(key, {"entry": key, "entries": 0, "percent_sum": 0, "time_ms_sum": 0})
        row["entries"] += 1
        row["percent_sum"] = round(row["percent_sum"] + float(stat.group(1)), 3)
        row["time_ms_sum"] = round(row["time_ms_sum"] + float(stat.group(2)) * TO_MS[stat.group(3)], 3)
    return sorted((r for r in totals.values() if r["entries"] >= 2), key=lambda r: r["entry"]) or None


def compact_output(output, limit, tids=frozenset()):
    """Bound large inventories while retaining parent nodes and stating omissions.

    This only affects the LLM presentation. The collected raw file stays intact.
    """
    result = dict(output)
    totals = state_totals(output, tids)
    if totals:
        result["workload_state_totals"] = totals
    arrows = arrow_totals(output, tids)
    if arrows:
        result["workload_arrow_totals"] = arrows
    result.pop("workload_data", None)  # Summarised above; too large to display.
    tree_groups = tree_group_totals(output)
    if tree_groups:
        result["group_tree_totals"] = tree_groups
    sampling = result.get("workload_sampling")
    if GROUPED_OUT and isinstance(sampling, dict) and isinstance(sampling.get("workload_entries"), list):
        entries = sampling["workload_entries"]
        kept = [e for e in entries if not grouped_out(e)]
        result["workload_sampling"] = {**sampling, "workload_entries": kept,
                                       "workload_entries_in_thread_groups_not_listed": len(entries) - len(kept)}
    notes = {}
    tree = output.get("tree", {})
    nodes = tree.get("nodes", [])
    retained_ids = None
    if len(nodes) > limit:
        chosen = select_entities(nodes, limit, lambda n: n.get("name", ""), tids)
        by_id = {node["id"]: node for node in nodes}
        retained_ids = {node["id"] for node in chosen}
        for node in chosen:
            parent = node.get("parent_id")
            visited = set()
            while parent in by_id and parent not in visited:
                visited.add(parent)
                retained_ids.add(parent)
                parent = by_id[parent].get("parent_id")
        result["tree"] = {**tree, "nodes": [n for n in nodes if n["id"] in retained_ids]}
        notes["tree_nodes_omitted"] = len(nodes) - len(retained_ids)
    data = output.get("data")
    if isinstance(data, dict) and data.get("kind") == "dataframe" and retained_ids is not None:
        columns = data["columns"]
        if "entry_id" in columns:
            column = columns.index("entry_id")
            indices = [i for i, row in enumerate(data["rows"]) if row[column] in retained_ids]
            result["data"] = {**data, "rows": [data["rows"][i] for i in indices],
                              "index": [data["index"][i] for i in indices]}
            notes["states_from_omitted_entries"] = len(data["rows"]) - len(indices)
    elif isinstance(data, dict) and "entries" in data:
        entries = data["entries"]
        # Reuse retained tree IDs so statistic rows retain their hierarchy.
        if retained_ids is not None:
            entries = [entry for entry in entries if entry.get("id") in retained_ids]
        result["data"] = {**data, "entries": entries}
        notes["statistics_entries_omitted"] = len(data["entries"]) - len(entries)
    elif isinstance(data, dict) and data and all(
            isinstance(v, dict) and v.get("kind") == "dataframe" for v in data.values()):
        names = select_entities(list(data), limit, str, tids)
        result["data"] = {name: data[name] for name in names}
        notes["xy_series_omitted"] = len(data) - len(names)
    if any(notes.values()):
        result["inventory_sampling"] = {
            **notes, "policy": f"Retain workload threads ({PROGRAM}, its threads and child processes, by name "
            "or TID) and CPUs, then evenly sample other entities; retain ancestors of selected "
            "tree nodes. Omitted entities remain in tmll_raw.json.gz and are not evidence of absence."}
    return result


def workload_entry_ids(output, tids):
    """Entries with workload rows: workload threads, and e.g. CPUs whose states name them."""
    ids = {n["id"] for n in output.get("tree", {}).get("nodes", []) if is_workload(n.get("name", ""), tids)}
    data = output.get("data")
    if isinstance(data, dict) and data.get("kind") == "dataframe" and {"entry_id", "label"} <= set(data["columns"]):
        entry, label = data["columns"].index("entry_id"), data["columns"].index("label")
        ids |= {row[entry] for row in data["rows"]
                if row[label] is not None and mentions_workload(row[label], tids)}
    return ids


def summarize(value, row_limit, other_limit=None, focus_ids=None, tids=frozenset()):
    """Deterministic presentation of native results; never manufacture a diagnosis.

    Workload entries/series get row_limit example rows, all others other_limit."""
    other_limit = row_limit if other_limit is None else min(other_limit, row_limit)
    if isinstance(value, dict) and value.get("kind") == "dataframe":
        columns, rows = value["columns"], value["rows"]
        # Preserve examples for every time-graph entry instead of allowing a busy
        # system thread to crowd all workload threads out of the prompt.
        groups = {}
        entry_col = columns.index("entry_id") if "entry_id" in columns else None
        for i, row in enumerate(rows):
            groups.setdefault(row[entry_col] if entry_col is not None else "all", []).append(i)
        limit = lambda key: row_limit if focus_ids is None or key == "all" or key in focus_ids else other_limit
        selected = sorted(i for key, indices in groups.items()
                          for i in (indices[n] for n in sample_indices(len(indices), limit(key))))
        result = {**value, "rows": [rows[i] for i in selected],
                  "index": [value["index"][i] for i in selected],
                  "total_rows": len(rows), "shown_rows": len(selected),
                  "omitted_rows": len(rows) - len(selected),
                  "sampling": "Evenly spaced rows per entry_id, or per series if no entry_id; "
                              "fewer rows for non-workload entries."}
        if "y" in columns:
            col = columns.index("y")
            numbers = [r[col] for r in rows if isinstance(r[col], (int, float))]
            if numbers:
                result["all_returned_samples_y_statistics"] = {
                    "count": len(numbers), "min": min(numbers), "max": max(numbers),
                    "mean": statistics.fmean(numbers), "median": statistics.median(numbers)}
        anomaly_cols = [i for i, name in enumerate(columns) if name.endswith("_is_anomaly")]
        if anomaly_cols:
            anomalies = [i for i, r in enumerate(rows) if any(r[c] is True for c in anomaly_cols)]
            shown = [anomalies[n] for n in sample_indices(len(anomalies), row_limit)]
            result["anomaly_rows_total"] = len(anomalies)
            result["anomaly_examples"] = [{"index": value["index"][i], "row": rows[i]} for i in shown]
        return result
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "arrows" and isinstance(item, list) and len(item) > row_limit:
                result[key] = {"total_arrows": len(item), "omitted_arrows": len(item) - row_limit,
                               "sampling": "Evenly spaced arrows in returned order.",
                               "samples": [item[i] for i in sample_indices(len(item), row_limit)]}
            elif (isinstance(item, dict) and item.get("kind") == "dataframe" and key != "data"
                  and "entry_id" not in item["columns"]):
                # A named XY series: full examples only for workload series.
                limit = row_limit if is_workload(key, tids) else other_limit
                result[key] = summarize(item, limit)
            else:
                result[key] = summarize(item, row_limit, other_limit, focus_ids, tids)
        return result
    if isinstance(value, list):
        return [summarize(item, row_limit, other_limit, focus_ids, tids) for item in value]
    return value


def build_evidence(raw, encoding, budget, rows, other_rows=None, entities=24):
    global GROUP_TIDS, GROUPED_OUT
    focus_from_raw(raw)
    groups, shown = thread_groups(raw.get("workload_threads") or {}, entities)
    GROUP_TIDS = {tid: name for name, tids in groups.items() for tid in tids}
    GROUPED_OUT = frozenset(GROUP_TIDS) - {tid for tids in shown.values() for tid in tids}
    try:
        return _build_evidence(raw, encoding, budget, rows, other_rows, entities, groups, shown)
    finally:
        GROUP_TIDS, GROUPED_OUT = {}, frozenset()


def _build_evidence(raw, encoding, budget, rows, other_rows, entities, groups, shown):
    tids = thread_status_tids(raw.get("outputs", [])) - GROUPED_OUT
    while True:
        outputs = [compact_output(o, entities, tids) for o in raw.get("outputs", [])]
        presented = {key: summarize(item, rows, other_rows, None, tids)
                     for key, item in raw.items() if key != "outputs"}
        if GROUPED_OUT and isinstance(presented.get("workload_threads"), dict):
            threads = presented["workload_threads"]
            presented["workload_threads"] = {tid: name for tid, name in threads.items() if tid not in GROUPED_OUT}
            presented["workload_threads_in_thread_groups_not_listed"] = len(threads) - len(presented["workload_threads"])
        presented["outputs"] = [summarize(o, rows, other_rows, workload_entry_ids(o, tids), tids)
                                for o in outputs]
        evidence = presented
        evidence["presentation"] = {"max_rows_per_series_or_entry": rows,
                                    "max_rows_per_other_series_or_entry": min(other_rows or rows, rows),
                                    "entity_limit_per_output": entities,
                                    "workload_tids": sorted(tids),
                                    **({"thread_groups": {
                                        name: {"threads": len(groups[name]), "shown_one_by_one": len(shown[name]),
                                               "shown_tids": shown[name],
                                               "rule": f"more than {entities} threads named '{name}': "
                                                       f"{entities} of them, evenly spread by TID, are shown "
                                                       "like the other workload threads; the rest are left "
                                                       "out one by one and counted in the group_rows of "
                                                       "workload_state_totals and in group_tree_totals"}
                                        for name in groups}} if groups else {}),
                                    "note": "Example rows are evenly sampled; statistics and "
                                            "workload_state_totals use all returned samples/states."}
        text = "TMLL ANALYSIS RESULTS\n" + json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))
        tokens = len(encoding.encode_ordinary(text))
        if tokens <= budget:
            return text, tokens, rows
        if rows == 1:
            raise ValueError(f"TMLL metadata alone exceeds the {budget}-token budget even after inventory sampling. "
                             "Narrow --keywords/--analyses or increase --budget; no evidence was silently dropped.")
        rows = max(1, rows // 2)


def cmd_prepare(args):
    import tiktoken

    enc = tiktoken.get_encoding(args.encoding)
    runs = sorted({j["run_id"] for j in common.load_jobs(trace=args.trace)})
    failed = []
    for n, run_id in enumerate(runs, 1):
        directory = EVIDENCE_DIR / run_id
        directory.mkdir(parents=True, exist_ok=True)
        raw_path = directory / "tmll_raw.json.gz"
        if (directory / "tmll.txt").exists() and not args.force and not args.reuse_raw:
            continue
        print(f"[{n}/{len(runs)}] {run_id}", flush=True)
        t0 = time.time()
        if not args.reuse_raw:
            command = [args.tmll_python, str(HERE / "collect_tmll.py"),
                       "--tmll-source", str(args.tmll_source), "--kernel", str(common.kernel_dir(run_id)),
                       "--label", run_id, "--run", run_id, "--program", common.program_of(run_id),
                       "--output", str(raw_path), "--host", args.host, "--port", str(args.port),
                       "--resample-freq", args.resample_freq, "--max-samples", str(args.max_samples),
                       "--max-entities", str(args.max_entities),
                       "--workload-resample-freq", args.workload_resample_freq,
                       "--analyses", *args.analyses]
            if args.keywords:
                command += ["--keywords", *args.keywords]
            try:
                subprocess.run(command, check=True, timeout=args.tmll_timeout)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                print(f"  failed: {exc}", flush=True)
                failed.append(run_id)
                continue
        if not raw_path.exists():
            print(f"  no saved TMLL results at {raw_path}", flush=True)
            failed.append(run_id)
            continue
        with gzip.open(raw_path, "rt", encoding="utf-8") as handle:
            raw = json.load(handle)
        try:
            text, tokens, rows = build_evidence(raw, enc, args.budget, args.rows, args.other_rows, args.entities)
        except ValueError as exc:
            print(f"  {exc}", flush=True)
            failed.append(run_id)
            continue
        meta = {"run_id": run_id, "program": raw["program"], "tokens": tokens,
                "evidence_sha256": digest(text), "encoding": enc.name,
                "budget_tokens": args.budget, "rows_per_series_or_entry": rows,
                "rows_per_other_series_or_entry": min(args.other_rows, rows),
                "entity_limit_per_output": args.entities,
                "workload_threads": raw.get("workload_threads"),
                "experiment_id": raw["experiment_id"], "tmll_revision": raw["tmll_revision"],
                "trace_begin_ns": raw["trace_begin_ns"], "trace_end_ns": raw["trace_end_ns"],
                "trace_events": raw["trace_events"], "resample_freq": raw["resample_freq"],
                "workload_resample_freq": raw.get("workload_resample_freq"),
                "collect_s": round(time.time() - t0, 1)}
        (directory / "tmll.txt").write_text(text, encoding="utf-8")
        (directory / "tmll.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        print(f"  {tokens:,} evidence tokens, {rows} rows per series/entry, "
              f"{len(raw.get('workload_threads') or {})} workload threads ({time.time() - t0:.0f} s)", flush=True)
    print(f"evidence for {len(runs) - len(failed)} of {len(runs)} traces in {EVIDENCE_DIR}"
          + (f"; failed: {' '.join(failed)}" if failed else ""))
    return 1 if failed else 0


def load_evidence(run_id):
    path = EVIDENCE_DIR / run_id / "tmll.txt"
    text = path.read_text(encoding="utf-8")
    meta = json.loads(path.with_suffix(".json").read_text())
    if digest(text) != meta["evidence_sha256"]:
        raise ValueError(f"Evidence hash mismatch: {path}; rerun prepare")
    return text, meta


def ask(client, args, text, meta, prompt):
    params = {
        "model": args.model, "instructions": SYSTEM_PROMPT,
        "input": [{"role": "user", "content": [
            # The evidence ends in an explicit cache breakpoint, as in slice_baselines.py: without
            # it gpt-6-luna cached nothing (run 1, 2026-11-23: 0 of 83M input tokens cached).
            {"type": "input_text", "text": text, "prompt_cache_breakpoint": {"mode": "explicit"}},
            {"type": "input_text", "text": f"\n\n---\nQuestion: {prompt}"}]}],
        "prompt_cache_key": f"bench-tmll-{meta['evidence_sha256'][:32]}",
        "max_output_tokens": args.max_output_tokens, "store": False,
    }
    if args.reasoning_effort:
        params["reasoning"] = {"effort": args.reasoning_effort}
    return client.responses.create(**params)


def cmd_run(args):
    jobs = common.load_jobs(question=args.question, trace=args.trace, wording=args.wording)
    missing = sorted({j["run_id"] for j in jobs if not (EVIDENCE_DIR / j["run_id"] / "tmll.txt").exists()})
    if missing:
        raise ValueError(f"no TMLL evidence for {len(missing)} traces ({' '.join(missing[:4])}...); "
                         "run `prepare` and check that it succeeds first")
    folder = common.out_dir(SYSTEM, args.run, args.out)
    todo = common.pending(jobs, folder, args.retry_errors)
    saved = len(jobs) - len(todo)
    if args.limit is not None:
        todo = todo[:args.limit]
    by_trace = {}
    for j in todo:
        by_trace.setdefault(j["run_id"], []).append(j)
    tokens = sum(load_evidence(r)[1]["tokens"] * len(js) for r, js in by_trace.items())
    print(f"{SYSTEM} run {args.run}: {len(jobs)} answers in this selection, {saved} already saved; "
          f"asking {len(todo)} on {len(by_trace)} traces, ~{tokens / 1e6:.1f}M evidence input tokens")
    if args.dry_run:
        for j in todo[:10]:
            print(f"  {j['id']:<26} {j['text'][:90]}")
        return 0
    common.require_key()
    from openai import OpenAI

    client = OpenAI(max_retries=args.max_retries, timeout=args.timeout)
    lock, stop = threading.Lock(), threading.Event()
    done = [0]
    started_all = time.time()

    def one(text, meta, build, j):
        if stop.is_set():
            return
        record = common.new_record(SYSTEM, build, args.run, j)
        record.update(evidence_tokens=meta["tokens"], evidence_sha256=meta["evidence_sha256"],
                      tmll_revision=meta["tmll_revision"], reasoning_effort=args.reasoning_effort)
        t0 = time.monotonic()
        answer, error = None, None
        try:
            response = ask(client, args, text, meta, j["prompt"])
            usage = response.usage
            answer = response.output_text
            record.update(model=response.model, response_status=response.status,
                          incomplete_reason=getattr(response.incomplete_details, "reason", None),
                          usage={"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
                                 "cached_tokens": getattr(usage.input_tokens_details, "cached_tokens", None),
                                 "reasoning_tokens": getattr(usage.output_tokens_details, "reasoning_tokens", None)})
            if response.status != "completed":
                error = f"response {response.status}: {record['incomplete_reason']}"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            if "insufficient_quota" in str(exc) or "context_length" in str(exc):
                stop.set()
        record["elapsed_s"] = round(time.monotonic() - t0, 2)
        common.finish(record, answer, error)
        with lock:
            common.save(folder, record)
            done[0] += 1
            print(common.progress(done[0], len(todo), record), flush=True)

    for run_id, js in by_trace.items():
        text, meta = load_evidence(run_id)
        build = common.fingerprint(Path(__file__), HERE / "collect_tmll.py", SYSTEM_PROMPT, args.model,
                                   args.reasoning_effort, args.max_output_tokens, meta["evidence_sha256"])
        one(text, meta, build, js[0])  # Warm the evidence prompt cache.
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for future in [pool.submit(one, text, meta, build, j) for j in js[1:]]:
                future.result()
        if stop.is_set():
            raise ValueError("Stopped: out of API credit, or the evidence does not fit the model's "
                             "context window (see the last error). Fix it and rerun to resume.")
    print(f"done: {done[0]} answers in {(time.time() - started_all) / 60:.1f} min")
    return 0


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("prepare", help="collect TMLL analyses and freeze token-budgeted evidence")
    p.add_argument("--trace", nargs="*", help="only these runs (default: every run in pairs.json)")
    p.add_argument("--tmll-source", type=Path, default=TMLL_UPSTREAM)
    p.add_argument("--tmll-python", default=str(TMLL_UPSTREAM / ".venv" / "bin" / "python"))
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=positive, default=8080)
    p.add_argument("--tmll-timeout", type=positive, default=3600, help="seconds per trace")
    p.add_argument("--keywords", nargs="+", help="OR filter on TMLL output name, ID, description")
    p.add_argument("--analyses", nargs="*", choices=["anomaly", "correlation"],
                   default=["anomaly", "correlation"], help="pass with no values to skip ML analyses")
    p.add_argument("--resample-freq", default="10ms")
    p.add_argument("--max-samples", type=positive, default=12000,
                   help="coarsen sampling on longer traces to cap points per series (default 12000)")
    p.add_argument("--max-entities", type=positive, default=200,
                   help="limit fetched entries per output, retaining workload names and ancestors")
    p.add_argument("--workload-resample-freq", default="100us",
                   help="time-graph resolution for workload thread entries only (no sample cap)")
    p.add_argument("--rows", type=positive, default=100, help="max displayed rows per workload series/entry")
    p.add_argument("--other-rows", type=positive, default=3, help="max displayed rows per other series/entry")
    p.add_argument("--entities", type=positive, default=24,
                   help="displayed entities per output, plus every workload thread and CPU")
    p.add_argument("--budget", type=positive, default=200_000)
    p.add_argument("--encoding", default="o200k_base")
    p.add_argument("--reuse-raw", action="store_true", help="reformat saved results without contacting TMLL")
    p.add_argument("--force", action="store_true", help="collect again where evidence exists")
    p.set_defaults(func=cmd_prepare)
    p = sub.add_parser("run", help="answer every bench question from its trace's TMLL evidence")
    p.add_argument("--run", type=int, default=1)
    p.add_argument("--out", help="save under results/tmll/<out> instead of run<N>")
    p.add_argument("--question", nargs="*")
    p.add_argument("--trace", nargs="*")
    p.add_argument("--wording", choices=("a", "b"))
    p.add_argument("--limit", type=int)
    p.add_argument("--model", default=common.MODEL)
    p.add_argument("--reasoning-effort", choices=["none", "minimal", "low", "medium", "high", "xhigh", "max"])
    p.add_argument("--max-output-tokens", type=positive, default=32_000)
    p.add_argument("--workers", type=positive, default=2)
    p.add_argument("--timeout", type=positive, default=900)
    p.add_argument("--max-retries", type=int, default=5)
    p.add_argument("--retry-errors", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_run)
    args = parser.parse_args()
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    sys.exit(main())
