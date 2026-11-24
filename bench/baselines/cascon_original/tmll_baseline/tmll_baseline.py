#!/usr/bin/env python3
"""TMLL + LLM baseline: prepare structured trace evidence, run the same 13
questions as llm_baseline/RAG_baseline, and export natural-language answers.

  python tmll_baseline.py prepare
  python tmll_baseline.py run --dry-run
  python tmll_baseline.py run --repeats 1
  python tmll_baseline.py export --repeat 1

Only trace/kernel is imported. No ground truth, program logs, workload source,
RAG documents, or other baselines' answers are read.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
RUNS_DIR = HERE.parent / "runs/runs_to_use"
EVIDENCE_DIR = HERE / "evidence"
RESULTS_DIR = HERE / "results"
ANSWERS_JSONL = RESULTS_DIR / "answers.jsonl"
QUESTIONS_FILE = HERE / "questions.json"
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


def find_traces(labels=None):
    traces = []
    for run in RUNS_DIR.iterdir() if RUNS_DIR.is_dir() else []:
        match = re.search(r"-(\d+)m-", run.name)
        kernel = run / "trace/kernel"
        if match and kernel.is_dir():
            traces.append((f"{match[1]}m", run, kernel))
    known = [t[0] for t in traces]
    if len(set(known)) != len(known):
        raise ValueError("Duplicate trace-duration labels in runs_to_use")
    if labels and set(labels) - set(known):
        raise ValueError(f"Unknown traces: {sorted(set(labels) - set(known))}")
    return sorted((t for t in traces if not labels or t[0] in labels),
                  key=lambda t: int(t[0][:-1]))


def sample_indices(length, limit):
    if length <= limit:
        return list(range(length))
    if limit == 1:
        return [length // 2]
    return [i * (length - 1) // (limit - 1) for i in range(limit)]


FOCUS_PATTERN = re.compile(r"batch_server|worker-\d+|flusher", re.IGNORECASE)
CPU_ENTRY = re.compile(r"^CPU \d+( Threads| States)?$")
HISTOGRAM_EDGES_MS = (0, 1, 2, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 80, 100, 200, 500, 1000)


def workload_threads(names):
    """{tid: name} for workload threads in Thread Status entry names ("<name> <tid> <pid> <ppid>")."""
    threads = {}
    for name in names:
        parts = str(name).split()
        if len(parts) >= 4 and all(p.isdigit() for p in parts[-3:]):
            thread = " ".join(parts[:-3])
            if FOCUS_PATTERN.search(thread):
                threads[parts[-3]] = thread
    return threads


def thread_status_tids(outputs):
    for output in outputs:
        if output.get("descriptor", {}).get("name") == "Thread Status":
            return frozenset(workload_threads(n.get("name", "") for n in output.get("tree", {}).get("nodes", [])))
    return frozenset()


def is_workload(name, tids=frozenset()):
    """Workload entries are named after the threads in the questions, or by their bare TID
    (e.g. futex waiters)."""
    name = str(name).strip()
    return bool(FOCUS_PATTERN.search(name)) or name in tids


def mentions_workload(label, tids=frozenset()):
    """State labels such as Resources Status "worker-2 (159975)"."""
    label = str(label)
    return bool(FOCUS_PATTERN.search(label)) or any(n in tids for n in re.findall(r"\d+", label))


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
    for row in data["rows"]:
        entry, label = get(row, "entry_id"), get(row, "label")
        name = str(names.get(entry, get(row, "entry_name") or entry)).strip()
        if not (is_workload(name, tids) or (label is not None and mentions_workload(label, tids))):
            continue
        start, end = get(row, "start_time"), get(row, "end_time")
        if start is None or end is None or (entry, start, end, label) in seen:
            continue  # States spanning two requests are returned twice.
        seen.add((entry, start, end, label))
        key = (name, json.dumps(state_name(get(row, "style"), get(row, "value"))), label)
        groups.setdefault(key, []).append((end - start) / 1e6)
    if not groups:
        return None
    rows = [{"entry": name, "state": json.loads(state), **({"label": label} if label is not None else {}),
             **duration_stats(durations)} for (name, state, label), durations in groups.items()]
    rows.sort(key=lambda r: (r["entry"], str(r.get("label")), -r["total_ms"]))
    sampling = output.get("workload_sampling") or output.get("collection_sampling") or {}
    return {"computed_from": f"all states returned in '{source}'",
            "resample_freq": sampling.get("resample_freq"),
            "note": "Durations of every returned state per workload entry and state; states "
                    "shorter than the sampling step may be missing.",
            "rows": rows}


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
            **notes, "policy": "Retain workload threads (batch_server, worker-N, flusher, by name "
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
    tids = thread_status_tids(raw.get("outputs", []))
    while True:
        outputs = [compact_output(o, entities, tids) for o in raw.get("outputs", [])]
        presented = {key: summarize(item, rows, other_rows, None, tids)
                     for key, item in raw.items() if key != "outputs"}
        presented["outputs"] = [summarize(o, rows, other_rows, workload_entry_ids(o, tids), tids)
                                for o in outputs]
        evidence = presented
        evidence["presentation"] = {"max_rows_per_series_or_entry": rows,
                                    "max_rows_per_other_series_or_entry": min(other_rows or rows, rows),
                                    "entity_limit_per_output": entities,
                                    "workload_tids": sorted(tids),
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

    traces = find_traces(args.traces)
    if not traces:
        raise ValueError(f"No kernel traces under {RUNS_DIR}")
    enc = tiktoken.get_encoding(args.encoding)
    for label, run, kernel in traces:
        directory = EVIDENCE_DIR / label
        directory.mkdir(parents=True, exist_ok=True)
        raw_path = directory / "tmll_raw.json.gz"
        if not args.reuse_raw:
            command = [args.tmll_python, str(HERE / "collect_tmll.py"),
                       "--tmll-source", str(args.tmll_source), "--kernel", str(kernel),
                       "--label", label, "--run", run.name, "--output", str(raw_path),
                       "--host", args.host, "--port", str(args.port),
                       "--resample-freq", args.resample_freq, "--max-samples", str(args.max_samples),
                       "--max-entities", str(args.max_entities),
                       "--workload-resample-freq", args.workload_resample_freq,
                       "--analyses", *args.analyses]
            if args.keywords:
                command += ["--keywords", *args.keywords]
            subprocess.run(command, check=True, timeout=args.tmll_timeout)
        if not raw_path.exists():
            raise ValueError(f"No saved TMLL results at {raw_path}; prepare without --reuse-raw")
        with gzip.open(raw_path, "rt", encoding="utf-8") as handle:
            raw = json.load(handle)
        text, tokens, rows = build_evidence(raw, enc, args.budget, args.rows, args.other_rows, args.entities)
        meta = {"trace": label, "run": run.name, "tokens": tokens,
                "evidence_sha256": digest(text), "encoding": enc.name,
                "budget_tokens": args.budget, "rows_per_series_or_entry": rows,
                "rows_per_other_series_or_entry": min(args.other_rows, rows),
                "entity_limit_per_output": args.entities,
                "experiment_id": raw["experiment_id"], "tmll_revision": raw["tmll_revision"],
                "trace_begin_ns": raw["trace_begin_ns"], "trace_end_ns": raw["trace_end_ns"],
                "trace_events": raw["trace_events"], "resample_freq": raw["resample_freq"],
                "workload_resample_freq": raw.get("workload_resample_freq")}
        (directory / "tmll.txt").write_text(text, encoding="utf-8")
        (directory / "tmll.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        print(f"{label}: {tokens:,} evidence tokens, {rows} rows per series/entry", flush=True)


def load_questions(ids=None):
    questions = json.loads(QUESTIONS_FILE.read_text())
    if ids and set(ids) - {q["id"] for q in questions}:
        raise ValueError("Unknown question ID; expected Q1 through Q13")
    return [q for q in questions if not ids or q["id"] in ids]


def load_evidence(labels=None):
    evidence = []
    for path in sorted(EVIDENCE_DIR.glob("*/tmll.txt")):
        if labels and path.parent.name not in labels:
            continue
        text = path.read_text(encoding="utf-8")
        meta = json.loads(path.with_suffix(".json").read_text())
        if digest(text) != meta["evidence_sha256"]:
            raise ValueError(f"Evidence hash mismatch: {path}; rerun prepare")
        evidence.append((text, meta))
    if labels and set(labels) - {m["trace"] for _, m in evidence}:
        missing = sorted(set(labels) - {m["trace"] for _, m in evidence})
        raise ValueError(f"Missing prepared traces: {', '.join(missing)}. "
                         f"Run `prepare --traces {' '.join(missing)}` and check that it succeeds "
                         "before running the LLM step. Raw .json.gz files alone are not prepared prompts.")
    if not evidence:
        raise ValueError("No TMLL evidence found; run `prepare` first")
    return sorted(evidence, key=lambda pair: int(pair[1]["trace"][:-1]))


def record_key(record):
    return (record["model"], record["trace"], record["question_id"], record["repeat"],
            record["evidence_sha256"], record["config_sha256"])


def completed(record):
    return "error" not in record and record.get("status") == "completed" and bool(record.get("answer", "").strip())


def records():
    if ANSWERS_JSONL.exists():
        for line in ANSWERS_JSONL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                yield json.loads(line)


def ask(client, args, text, meta, question):
    params = {
        "model": args.model, "instructions": SYSTEM_PROMPT,
        "input": [{"role": "user", "content": [
            {"type": "input_text", "text": text},
            {"type": "input_text", "text": f"\n\n---\nQuestion: {question}"}]}],
        "prompt_cache_key": f"cascon-tmll-{meta['evidence_sha256'][:32]}",
        "max_output_tokens": args.max_output_tokens, "store": False,
    }
    if args.reasoning_effort:
        params["reasoning"] = {"effort": args.reasoning_effort}
    return client.responses.create(**params)


def cmd_run(args):
    evidence, questions = load_evidence(args.traces), load_questions(args.questions)
    config_hash = digest(json.dumps({"prompt": SYSTEM_PROMPT, "questions": load_questions(),
                                    "reasoning_effort": args.reasoning_effort,
                                    "max_output_tokens": args.max_output_tokens}, sort_keys=True))
    done = {record_key(r) for r in records() if completed(r)}
    plan = []
    for text, meta in evidence:
        jobs = []
        for q in questions:
            for rep in range(1, args.repeats + 1):
                rec = {"model": args.model, "trace": meta["trace"], "slice": "TMLL_full",
                       "run": meta["run"], "question_id": q["id"], "question_type": q["type"],
                       "question": q["question"], "repeat": rep, "evidence_tokens": meta["tokens"],
                       "evidence_sha256": meta["evidence_sha256"], "config_sha256": config_hash,
                       "reasoning_effort": args.reasoning_effort, "tmll_revision": meta["tmll_revision"]}
                if record_key(rec) not in done:
                    jobs.append(rec)
        if jobs:
            plan.append((text, meta, jobs))
    calls = sum(len(jobs) for _, _, jobs in plan)
    tokens = sum(meta["tokens"] * len(jobs) for _, meta, jobs in plan)
    print(f"{calls} calls to {args.model}, ~{tokens / 1e6:.2f}M evidence input tokens")
    for _, meta, jobs in plan:
        print(f"  {meta['trace']:>4} TMLL_full {meta['tokens']:>8} tokens x {len(jobs)} calls")
    if args.dry_run or not plan:
        return
    from openai import OpenAI

    client = OpenAI(max_retries=args.max_retries, timeout=args.timeout)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    lock, stop = threading.Lock(), threading.Event()

    def one(text, meta, rec):
        if stop.is_set():
            return
        rec["time"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        start = time.monotonic()
        try:
            response = ask(client, args, text, meta, rec["question"])
            usage = response.usage
            rec.update(answer=response.output_text, status=response.status, response_model=response.model,
                       incomplete_reason=getattr(response.incomplete_details, "reason", None),
                       input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
                       cached_tokens=getattr(usage.input_tokens_details, "cached_tokens", None),
                       reasoning_tokens=getattr(usage.output_tokens_details, "reasoning_tokens", None))
        except Exception as exc:
            rec["error"] = f"{type(exc).__name__}: {exc}"
            if "insufficient_quota" in str(exc):
                stop.set()
        rec["latency_s"] = round(time.monotonic() - start, 1)
        with lock:
            with ANSWERS_JSONL.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(rec) + "\n")
            print(f"  {rec['trace']} {rec['question_id']} rep {rec['repeat']}: "
                  f"{rec.get('error', rec.get('status'))} ({rec['latency_s']}s)", flush=True)

    for text, meta, jobs in plan:
        one(text, meta, jobs[0])  # Warm the common evidence prompt cache.
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(one, text, meta, rec) for rec in jobs[1:]]
            for future in futures:
                future.result()
        if stop.is_set():
            raise ValueError("Stopped: API account out of credit. Rerun after adding credit to resume.")


def cmd_export(args):
    latest = {}
    for rec in records():
        if completed(rec) and (args.repeat is None or rec["repeat"] == args.repeat):
            latest[record_key(rec)] = rec
    if not latest:
        raise ValueError("No completed answers recorded for this selection")
    rows = sorted(latest.values(), key=lambda r: (r["model"], int(r["question_id"][1:]),
                                                 int(r["trace"][:-1]), r["repeat"]))
    columns = ["model", "response_model", "trace", "slice", "question_id", "question_type",
               "question", "repeat", "answer", "status", "evidence_tokens", "input_tokens",
               "cached_tokens", "output_tokens", "reasoning_tokens", "latency_s",
               "evidence_sha256", "config_sha256", "tmll_revision"]
    output = RESULTS_DIR / ("answers.csv" if args.repeat is None else f"answers_repeat{args.repeat}.csv")
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    lines = ["# TMLL + LLM baseline answers", ""]
    for q in load_questions():
        selected = [r for r in rows if r["question_id"] == q["id"]]
        if not selected:
            continue
        lines += [f"## {q['id']} ({q['type']}): {q['question']}", ""]
        for r in selected:
            lines += [f"### {r['trace']} trace · TMLL full trace · {r['model']} · repeat {r['repeat']}", "",
                      f"*{r['input_tokens']:,} input tokens ({r['cached_tokens'] or 0:,} cached), "
                      f"{r['output_tokens']:,} output tokens, {r['latency_s']} s; "
                      f"evidence {r['evidence_sha256'][:12]}, config {r['config_sha256'][:12]}*", ""]
            lines += [f"> {line}" if line.strip() else ">" for line in r["answer"].splitlines()]
            lines.append("")
    output.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(rows)} answers -> {output} and {output.with_suffix('.md')}")


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("prepare", help="collect TMLL analyses and freeze token-budgeted evidence")
    p.add_argument("--traces", nargs="+")
    p.add_argument("--tmll-source", type=Path, default=HERE.parent / "tmll")
    p.add_argument("--tmll-python", default=sys.executable)
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
    p.set_defaults(func=cmd_prepare)
    p = sub.add_parser("run", help="translate TMLL evidence into answers")
    p.add_argument("--traces", nargs="+")
    p.add_argument("--questions", nargs="+")
    p.add_argument("--model", default="gpt-5.6")
    p.add_argument("--repeats", type=positive, default=1)
    p.add_argument("--reasoning-effort", choices=["none", "minimal", "low", "medium", "high", "xhigh", "max"])
    p.add_argument("--max-output-tokens", type=positive, default=32_000)
    p.add_argument("--workers", type=positive, default=2)
    p.add_argument("--timeout", type=positive, default=900)
    p.add_argument("--max-retries", type=int, default=5)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("export", help="write completed answers as CSV and Markdown")
    p.add_argument("--repeat", type=positive)
    p.set_defaults(func=cmd_export)
    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
