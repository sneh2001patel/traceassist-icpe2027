#!/usr/bin/env python3
"""The LLM-only and LLM + RAG baselines on the symptom bench, adapted from the CASCON
experiment (../cascon_original/llm_baseline, ../cascon_original/RAG_baseline).

Both give the model raw LTTng trace text and no tools. A bench trace is ~30 s of a whole
machine, far more text than fits in a prompt, so each trace is cut into one slice of at most
--budget tokens (default 200,000): 20 short windows of consecutive events, spaced evenly over the
whole trace (CASCON's "C_sampled"). The user chose this slice only, so each baseline gives one
answer per pair, 516 in all, like TraceAssist's run 1.

  llm_only  system prompt, slice, the question with the verdict line
  rag       the same, plus the RETRIEVED KNOWLEDGE for the question (retrieve_docs.py: the 6
            nearest documents in TMLL's knowledge base, tmll/rag/knowledge, the same documents
            TraceAssist's RAG step draws on; no program descriptions)

Each question is its own API call: no answer sees another. The slice comes first so OpenAI's
prompt cache reuses it for every question on the same trace.

Only runs/<id>/trace/kernel is read (babeltrace2). The model is gpt-6-luna, as for TraceAssist.

Setup:   python3 -m venv .venv && .venv/bin/pip install openai tiktoken
         export OPENAI_API_KEY=...
Usage:   .venv/bin/python slice_baselines.py prepare                 # slices (babeltrace2, no API)
         .venv/bin/python slice_baselines.py run --system llm_only --dry-run
         .venv/bin/python slice_baselines.py run --system llm_only   # results/llm_only/run1/
         .venv/bin/python slice_baselines.py run --system rag        # results/rag/run1/
         python3 ../score.py --system llm_only
A stopped run continues where it left off: rerun the same command.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import common

SLICES = common.HERE / "slices"
DOCS_FILE = common.HERE / "retrieved_docs.json"

SYSTEM_PROMPTS = {
    # The CASCON LLM-only system prompt, unchanged.
    "llm_only": (
        "You are an expert in Linux kernel tracing and performance analysis. The user message "
        "contains text from an LTTng kernel trace, printed by babeltrace2, followed by one question "
        "about it. Answer the question using only the trace text provided. Be specific: name "
        "processes and threads (with their TIDs), CPUs, system calls and durations where relevant. "
        "If the trace text is not enough to answer with confidence, say so and explain what is "
        "missing, then give your best answer."),
    # The CASCON RAG system prompt, unchanged: the LLM-only one plus the knowledge section.
    "rag": (
        "You are an expert in Linux kernel tracing and performance analysis. The user message "
        "contains text from an LTTng kernel trace, printed by babeltrace2, then background "
        "documentation retrieved for the question (RETRIEVED KNOWLEDGE), then one question about the "
        "trace. Answer the question using only the trace text as the source of facts about this "
        "system; use the retrieved documentation only to interpret the trace. Be specific: name "
        "processes and threads (with their TIDs), CPUs, system calls and durations where relevant. "
        "If the trace text is not enough to answer with confidence, say so and explain what is "
        "missing, then give your best answer."),
}


# --------------------------------------------------------------------------- slices

def trace_range_ns(kernel: Path) -> tuple[int, int]:
    """(begin, end) of the trace in ns since the epoch, from babeltrace2's packet index."""
    out = subprocess.run(
        ["babeltrace2", "query", "src.ctf.fs", "babeltrace.trace-infos",
         "--params", f"inputs=[{json.dumps(str(kernel))}]"],
        capture_output=True, text=True, check=True).stdout
    pairs = re.findall(r"range-ns:\s*\n\s*begin:\s*(\d+)\s*\n\s*end:\s*(\d+)", out)
    if not pairs:
        raise RuntimeError(f"could not read the time range of {kernel}")
    return min(int(b) for b, _ in pairs), max(int(e) for _, e in pairs)


def read_events(kernel: Path, enc, max_tokens: int, start_ns: int) -> tuple[list[str], int]:
    """Consecutive babeltrace2 text lines from start_ns, up to max_tokens."""
    cmd = ["babeltrace2", f"--begin={start_ns // 10**9}.{start_ns % 10**9:09d}", str(kernel)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, errors="replace")
    lines, tokens = [], 0
    try:
        for line in proc.stdout:
            n = len(enc.encode_ordinary(line))
            if tokens + n > max_tokens:
                break
            lines.append(line)
            tokens += n
    finally:
        proc.kill()
        proc.wait()
    return lines, tokens


def ts_of(line: str) -> str:
    return line[1:19] if line.startswith("[") else "?"


def readable_streams(kernel: Path, run_id: str) -> tuple[Path, list[dict]]:
    """A copy of the trace folder (symlinks) without the stream files babeltrace2 cannot read to
    the end, and what was left out. babeltrace2 stops at the first damaged packet in any stream,
    so one bad stream would otherwise end every window after it. (pipeline-394e: the CPU 6
    stream, bench_6, has a damaged packet 4.5 s into the trace. Trace Compass reads past it.)"""
    good = SLICES / run_id / "_readable"
    if good.exists():
        for f in good.iterdir():
            f.unlink()
    good.mkdir(parents=True, exist_ok=True)
    (good / "metadata").symlink_to(kernel / "metadata")
    dropped = []
    probe = SLICES / run_id / "_probe"
    for stream in sorted(f for f in kernel.iterdir() if f.is_file() and f.name != "metadata"):
        if probe.exists():
            for f in probe.iterdir():
                f.unlink()
        probe.mkdir(exist_ok=True)
        (probe / "metadata").symlink_to(kernel / "metadata")
        (probe / stream.name).symlink_to(stream)
        r = subprocess.run(["babeltrace2", str(probe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, errors="replace")
        if r.returncode == 0:
            (good / stream.name).symlink_to(stream)
        else:
            lines = r.stdout.splitlines()
            dropped.append({"stream": stream.name, "readable_until": ts_of(lines[-1]) if lines else None})
    for f in probe.iterdir():
        f.unlink()
    probe.rmdir()
    return good, dropped


def build_slice(run_id: str, enc, budget: int, windows: int) -> tuple[str, dict]:
    """CASCON's C_sampled slice: `windows` windows of consecutive events, evenly spaced."""
    kernel = common.kernel_dir(run_id)
    begin, end = trace_range_ns(kernel)
    span_s = (end - begin) / 1e9
    starts = [begin + (2 * i + 1) * (end - begin) // (2 * windows) for i in range(windows)]
    per_window = budget // windows
    with ThreadPoolExecutor(max_workers=8) as pool:
        parts = list(pool.map(lambda s: read_events(kernel, enc, per_window, s), starts))
    dropped = []
    if any(not lines for lines, _ in parts):
        # A window came back empty: babeltrace2 hit a damaged packet. Read those windows again
        # from the streams it can read, and say in the slice what is missing.
        good, dropped = readable_streams(kernel, run_id)
        redo = [i for i, (lines, _) in enumerate(parts) if not lines]
        with ThreadPoolExecutor(max_workers=8) as pool:
            again = list(pool.map(lambda i: read_events(good, enc, per_window, starts[i]), redo))
        for i, part in zip(redo, again):
            parts[i] = part
    chunks, wmeta = [], []
    for i, (lines, _) in enumerate(parts, 1):
        if not lines:
            continue
        chunks.append(f"=== window {i}/{windows}: {len(lines)} events, "
                      f"{ts_of(lines[0])} to {ts_of(lines[-1])} ===\n" + "".join(lines))
        wmeta.append({"window": i, "events": len(lines), "first_ts": ts_of(lines[0]),
                      "last_ts": ts_of(lines[-1])})
    local = lambda ns: datetime.fromtimestamp(ns / 1e9).strftime("%H:%M:%S")
    header = (f"LTTng kernel trace, babeltrace2 text output. The full trace spans {span_s:.1f} s "
              f"({local(begin)} to {local(end)}) and contains far more events than fit here. "
              f"Shown below: {len(wmeta)} short windows of consecutive events, spaced evenly across "
              f"the whole trace. Events between windows are omitted.")
    for d in dropped:
        header += (f" The stream file {d['stream']} has a damaged packet that babeltrace2 cannot read"
                   f" past (readable until {d['readable_until']}); its events are missing from the"
                   f" windows after that.")
    text = f"{header}\n\n" + "".join(chunks)
    meta = {"run_id": run_id, "slice": "C_sampled", "budget_tokens": budget, "encoding": enc.name,
            "trace_begin_ns": begin, "trace_end_ns": end, "trace_span_s": round(span_s, 3),
            "events": sum(w["events"] for w in wmeta), "windows": wmeta, "unreadable_streams": dropped,
            "tokens": len(enc.encode_ordinary(text))}
    return text, meta


def cmd_prepare(args) -> int:
    import tiktoken

    enc = tiktoken.get_encoding(args.encoding)
    runs = sorted({j["run_id"] for j in common.load_jobs(trace=args.trace)})
    for n, run_id in enumerate(runs, 1):
        txt = SLICES / run_id / "C_sampled.txt"
        meta_path = txt.with_suffix(".json")
        if txt.exists() and meta_path.exists() and not args.force:
            meta = json.loads(meta_path.read_text())
            if meta.get("budget_tokens") == args.budget:
                continue
        t0 = time.time()
        text, meta = build_slice(run_id, enc, args.budget, args.windows)
        txt.parent.mkdir(parents=True, exist_ok=True)
        txt.write_text(text)
        meta_path.write_text(json.dumps(meta, indent=1) + "\n")
        print(f"[{n}/{len(runs)}] {run_id:<22} {meta['events']:>8} events {meta['tokens']:>8} tokens "
              f"({time.time() - t0:.0f} s)", flush=True)
    print(f"slices for {len(runs)} traces in {SLICES}")
    return 0


# --------------------------------------------------------------------------- run

def knowledge_text(documents: list[dict]) -> str:
    """RETRIEVED KNOWLEDGE, in the format of tmll/rag/prompt_builder.py (as in CASCON)."""
    sections = []
    for d in documents:
        body = d["full_source_text"] or d["text"]
        note = " (full source fetched)" if d["full_source_text"] else " (indexed summary only)"
        sections.append(f"[{d['rank']}] {d['title']}{note}\n{body}\nSource: {d['source_url']}")
    return "RETRIEVED KNOWLEDGE\n" + "\n\n".join(sections)


def ask(client, args, slice_text: str, tail: str, cache_key: str):
    params = {
        "model": args.model,
        "instructions": SYSTEM_PROMPTS[args.system],
        "input": [{"role": "user", "content": [
            # The slice is its own block ending in an explicit cache breakpoint (as in CASCON),
            # so every question on the same trace reads it from the prompt cache.
            {"type": "input_text", "text": slice_text,
             "prompt_cache_breakpoint": {"mode": "explicit"}},
            {"type": "input_text", "text": tail},
        ]}],
        "prompt_cache_key": cache_key,
        "max_output_tokens": args.max_output_tokens,
        "store": False,
    }
    if args.reasoning_effort:
        params["reasoning"] = {"effort": args.reasoning_effort}
    return client.responses.create(**params)


def cmd_run(args) -> int:
    jobs = common.load_jobs(question=args.question, trace=args.trace, wording=args.wording)
    docs = json.loads(DOCS_FILE.read_text()) if args.system == "rag" else {}
    if args.system == "rag":
        missing = sorted({j["question_id"] for j in jobs} - set(docs))
        if missing:
            sys.exit(f"no retrieved documents for {missing[:5]}...; run retrieve_docs.py first")
    missing = sorted({j["run_id"] for j in jobs if not (SLICES / j["run_id"] / "C_sampled.txt").exists()})
    if missing:
        sys.exit(f"no slice for {len(missing)} traces ({missing[:3]}...); run `prepare` first")

    folder = common.out_dir(args.system, args.run, args.out)
    todo = common.pending(jobs, folder, args.retry_errors)
    saved = len(jobs) - len(todo)
    if args.limit is not None:
        todo = todo[:args.limit]
    by_trace: dict[str, list[dict]] = {}
    for j in todo:
        by_trace.setdefault(j["run_id"], []).append(j)
    tokens = sum(json.loads((SLICES / r / "C_sampled.json").read_text())["tokens"] * len(js)
                 for r, js in by_trace.items())
    print(f"{args.system} run {args.run}: {len(jobs)} answers in this selection, "
          f"{saved} already saved; asking "
          f"{len(todo)} on {len(by_trace)} traces, ~{tokens / 1e6:.1f}M input tokens of trace"
          + (" plus ~4.5k of retrieved knowledge each" if args.system == "rag" else ""))
    if args.dry_run:
        for j in todo[:10]:
            print(f"  {j['id']:<26} {j['text'][:90]}")
        return 0

    common.require_key()
    from openai import OpenAI

    client = OpenAI(max_retries=args.max_retries, timeout=args.timeout)
    lock = threading.Lock()
    stop = threading.Event()
    done = [0]
    started_all = time.time()
    totals = {"input": 0, "cached": 0, "output": 0}

    def one(run_id: str, slice_text: str, meta: dict, build: str, j: dict) -> None:
        if stop.is_set():
            return
        record = common.new_record(args.system, build, args.run, j)
        record.update(slice="C_sampled", slice_tokens=meta["tokens"], slice_events=meta["events"],
                      reasoning_effort=args.reasoning_effort)
        if args.system == "rag":
            retrieved = docs[j["question_id"]]["documents"]
            record["retrieved_doc_ids"] = [d["id"] for d in retrieved]
            tail = f"\n\n---\n{knowledge_text(retrieved)}\n\n---\nQuestion: {j['prompt']}"
        else:
            tail = f"\n\n---\nQuestion: {j['prompt']}"
        t0 = time.time()
        answer, error = None, None
        try:
            resp = ask(client, args, slice_text, tail, f"bench-{args.system}-{run_id}")
            usage = resp.usage
            answer = resp.output_text
            record.update(model=resp.model, response_status=resp.status,
                          incomplete_reason=getattr(resp.incomplete_details, "reason", None),
                          usage={"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
                                 "cached_tokens": getattr(usage.input_tokens_details, "cached_tokens", None),
                                 "reasoning_tokens": getattr(usage.output_tokens_details, "reasoning_tokens", None)})
            if resp.status != "completed":
                error = f"response {resp.status}: {record['incomplete_reason']}"
        except Exception as e:  # saved as an error; --retry-errors asks again
            error = f"{type(e).__name__}: {e}"
            if "insufficient_quota" in str(e) or "context_length" in str(e):
                stop.set()
        record["elapsed_s"] = round(time.time() - t0, 2)
        common.finish(record, answer, error)
        with lock:
            common.save(folder, record)
            done[0] += 1
            u = record.get("usage") or {}
            totals["input"] += u.get("input_tokens") or 0
            totals["cached"] += u.get("cached_tokens") or 0
            totals["output"] += u.get("output_tokens") or 0
            print(common.progress(done[0], len(todo), record), flush=True)

    for run_id, js in by_trace.items():
        slice_text = (SLICES / run_id / "C_sampled.txt").read_text()
        meta = json.loads((SLICES / run_id / "C_sampled.json").read_text())
        parts = [Path(__file__), SYSTEM_PROMPTS[args.system], args.model, args.reasoning_effort,
                 args.max_output_tokens, meta["tokens"], common.fingerprint(slice_text)]
        if args.system == "rag":
            parts.append(DOCS_FILE)
        build = common.fingerprint(*parts)
        # The first call alone, so the slice is in the prompt cache before the rest go out.
        one(run_id, slice_text, meta, build, js[0])
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for j in js[1:]:
                pool.submit(one, run_id, slice_text, meta, build, j)
        if stop.is_set():
            print("Stopped: the API account is out of credit or the slice does not fit the model's "
                  "context window (see the last error). Fix it, then run the same command again.",
                  file=sys.stderr)
            return 2
    took = time.time() - started_all
    print(f"done: {done[0]} answers in {took / 60:.1f} min; tokens {totals['input']:,} in "
          f"({totals['cached']:,} cached), {totals['output']:,} out")
    return 0


# --------------------------------------------------------------------------- main

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("prepare", help="cut each bench trace into a token-budgeted slice")
    sp.add_argument("--trace", nargs="*", help="only these runs (default: every run in pairs.json)")
    sp.add_argument("--budget", type=int, default=200_000, help="max trace tokens per slice (default 200000)")
    sp.add_argument("--windows", type=int, default=20, help="windows per slice (default 20)")
    sp.add_argument("--encoding", default="o200k_base", help="tiktoken encoding (default o200k_base)")
    sp.add_argument("--force", action="store_true", help="rebuild slices that already exist")
    sp.set_defaults(func=cmd_prepare)

    sp = sub.add_parser("run", help="ask every bench question on its trace's slice")
    sp.add_argument("--system", required=True, choices=sorted(SYSTEM_PROMPTS))
    sp.add_argument("--run", type=int, default=1)
    sp.add_argument("--out", help="save under results/<system>/<out> instead of run<N>")
    sp.add_argument("--question", nargs="*", help="only these questions, e.g. Q15 Q23")
    sp.add_argument("--trace", nargs="*", help="only these runs, e.g. batch_server-1f3b")
    sp.add_argument("--wording", choices=("a", "b"))
    sp.add_argument("--limit", type=int, help="ask at most this many new questions")
    sp.add_argument("--model", default=common.MODEL)
    sp.add_argument("--reasoning-effort", choices=["none", "minimal", "low", "medium", "high", "xhigh", "max"],
                    help="default: the model's own default, as TraceAssist's answer writer")
    sp.add_argument("--max-output-tokens", type=int, default=32_000, help="includes reasoning (default 32000)")
    sp.add_argument("--workers", type=int, default=2, help="parallel calls per trace (default 2)")
    sp.add_argument("--timeout", type=float, default=900, help="seconds per call (default 900)")
    sp.add_argument("--max-retries", type=int, default=5)
    sp.add_argument("--retry-errors", action="store_true", help="ask again where an error was saved")
    sp.add_argument("--dry-run", action="store_true", help="only print what would be asked")
    sp.set_defaults(func=cmd_run)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
