#!/usr/bin/env python3
"""Asks TraceAssist every bench question on its traces, through the server's /ask endpoint, and
saves each answer for grading.

    python3 run_traceassist.py --dry-run                 # list what would be asked, no calls
    python3 run_traceassist.py --run 1 --limit 10        # the first 10 answers of run 1
    python3 run_traceassist.py --run 1 --v1              # the 6 supported symptoms only
    python3 run_traceassist.py --run 1                   # all 516 (258 pairs x 2 wordings)
    python3 run_traceassist.py --run 2 ...               # runs 2 and 3: TraceAssist's consistency

Needs the Trace Server with TraceAssist on 127.0.0.1:8092 (and the TMLL service on 8000 for
TMLL's evidence and the RAG documents).

What a system under test sees: the kernel trace folder and the question text with the verdict
line (verdict.py). Nothing else: no run id meaning, no fault, no truth. The truth lives in
pairs.json and is only joined back at grading time.

Each answer is saved to results/traceassist/run<N>/<question id>__<run id>.json, written once
it is complete, so the runner can be stopped and restarted: answers already saved are skipped
(use --retry-errors to redo the ones that failed). Questions are grouped by trace, so the server
opens each trace once per run. The server answers one question at a time, so this runs
sequentially.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import verdict

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results" / "traceassist"
SYSTEM = "traceassist"
# What decides TraceAssist's behaviour: the bundle installed in the Trace Server, and the skill
# files it reads at run time from the plug-in project. Their hash is saved with every answer.
BUNDLE = (Path(os.environ.get("TRACE_SERVER", HERE.parent / "trace-server" / "trace-compass-server")) / "plugins"
          / "org.eclipse.tracecompass.traceassist.server_0.1.0.jar")
SKILLS = HERE.parent / "traceassist" / "plugin" / "skills"
# The TMLL service (TMLL evidence, late cycles, RAG): its Python code, not its cache or documents.
TMLL = HERE.parent / "tmll"


def build_fingerprint() -> str:
    """sha256 over the installed bundle, every skill file and the TMLL service's code: two answers
    with the same fingerprint came from the same TraceAssist. (The running service must have been
    restarted after a code change for this to hold.)"""
    import hashlib
    h = hashlib.sha256()
    files = [BUNDLE] + sorted(SKILLS.rglob("*")) + sorted(TMLL.glob("*.py")) + sorted((TMLL / "rag").glob("*.py"))
    for f in files:
        if f.is_file():
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def knowledge_fingerprint() -> str:
    """sha256 over the RAG knowledge base TraceAssist retrieves from (tmll/rag/knowledge). Kept apart
    from the build fingerprint: the documents decide what the RAG step can add, so a change to them
    must show in the answers too. (The CASCON batch_server description was removed on 2026-11-22.)"""
    import hashlib
    h = hashlib.sha256()
    for f in sorted((TMLL / "rag" / "knowledge").rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(TMLL)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def load_jobs(args) -> list[dict]:
    pairs = json.loads((HERE / "pairs.json").read_text())["pairs"]
    texts = {}
    for q in json.loads((HERE / "questions.json").read_text())["questions"]:
        texts[q["id"]] = q
    jobs = []
    for p in pairs:
        if args.v1 and not p["v1"]:
            continue
        if args.question and p["question"] not in args.question:
            continue
        if args.trace and p["run_id"] not in args.trace:
            continue
        for wording in ("a", "b"):
            if args.wording and wording != args.wording:
                continue
            q = texts[p["question"] + wording]
            jobs.append({
                "id": f"{q['id']}__{p['run_id']}",
                "question_id": q["id"],
                "run_id": p["run_id"],
                "trace": str(HERE / "runs" / p["run_id"] / "trace" / "kernel"),
                "text": q["text"],
            })
    # Grouped by trace, so each trace is opened once; questions in order within a trace.
    order = {f"Q{n}": n for n in range(1, 1000)}
    jobs.sort(key=lambda j: (j["run_id"], order[j["question_id"][:-1]], j["question_id"][-1]))
    return jobs


def ask(server: str, trace: str, text: str, timeout: float) -> dict:
    # skill_cache False: every AI skill calls the model, as on a fresh server. Otherwise runs 2
    # and 3 would reuse run 1's skill decisions (the server keeps them in memory) and look more
    # consistent than they are.
    body = {"trace_path": trace, "question": text, "rag": True, "stream": False, "skill_cache": False}
    request = urllib.request.Request(f"{server}/ask", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def tmll_started_at(tmll: str, wait_s: float = 0) -> float | None:
    """The TMLL service's start time from its /health, or None if it is not up (after waiting up
    to wait_s for it). TraceAssist still answers when TMLL is down, just without TMLL's evidence and
    the RAG documents, so the runner checks it around every answer instead of trusting the answer."""
    deadline = time.time() + wait_s
    while True:
        try:
            with urllib.request.urlopen(f"{tmll}/health", timeout=10) as response:
                return float(json.loads(response.read()).get("started_at") or 0)
        except Exception:
            if time.time() >= deadline:
                return None
            time.sleep(10)


def save(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=1) + "\n")
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=int, default=1, choices=(1, 2, 3), help="repeat number (default 1)")
    ap.add_argument("--server", default="http://127.0.0.1:8092")
    ap.add_argument("--limit", type=int, help="ask at most this many new questions")
    ap.add_argument("--v1", action="store_true", help="only the 6 symptoms the thread search supports")
    ap.add_argument("--question", nargs="*", help="only these questions, e.g. Q15 Q23")
    ap.add_argument("--trace", nargs="*", help="only these runs, e.g. batch_server-ff0f")
    ap.add_argument("--wording", choices=("a", "b"), help="only the precise (a) or everyday (b) wording")
    ap.add_argument("--out", help="save under results/traceassist/<out> instead of run<N> (development checks)")
    ap.add_argument("--tmll", default="http://127.0.0.1:8000", help="the TMLL service, checked around every answer")
    ap.add_argument("--timeout", type=float, default=1800, help="seconds per answer (default 1800)")
    ap.add_argument("--retry-errors", action="store_true", help="redo answers saved with an error")
    ap.add_argument("--dry-run", action="store_true", help="list the jobs, ask nothing")
    args = ap.parse_args()

    jobs = load_jobs(args)
    out_dir = RESULTS / (args.out or f"run{args.run}")
    todo = []
    for j in jobs:
        path = out_dir / f"{j['id']}.json"
        if path.exists():
            old = json.loads(path.read_text())
            if old.get("status") == "ok" or not args.retry_errors:
                continue
        todo.append(j)
    saved = len(jobs) - len(todo)
    if args.limit is not None:
        todo = todo[:args.limit]
    traces = len({j["run_id"] for j in todo})
    print(f"run {args.run}: {len(jobs)} answers in this selection, {saved} already saved; "
          f"asking {len(todo)} on {traces} traces")
    if args.dry_run:
        for j in todo:
            print(f"  {j['id']:<22} {j['text'][:90]}")
        print(f"\nEach question is sent as:\n\n{verdict.prompt('<question>')}")
        return 0

    build = build_fingerprint()
    knowledge = knowledge_fingerprint()
    print(f"TraceAssist build {build}, RAG knowledge base {knowledge}")
    tokens_in = tokens_out = 0
    started_all = time.time()
    for n, j in enumerate(todo, 1):
        prompt = verdict.prompt(j["text"])
        record = {"system": SYSTEM, "build": build, "knowledge": knowledge, "run": args.run, "id": j["id"], "question_id": j["question_id"],
                  "run_id": j["run_id"], "trace": j["trace"], "prompt": prompt,
                  "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        tmll_before = tmll_started_at(args.tmll, wait_s=600)
        if tmll_before is None:
            print(f"error: the TMLL service is not up at {args.tmll}; stopping (nothing saved for {j['id']})",
                  file=sys.stderr)
            return 2
        t0 = time.time()
        try:
            response = ask(args.server, j["trace"], prompt, args.timeout)
            record["status"] = "ok" if response.get("answer") else "error"
            record["answer"] = response.pop("answer", "")
            record["response"] = response
            if record["status"] == "error":
                record["error"] = response.get("error", "no answer in the response")
        except urllib.error.HTTPError as e:
            record.update(status="error", error=f"HTTP {e.code}: {e.read().decode(errors='replace')[:2000]}")
        except urllib.error.URLError as e:
            print(f"error: TraceAssist is not reachable at {args.server} ({e.reason})", file=sys.stderr)
            return 2
        except Exception as e:  # timeout, broken connection, bad JSON
            record.update(status="error", error=repr(e))
        record["elapsed_s"] = round(time.time() - t0, 2)
        tmll_after = tmll_started_at(args.tmll)
        if tmll_after != tmll_before:
            # TMLL died (or restarted) while this answer was built: its TMLL evidence is missing.
            record.update(status="error", error="the TMLL service went down during this answer")
        record["model"] = (record.get("response") or {}).get("model")
        record["verdict"] = verdict.parse(record.get("answer", ""))
        save(out_dir / f"{j['id']}.json", record)

        usage = (record.get("response") or {}).get("usage") or {}
        tokens_in += usage.get("input_tokens", 0)
        tokens_out += usage.get("output_tokens", 0)
        v = record["verdict"]
        shown = v["verdict"] or "NO VERDICT LINE"
        if v["position"] == "later":
            shown += " (not first line)"
        print(f"[{n}/{len(todo)}] {j['id']:<22} {record['status']:<5} {record['elapsed_s']:>7.1f} s  "
              f"{record['model'] or '?'}  "
              f"{shown}" + (f"  {record.get('error', '')[:120]}" if record["status"] != "ok" else ""),
              flush=True)

    took = time.time() - started_all
    print(f"done: {len(todo)} answers in {took / 60:.1f} min; answer-writer tokens "
          f"{tokens_in:,} in, {tokens_out:,} out (the AI skills' tokens are not reported)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
