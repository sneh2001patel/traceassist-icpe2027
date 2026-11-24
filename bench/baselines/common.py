"""What the four bench baselines share: the questions they are asked, the prompt and verdict line,
and how an answer is saved so that score.py grades it exactly like TraceAssist's.

A baseline sees only the question text with the verdict line (verdict.py) and the run's
trace/kernel folder, as TraceAssist does. pairs.json is read only for which question goes with
which run; its truth, role and fault fields are never passed on. ground_truth/, capture.json,
program.log, index.csv, pairs.csv and answer_key.json are never opened.

Answers are saved to results/<system>/run<N>/<question id>__<run id>.json with the same fields
run_traceassist.py writes (status "ok" or "error", answer, verdict, model, build), so
    python3 score.py --system <system> --run 1
scores them. Each baseline is run once (run 1) and compared with TraceAssist's run 1.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent          # symptom_bench/baselines
BENCH = HERE.parent                             # symptom_bench
sys.path.insert(0, str(BENCH))
import verdict  # noqa: E402  (the bench's verdict line and its parser)

RESULTS = BENCH / "results"
RUNS = BENCH / "runs"
MODEL = "gpt-6-luna"   # the model TraceAssist's answer writer uses (AnswerWriter.DEFAULT_MODEL)


def program_of(run_id: str) -> str:
    """The program a run traced: the run id without its 4-hex suffix ("batch_server-1f3b" ->
    "batch_server"). Every bench question names this program, so it is not extra information."""
    return run_id.rsplit("-", 1)[0]


def kernel_dir(run_id: str) -> Path:
    return RUNS / run_id / "trace" / "kernel"


def load_jobs(question=None, trace=None, wording=None) -> list[dict]:
    """Every (question wording, run) the bench asks: 258 pairs x 2 wordings = 516 jobs, grouped by
    trace (so a trace's slice or evidence is loaded once) and in question order within a trace."""
    pairs = json.loads((BENCH / "pairs.json").read_text())["pairs"]
    texts = {q["id"]: q for q in json.loads((BENCH / "questions.json").read_text())["questions"]}
    jobs = []
    for p in pairs:
        if question and p["question"] not in question:
            continue
        if trace and p["run_id"] not in trace:
            continue
        for w in ("a", "b"):
            if wording and w != wording:
                continue
            q = texts[p["question"] + w]
            jobs.append({"id": f"{q['id']}__{p['run_id']}", "question_id": q["id"],
                         "run_id": p["run_id"], "program": program_of(p["run_id"]),
                         "trace": str(kernel_dir(p["run_id"])), "text": q["text"],
                         "prompt": verdict.prompt(q["text"])})
    order = {f"Q{n}": n for n in range(1, 1000)}
    jobs.sort(key=lambda j: (j["run_id"], order[j["question_id"][:-1]], j["question_id"][-1]))
    return jobs


def fingerprint(*parts) -> str:
    """sha256 over strings and files: two answers with the same build came from the same baseline
    code, prompt and inputs."""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, Path):
            h.update(part.name.encode())
            h.update(part.read_bytes())
        else:
            h.update(str(part).encode())
    return h.hexdigest()[:16]


def out_dir(system: str, run: int, out: str | None = None) -> Path:
    return RESULTS / system / (out or f"run{run}")


def pending(jobs: list[dict], folder: Path, retry_errors: bool) -> list[dict]:
    """The jobs without a saved answer (and, with retry_errors, those saved with an error)."""
    todo = []
    for j in jobs:
        path = folder / f"{j['id']}.json"
        if path.exists():
            old = json.loads(path.read_text())
            if old.get("status") == "ok" or not retry_errors:
                continue
        todo.append(j)
    return todo


def new_record(system: str, build: str, run: int, job: dict) -> dict:
    return {"system": system, "build": build, "run": run, "id": job["id"],
            "question_id": job["question_id"], "run_id": job["run_id"], "trace": job["trace"],
            "prompt": job["prompt"], "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}


def finish(record: dict, answer: str | None, error: str | None = None) -> dict:
    """Sets status, answer and the parsed verdict, the fields score.py reads."""
    record["answer"] = answer or ""
    if error:
        record.update(status="error", error=error)
    elif not record["answer"].strip():
        record.update(status="error", error="empty answer")
    else:
        record["status"] = "ok"
    record["verdict"] = verdict.parse(record["answer"])
    return record


def save(folder: Path, record: dict) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{record['id']}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=1) + "\n")
    os.replace(tmp, path)


def progress(n: int, total: int, record: dict) -> str:
    v = record["verdict"]
    shown = v["verdict"] or "NO VERDICT LINE"
    if v.get("position") == "later":
        shown += " (not first line)"
    extra = f"  {record.get('error', '')[:120]}" if record["status"] != "ok" else ""
    return (f"[{n}/{total}] {record['id']:<26} {record['status']:<5} {record.get('elapsed_s', 0):>7.1f} s  "
            f"{record.get('model') or '?'}  {shown}{extra}")


def require_key() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is not set. Export it in this shell first (it is read from the "
                 "environment only, never printed or saved).")
