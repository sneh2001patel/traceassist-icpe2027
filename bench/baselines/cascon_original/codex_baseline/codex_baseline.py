#!/usr/bin/env python3
"""
Codex-agent baseline for the CASCON experiment: a general-purpose coding agent
(Codex CLI, GPT-5.6) with a shell, babeltrace2 and Python, given the full trace.

Condition (same as the other baselines where it matters):
  - model gpt-5.6-sol (what the alias gpt-5.6 resolved to for the other baselines), at the
    reasoning effort the API uses by default for gpt-5.6 (looked up at run time), no web search
  - the agent sees only the trace's kernel/ directory (read-only, at /data/trace);
    ground_truth/, program.log, the program source, the paper and the other
    baselines are not in the container
  - the container's only network route is a proxy that allows the model API hosts
    (docker/allowlist); everything else, including pip and curl, is refused
  - a fresh CODEX_HOME per conversation (no memories, no earlier sessions), with
    connectors, plugins, browsers and image generation turned off (codex_config.toml)

Session style: one conversation per trace. Q1 starts a `codex exec` session and
Q2..Q13 continue it with `codex exec resume`, in the order of questions.json, the
same order the framework was asked in. The agent's workspace (/work) and session
persist across the questions of one trace, and nothing carries over between traces.

Time budget: --question-timeout seconds per question (default 1800 = 30 min),
enforced inside the container. A question that runs out of time is recorded with
status "timeout" and no answer, and the conversation moves on to the next question.

Setup:   docker compose --profile agent build        (or: codex_baseline.py build)
         codex_baseline.py check                      # isolation + model smoke test
Auth:    export OPENAI_API_KEY=...   (required: Codex refuses gpt-5.6 on a ChatGPT login;
         the API key is also how llm_baseline and RAG_baseline were run)
Usage:   codex_baseline.py run --dry-run
         codex_baseline.py run [--traces 2m] [--repeats 1]   # appends results/answers.jsonl
         codex_baseline.py export                            # results/answers.csv + .md
A stopped run continues where it left off: rerun the same command.
"""
import argparse
import csv
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNS_DIR = HERE.parent / "runs" / "runs_to_use"
QUESTIONS_FILE = HERE.parent / "llm_baseline" / "questions.json"   # identical wording
COMPOSE_FILE = HERE / "docker-compose.yml"
CODEX_CONFIG = HERE / "codex_config.toml"
WORK_DIR = HERE / "work"                    # per-conversation workspaces (gitignored)
RESULTS_DIR = HERE / "results"
ANSWERS_JSONL = RESULTS_DIR / "answers.jsonl"
TRANSCRIPTS_DIR = RESULTS_DIR / "transcripts"

AGENT_IMAGE = "codex-baseline-agent:latest"
PROXY_SERVICE = "proxy"

PREAMBLE = """\
You are an expert in Linux kernel tracing and performance analysis.

An LTTng kernel trace (CTF format) is in /data/trace (read-only). Your working directory, \
/work, is yours for scripts and intermediate files. You have babeltrace2, Python 3 with \
the bt2 bindings, numpy and pandas, and standard command-line tools. There is no internet \
access.

I will ask you a series of questions about this trace, one per message. Answer each one \
using evidence from the trace. Be specific: name processes and threads (with their TIDs), \
CPUs, system calls and durations where relevant. If the trace is not enough to answer \
with confidence, say so and explain what is missing, then give your best answer.

Each question has a time limit of {minutes} minutes. If you run out of time the question \
gets no answer, so leave enough time to write it. End each turn with your final answer to \
the question."""

# Commands that touch credentials or the model API directly are flagged for review: with
# the API reachable through the proxy, these are the only way around the no-web condition.
SUSPICIOUS = re.compile(r"auth\.json|/codex\b|openai\.com|chatgpt\.com|HTTPS?_PROXY|proxy:8888",
                        re.IGNORECASE)


# --------------------------------------------------------------------------- helpers

def find_traces():
    """[(label, run_dir, kernel_dir)] for every run in runs/runs_to_use, shortest first."""
    traces = []
    for run in sorted(RUNS_DIR.iterdir()):
        m = re.search(r"-(\d+)m-", run.name)
        kernel = run / "trace" / "kernel"
        if m and kernel.is_dir():
            traces.append((int(m.group(1)), f"{m.group(1)}m", run, kernel))
    return [(label, run, kernel) for _, label, run, kernel in sorted(traces)]


def load_questions(args):
    questions = json.loads(QUESTIONS_FILE.read_text())
    if args.questions:
        questions = [q for q in questions if q["id"] in args.questions]
    return questions


def compose(*args, **kw):
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], **kw)


def start_proxy():
    compose("up", "-d", "--wait", PROXY_SERVICE, check=True, capture_output=True)


def start_agent(name, kernel, workspace, home):
    """A long-lived agent container for one conversation; questions run via `docker exec`."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    compose("run", "-d", "--rm", "--name", name, "-u", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{kernel}:/data/trace:ro", "-v", f"{workspace}:/work",
            "-v", f"{home}:/codex", "agent", check=True, capture_output=True)


def stop_agent(name):
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def write_auth(home, mode):
    """Put credentials into a fresh CODEX_HOME. Removed again when the conversation ends."""
    auth = home / "auth.json"
    if mode == "api-key":
        subprocess.run(["codex", "login", "--with-api-key"], input=os.environ["OPENAI_API_KEY"],
                       text=True, check=True, capture_output=True,
                       env={**os.environ, "CODEX_HOME": str(home)})
    else:
        shutil.copy(Path.home() / ".codex" / "auth.json", auth)
    auth.chmod(0o600)


def auth_mode(args):
    if args.auth == "api-key" and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("Set OPENAI_API_KEY first. Codex refuses gpt-5.6 on a ChatGPT login "
                 "(\"model is not supported when using Codex with a ChatGPT account\"), "
                 "and the API key matches how llm_baseline and RAG_baseline were run.")
    return args.auth


def api_default(alias):
    """(resolved model, default reasoning effort) the OpenAI API uses for `alias` when the
    request names no effort, which is how llm_baseline and RAG_baseline called it."""
    import urllib.request
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps({"model": alias, "input": "Reply with OK.", "max_output_tokens": 256,
                         "store": False}).encode(),
        headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        resp = json.load(r)
    return resp.get("model"), (resp.get("reasoning") or {}).get("effort")


def resolve_effort(args):
    """--reasoning-effort match: pin Codex to the API's own default for the baselines' alias.
    Codex would otherwise send its catalog default (`low` for gpt-5.6-sol)."""
    if args.reasoning_effort != "match":
        return
    resolved, effort = api_default(args.baseline_alias)
    print(f"API default for {args.baseline_alias}: model {resolved}, reasoning effort {effort}")
    if resolved != args.model:
        sys.exit(f"{args.baseline_alias} now resolves to {resolved}, not {args.model}. Check which "
                 f"model the other baselines' answers.jsonl recorded as response_model, and pass "
                 f"--model and --reasoning-effort explicitly.")
    if not effort:
        sys.exit("the API did not report a default reasoning effort; pass --reasoning-effort")
    args.reasoning_effort = effort


def codex_cmd(args, session_id, answer_path, timeout_s):
    cmd = ["timeout", "-k", "30", str(timeout_s), "codex", "exec"]
    if session_id:
        cmd += ["resume", session_id]
    cmd += ["--strict-config", "--json", "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",   # Docker is the sandbox
            "-m", args.model, "-o", answer_path]
    if not session_id:
        cmd += ["-C", "/work"]
    if args.reasoning_effort:
        cmd += ["-c", f'model_reasoning_effort="{args.reasoning_effort}"']
    return cmd + ["-"]   # prompt from stdin


def parse_events(path):
    """Session id, token usage, tool use and errors from a `codex exec --json` event log."""
    out = {"session_id": None, "input_tokens": 0, "cached_tokens": 0, "output_tokens": 0,
           "reasoning_tokens": 0, "turns": 0, "item_types": Counter(), "commands": [],
           "errors": [], "warnings": []}
    for line in path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("type", "")
        if t == "thread.started":
            out["session_id"] = out["session_id"] or ev.get("thread_id")
        elif t == "turn.completed":
            u = ev.get("usage") or {}
            out["turns"] += 1
            out["input_tokens"] += u.get("input_tokens") or 0
            out["cached_tokens"] += u.get("cached_input_tokens") or 0
            out["output_tokens"] += u.get("output_tokens") or 0
            out["reasoning_tokens"] += u.get("reasoning_output_tokens") or 0
        elif t == "item.completed":
            item = ev.get("item") or {}
            out["item_types"][item.get("type", "?")] += 1
            if item.get("type") == "command_execution":
                out["commands"].append(item.get("command", ""))
            elif item.get("type") == "error":   # non-fatal notices, e.g. missing model metadata
                out["warnings"].append(item.get("message", ""))
        elif t in ("turn.failed", "error"):
            err = ev.get("error") or ev
            out["errors"].append(err.get("message") if isinstance(err, dict) else str(err))
    return out


# --------------------------------------------------------------------------- build / check

def cmd_build(args):
    compose("--profile", "agent", "build", check=True)


def cmd_check(args):
    """Prove the isolation holds, then (unless --no-model) send one tiny prompt."""
    start_proxy()
    name = "codex-baseline-check"
    tmp = WORK_DIR / "_check"
    shutil.rmtree(tmp, ignore_errors=True)
    (tmp / "work").mkdir(parents=True)
    (tmp / "codex").mkdir()
    shutil.copy(CODEX_CONFIG, tmp / "codex" / "config.toml")
    kernel = find_traces()[0][2]
    ok = True
    try:
        start_agent(name, kernel, tmp / "work", tmp / "codex")
        probe = r"""
import os, socket, urllib.request, urllib.error
def get(url, proxy):
    h = urllib.request.ProxyHandler({"https": "http://proxy:8888"} if proxy else {})
    try:
        r = urllib.request.build_opener(h).open(url, timeout=10); return f"reached (HTTP {r.status})"
    except urllib.error.HTTPError as e: return f"reached (HTTP {e.code})"
    except Exception as e: return f"blocked ({type(e).__name__})"
print("direct  example.com   :", get("https://example.com", False))
print("direct  api.openai.com:", get("https://api.openai.com/v1/models", False))
print("proxy   example.com   :", get("https://example.com", True))
print("proxy   google.com    :", get("https://www.google.com", True))
print("proxy   pypi.org      :", get("https://pypi.org/simple/", True))
print("proxy   api.openai.com:", get("https://api.openai.com/v1/models", True))
"""
        r = subprocess.run(["docker", "exec", name, "python3", "-c", probe],
                           capture_output=True, text=True)
        print(r.stdout + r.stderr)
        for line in r.stdout.splitlines():
            should_reach = line.startswith("proxy   api.openai.com")
            if ("reached" in line) != should_reach:
                ok = False
                print(f"  !! unexpected: {line}")
        r = subprocess.run(["docker", "exec", name, "sh", "-c",
                            "codex --version; babeltrace2 --version | head -1; "
                            "python3 -c 'import bt2, pandas; print(\"bt2\", bt2.__version__)'; "
                            "ls /data/trace | head -3; ls / "],
                           capture_output=True, text=True)
        print(r.stdout + r.stderr)

        if not args.no_model:
            write_auth(tmp / "codex", auth_mode(args))
            resolve_effort(args)
            cmd = codex_cmd(args, None, "/codex/check.md", 300)
            r = subprocess.run(["docker", "exec", "-i", "-w", "/work", name, *cmd],
                               input="Reply with the single word OK. Do not run any commands.",
                               capture_output=True, text=True)
            (tmp / "events.jsonl").write_text(r.stdout)
            ev = parse_events(tmp / "events.jsonl")
            answer = (tmp / "codex" / "check.md")
            print(f"model {args.model}: exit {r.returncode}, answer "
                  f"{answer.read_text().strip()!r}" if answer.exists() else
                  f"model {args.model}: exit {r.returncode}, no answer")
            print(f"  session {ev['session_id']}, tokens in/out {ev['input_tokens']}/"
                  f"{ev['output_tokens']}, items {dict(ev['item_types'])}")
            for w in ev["warnings"]:
                print(f"  warning: {w}")
            for e in ev["errors"]:
                print(f"  error: {e}")
            if r.returncode != 0 or not answer.exists():
                ok = False
                print(r.stderr[-3000:])
    finally:
        stop_agent(name)
        (tmp / "codex" / "auth.json").unlink(missing_ok=True)
    print("CHECK PASSED" if ok else "CHECK FAILED")
    sys.exit(0 if ok else 1)


# --------------------------------------------------------------------------- run

def load_records():
    if not ANSWERS_JSONL.exists():
        return []
    return [json.loads(line) for line in ANSWERS_JSONL.read_text().splitlines() if line.strip()]


TOKEN_KEYS = ("input_tokens", "cached_tokens", "output_tokens", "reasoning_tokens")


def fmt(n):
    return "?" if n is None else f"{n:,}"


def conversation_state(records, model, label, rep):
    """(question ids already settled, session id, session token totals so far, question ids
    whose tokens are not yet measured) for one trace conversation."""
    done, session = set(), None
    totals, pending = dict.fromkeys(TOKEN_KEYS, 0), []
    for r in records:
        if r["model"] == model and r["trace"] == label and r["repeat"] == rep:
            session = session or r.get("session_id")
            if r["status"] in ("completed", "timeout"):
                done.add(r["question_id"])
            if r.get("session_tokens"):
                totals, pending = r["session_tokens"], []
            else:
                pending.append(r["question_id"])
    return done, session, totals, pending


def run_conversation(args, label, run, kernel, rep, questions, lock):
    key = f"{label}-r{rep}"
    with lock:
        done, session_id, totals, pending = conversation_state(load_records(), args.model,
                                                                label, rep)
    todo = [q for q in questions if q["id"] not in done]
    if not todo:
        return
    base = WORK_DIR / key
    if session_id is None:          # not started yet: begin from a clean slate
        shutil.rmtree(base, ignore_errors=True)
    (base / "work").mkdir(parents=True, exist_ok=True)
    (base / "codex" / "answers").mkdir(parents=True, exist_ok=True)
    shutil.copy(CODEX_CONFIG, base / "codex" / "config.toml")
    tdir = TRANSCRIPTS_DIR / key
    tdir.mkdir(parents=True, exist_ok=True)

    name = f"codex-baseline-{key}"
    write_auth(base / "codex", args.auth_mode)
    try:
        start_agent(name, kernel, base / "work", base / "codex")
        for q in todo:
            first = session_id is None
            prompt = (PREAMBLE.format(minutes=args.question_timeout // 60) + "\n\nQuestion: "
                      if first else "Question: ") + q["question"]
            answer_file = base / "codex" / "answers" / f"{q['id']}.md"
            answer_file.unlink(missing_ok=True)
            events_file = tdir / f"{q['id']}.jsonl"
            cmd = codex_cmd(args, session_id, f"/codex/answers/{q['id']}.md",
                            args.question_timeout)
            rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "model": args.model, "reasoning_effort": args.reasoning_effort,
                   "auth": args.auth_mode, "trace": label, "run": run.name, "repeat": rep,
                   "question_id": q["id"], "question_type": q["type"], "hub": q.get("hub"),
                   "question": q["question"], "question_timeout_s": args.question_timeout}
            t0 = time.time()
            with events_file.open("w") as out, (tdir / f"{q['id']}.stderr.log").open("w") as err:
                try:
                    p = subprocess.run(["docker", "exec", "-i", "-w", "/work", name, *cmd],
                                       input=prompt, text=True, stdout=out, stderr=err,
                                       timeout=args.question_timeout + 300)
                    code = p.returncode
                except subprocess.TimeoutExpired:   # backstop; `timeout` inside should win
                    subprocess.run(["docker", "exec", name, "pkill", "-f", "codex"],
                                   capture_output=True)
                    code = 124
            ev = parse_events(events_file)
            session_id = session_id or ev["session_id"]
            answer = answer_file.read_text() if answer_file.exists() else ""
            if code in (124, 137):
                status = "timeout"
            elif code == 0 and answer.strip():
                status = "completed"
            else:
                status = "error"
            flagged = [c for c in ev["commands"] if SUSPICIOUS.search(c)]
            # turn.completed usage is the session's running total, so this question's cost
            # is the difference from the last measured total. A question killed before its
            # turn completed has no total; its tokens land in the next measured question,
            # whose tokens_cover then lists both.
            pending.append(q["id"])
            if ev["turns"]:
                now = {k: ev[k] for k in TOKEN_KEYS}
                per_q = {k: now[k] - totals[k] for k in TOKEN_KEYS}
                rec.update(session_tokens=now, tokens_cover=pending)
                totals, pending = now, []
            else:
                per_q = dict.fromkeys(TOKEN_KEYS)
                rec.update(session_tokens=None, tokens_cover=[])
            rec.update(
                status=status, exit_code=code, answer=answer, session_id=session_id,
                latency_s=round(time.time() - t0, 1), turns=ev["turns"], **per_q,
                n_commands=len(ev["commands"]), item_types=dict(ev["item_types"]),
                flagged_commands=flagged, errors=ev["errors"][:5],
                warnings=sorted(set(ev["warnings"]))[:5])
            # Anything beyond shell, edits and messages means a tool we meant to switch off.
            extra = set(ev["item_types"]) - {"command_execution", "agent_message", "reasoning",
                                             "file_change", "todo_list", "error"}
            if extra:
                rec["unexpected_tools"] = sorted(extra)
            with lock:
                RESULTS_DIR.mkdir(exist_ok=True)
                with ANSWERS_JSONL.open("a") as f:
                    f.write(json.dumps(rec) + "\n")
                print(f"  {key:<7} {q['id']:<4} {status:<9} {rec['latency_s']:>7}s "
                      f"{rec['n_commands']:>3} cmds  in {fmt(rec['input_tokens']):>9} "
                      f"(cached {fmt(rec['cached_tokens'])})  out {fmt(rec['output_tokens'])}"
                      + (f"  FLAGGED {len(flagged)}" if flagged else "")
                      + (f"  UNEXPECTED {sorted(extra)}" if extra else ""), flush=True)
            with events_file.open("rb") as src, gzip.open(f"{events_file}.gz", "wb") as dst:
                shutil.copyfileobj(src, dst)
            events_file.unlink()
            if status == "error":
                print(f"  {key}: stopping this conversation after an error on {q['id']}; "
                      f"see {tdir}/{q['id']}.stderr.log. Rerun to continue.", flush=True)
                break
    finally:
        stop_agent(name)
        (base / "codex" / "auth.json").unlink(missing_ok=True)


def cmd_run(args):
    questions = load_questions(args)
    traces = [t for t in find_traces() if not args.traces or t[0] in args.traces]
    records = load_records()
    plan = []
    for label, run, kernel in traces:
        for rep in range(1, args.repeats + 1):
            done, session, _, _ = conversation_state(records, args.model, label, rep)
            todo = [q["id"] for q in questions if q["id"] not in done]
            if todo:
                plan.append((label, run, kernel, rep, todo, session))
    worst_h = sum(len(p[4]) for p in plan) * args.question_timeout / 3600
    print(f"{len(plan)} conversations with {args.model}, "
          f"{sum(len(p[4]) for p in plan)} questions, at most {worst_h:.1f} h "
          f"({args.question_timeout // 60} min per question, {args.jobs} at a time)")
    for label, run, _, rep, todo, session in plan:
        print(f"  {label:>4} repeat {rep}: {' '.join(todo)}"
              + (f"  (resuming session {session})" if session else ""))
    if args.dry_run or not plan:
        return

    args.auth_mode = auth_mode(args)
    print(f"auth: {args.auth_mode}")
    resolve_effort(args)
    print(f"model {args.model}, reasoning effort {args.reasoning_effort}")
    start_proxy()
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run_conversation, args, label, run, kernel, rep, questions, lock)
                   for label, run, kernel, rep, _, _ in plan]
        for f in futures:
            f.result()


# --------------------------------------------------------------------------- export

def cmd_export(args):
    records = load_records()
    if not records:
        sys.exit("no answers recorded yet")
    latest = {}
    for r in records:
        if r["status"] != "error" and (args.repeat is None or r["repeat"] == args.repeat):
            latest[(r["model"], r["trace"], r["question_id"], r["repeat"])] = r
    rows = sorted(latest.values(), key=lambda r: (r["model"], int(r["trace"][:-1]), r["repeat"],
                                                  int(r["question_id"][1:])))
    cols = ["model", "trace", "repeat", "question_id", "question_type", "hub", "question",
            "status", "answer", "latency_s", "n_commands", "turns", "input_tokens",
            "cached_tokens", "output_tokens", "reasoning_tokens", "session_id"]
    name = "answers.csv" if args.repeat is None else f"answers_repeat{args.repeat}.csv"
    out = RESULTS_DIR / name
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} answers -> {out}")
    md = out.with_suffix(".md")
    md.write_text(answers_markdown(rows, args.repeat))
    print(f"{len(rows)} answers -> {md}")


def answers_markdown(rows, repeat):
    """Answers grouped by question, so all traces for one question sit together."""
    models = sorted({r["model"] for r in rows})
    lines = [f"# Codex-agent baseline answers ({', '.join(models)}"
             + (f", repeat {repeat})" if repeat else ")"), ""]
    by_q = {}
    for r in sorted(rows, key=lambda r: (int(r["question_id"][1:]), int(r["trace"][:-1]),
                                         r["repeat"])):
        by_q.setdefault(r["question_id"], []).append(r)
    for qid, qrows in by_q.items():
        lines += [f"## {qid} ({qrows[0]['question_type']}): {qrows[0]['question']}", ""]
        for r in qrows:
            rep = "" if repeat else f", repeat {r['repeat']}"
            lines += [f"### {qid} · {r['trace']} trace{rep}", "",
                      f"*{r['status']}, {r['latency_s']} s, {r['n_commands']} commands, "
                      f"{fmt(r['input_tokens'])} input tokens ({fmt(r['cached_tokens'])} cached), "
                      f"{fmt(r['output_tokens'])} output tokens*", ""]
            text = r["answer"] or "(no answer: ran out of time)"
            lines += [f"> {line}" if line.strip() else ">" for line in text.splitlines()]
            lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def model_opts(sp):
        sp.add_argument("--model", default="gpt-5.6-sol",
                        help="default gpt-5.6-sol: what the API alias gpt-5.6 resolved to in "
                             "llm_baseline/RAG_baseline (their response_model), and a model "
                             "Codex has metadata for (the bare alias gets fallback metadata)")
        sp.add_argument("--reasoning-effort", default="match",
                        choices=["match", "none", "minimal", "low", "medium", "high", "xhigh",
                                 "max"],
                        help="match (default): ask the API which effort it uses for "
                             "--baseline-alias by default and pin Codex to that")
        sp.add_argument("--baseline-alias", default="gpt-5.6",
                        help="model name the other baselines requested (default gpt-5.6)")
        sp.add_argument("--auth", choices=["api-key", "chatgpt"], default="api-key",
                        help="api-key (default): OPENAI_API_KEY. chatgpt: a copy of "
                             "~/.codex/auth.json; only for models a ChatGPT plan allows "
                             "(gpt-5.6 is not one of them)")

    sp = sub.add_parser("build", help="build the agent and proxy images")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("check", help="verify network isolation and that the model answers")
    model_opts(sp)
    sp.add_argument("--no-model", action="store_true", help="skip the model call")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("run", help="one conversation per trace, all questions in order")
    model_opts(sp)
    sp.add_argument("--traces", nargs="+", metavar="LABEL", help="e.g. 2m 10m (default: all)")
    sp.add_argument("--questions", nargs="+", metavar="ID", help="e.g. Q1 Q4 (default: all)")
    sp.add_argument("--repeats", type=int, default=1,
                    help="conversations per trace, each from scratch (default 1)")
    sp.add_argument("--question-timeout", type=int, default=1800,
                    help="seconds per question (default 1800 = 30 min)")
    sp.add_argument("--jobs", type=int, default=1,
                    help="conversations at once; >1 makes them compete for CPU, which eats "
                         "into each one's time budget (default 1)")
    sp.add_argument("--dry-run", action="store_true", help="only print the plan")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("export", help="write results/answers.csv and .md")
    sp.add_argument("--repeat", type=int,
                    help="only this repeat, written to results/answers_repeat<N>.csv")
    sp.set_defaults(func=cmd_export)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
