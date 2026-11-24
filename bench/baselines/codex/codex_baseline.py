#!/usr/bin/env python3
"""
Codex-agent baseline on the symptom bench, adapted from the CASCON experiment
(../cascon_original/codex_baseline): a general-purpose coding agent (Codex CLI) with a shell,
babeltrace2 and Python, given the full trace.

Condition (as in CASCON):
  - the agent sees only the run's trace/kernel directory (read-only, at /data/trace);
    ground_truth/, capture.json, program.log, the program sources, the answer key, pairs.json
    and the other systems' answers are not in the container
  - the container's only network route is a proxy that allows the model API hosts
    (docker/allowlist); everything else, including pip and curl, is refused
  - a fresh CODEX_HOME (no memories, no earlier sessions), with connectors, plugins, browsers
    and image generation turned off (codex_config.toml); no web search
  - the model is gpt-6-luna, as for TraceAssist and the other baselines, at the reasoning
    effort the API uses by default for it (looked up at run time, like CASCON's "match")

Changed for the bench (the user's choice): a fresh session per question. Each of the 516
(question, run) pairs starts a new container, workspace and CODEX_HOME, so no answer sees
another, as for TraceAssist and the other baselines. CASCON asked a trace's 13 questions in one
conversation. The question is the bench question with the verdict line (verdict.py).

Time budget: --question-timeout seconds per question (default 1800 = 30 min, as in CASCON),
enforced inside the container. A question that runs out of time is saved with a note instead
of an answer, so score.py counts it as "no verdict" (noV) rather than leaving it out.

Setup:   docker compose --profile agent build        (or: codex_baseline.py build; the CASCON
                                                       images are reused if already built)
         export OPENAI_API_KEY=...
         codex_baseline.py check                      # isolation + model smoke test
Usage:   codex_baseline.py run --dry-run
         codex_baseline.py run [--jobs 2]             # results/codex/run1/<id>.json
         python3 ../../score.py --system codex
A stopped run continues where it left off: rerun the same command.
"""
import argparse

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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common  # noqa: E402  (the bench baselines' shared code)

HERE = Path(__file__).resolve().parent
SYSTEM = "codex"
COMPOSE_FILE = HERE / "docker-compose.yml"
CODEX_CONFIG = HERE / "codex_config.toml"
WORK_DIR = HERE / "work"                    # per-question workspaces, removed afterwards

AGENT_IMAGE = "codex-bench-agent:0.167.0"  # own name: CASCON keeps codex-baseline-agent:latest (codex-cli 0.153.4)
PROXY_SERVICE = "proxy"

PREAMBLE = """\
You are an expert in Linux kernel tracing and performance analysis.

An LTTng kernel trace (CTF format) is in /data/trace (read-only). Your working directory, \
/work, is yours for scripts and intermediate files. You have babeltrace2, Python 3 with \
the bt2 bindings, numpy and pandas, and standard command-line tools. There is no internet \
access.

I will ask you one question about this trace. Answer it using evidence from the trace. Be specific: name processes and threads (with their TIDs), \
CPUs, system calls and durations where relevant. If the trace is not enough to answer \
with confidence, say so and explain what is missing, then give your best answer.

The question has a time limit of {minutes} minutes. If you run out of time it gets no \
answer, so leave enough time to write it. End your turn with your final answer to the \
question."""

# Commands that touch credentials or the model API directly are flagged for review: with
# the API reachable through the proxy, these are the only way around the no-web condition.
SUSPICIOUS = re.compile(r"auth\.json|/codex\b|openai\.com|chatgpt\.com|HTTPS?_PROXY|proxy:8888",
                        re.IGNORECASE)


# --------------------------------------------------------------------------- helpers

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
    if resolved != args.model and not str(resolved).startswith(f"{args.model}-"):
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
    kernel = common.kernel_dir(common.load_jobs()[0]["run_id"])
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

TOKEN_KEYS = ("input_tokens", "cached_tokens", "output_tokens", "reasoning_tokens")


def fmt(n):
    return "?" if n is None else f"{n:,}"


def run_question(args, job, folder, lock, counter, total):
    """One bench question in a fresh container, workspace and CODEX_HOME."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "-", job["id"])
    base = WORK_DIR / safe
    shutil.rmtree(base, ignore_errors=True)
    (base / "work").mkdir(parents=True)
    (base / "codex").mkdir()
    shutil.copy(CODEX_CONFIG, base / "codex" / "config.toml")
    tdir = folder / "transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    name = f"codex-bench-{safe}"
    record = common.new_record(SYSTEM, args.build, args.run, job)
    record.update(model=args.model, reasoning_effort=args.reasoning_effort,
                  question_timeout_s=args.question_timeout)
    prompt = PREAMBLE.format(minutes=args.question_timeout // 60) + "\n\nQuestion: " + job["prompt"]
    events_file = tdir / f"{job['id']}.jsonl"
    write_auth(base / "codex", args.auth_mode)
    t0 = time.time()
    try:
        start_agent(name, job["trace"], base / "work", base / "codex")
        cmd = codex_cmd(args, None, "/codex/answer.md", args.question_timeout)
        with events_file.open("w") as out, (tdir / f"{job['id']}.stderr.log").open("w") as err:
            try:
                p = subprocess.run(["docker", "exec", "-i", "-w", "/work", name, *cmd],
                                   input=prompt, text=True, stdout=out, stderr=err,
                                   timeout=args.question_timeout + 300)
                code = p.returncode
            except subprocess.TimeoutExpired:   # backstop; `timeout` inside should win
                subprocess.run(["docker", "exec", name, "pkill", "-f", "codex"], capture_output=True)
                code = 124
        answer_file = base / "codex" / "answer.md"
        answer = answer_file.read_text() if answer_file.exists() else ""
    finally:
        stop_agent(name)
        (base / "codex" / "auth.json").unlink(missing_ok=True)
    record["elapsed_s"] = round(time.time() - t0, 2)
    ev = parse_events(events_file)
    flagged = [c for c in ev["commands"] if SUSPICIOUS.search(c)]
    extra = set(ev["item_types"]) - {"command_execution", "agent_message", "reasoning",
                                     "file_change", "todo_list", "error"}
    record.update(exit_code=code, session_id=ev["session_id"], turns=ev["turns"],
                  usage={k: ev[k] for k in TOKEN_KEYS}, n_commands=len(ev["commands"]),
                  item_types=dict(ev["item_types"]), flagged_commands=flagged,
                  errors=ev["errors"][:5], warnings=sorted(set(ev["warnings"]))[:5])
    if extra:
        record["unexpected_tools"] = sorted(extra)
    if code in (124, 137):
        # Ran out of time: saved as an answer without a verdict, so score.py counts it (noV).
        record["timed_out"] = True
        common.finish(record, answer.strip() or "(no answer: the agent ran out of its time budget)")
    elif code == 0 and answer.strip():
        common.finish(record, answer)
    else:
        common.finish(record, answer, f"codex exited with {code}: {'; '.join(ev['errors'][:2])}"[:500])
    with events_file.open("rb") as src, gzip.open(f"{events_file}.gz", "wb") as dst:
        shutil.copyfileobj(src, dst)
    events_file.unlink()
    shutil.rmtree(base, ignore_errors=True)
    with lock:
        common.save(folder, record)
        counter[0] += 1
        print(common.progress(counter[0], total, record)
              + f"  {record['n_commands']} cmds, in {fmt(ev['input_tokens'])} (cached {fmt(ev['cached_tokens'])}),"
              f" out {fmt(ev['output_tokens'])}"
              + ("  TIMEOUT" if record.get("timed_out") else "")
              + (f"  FLAGGED {len(flagged)}" if flagged else "")
              + (f"  UNEXPECTED {sorted(extra)}" if extra else ""), flush=True)
    return record["status"]


def cmd_run(args):
    jobs = common.load_jobs(question=args.question, trace=args.trace, wording=args.wording)
    folder = common.out_dir(SYSTEM, args.run, args.out)
    todo = common.pending(jobs, folder, args.retry_errors)
    saved = len(jobs) - len(todo)
    if args.limit is not None:
        todo = todo[:args.limit]
    worst_h = len(todo) * args.question_timeout / 3600 / args.jobs
    print(f"{SYSTEM} run {args.run}: {len(jobs)} answers in this selection, {saved} already saved; "
          f"asking {len(todo)}, a fresh session each, {args.jobs} at a time "
          f"(at most {worst_h:.0f} h at {args.question_timeout // 60} min per question)")
    if args.dry_run:
        for j in todo[:10]:
            print(f"  {j['id']:<26} {j['text'][:90]}")
        return
    common.require_key()
    args.auth_mode = auth_mode(args)
    resolve_effort(args)
    print(f"model {args.model}, reasoning effort {args.reasoning_effort}")
    args.build = common.fingerprint(Path(__file__), CODEX_CONFIG, COMPOSE_FILE, PREAMBLE, args.model,
                                    args.reasoning_effort, args.question_timeout,
                                    *sorted((HERE / "docker").iterdir()))
    start_proxy()
    lock, counter = threading.Lock(), [0]
    errors = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run_question, args, j, folder, lock, counter, len(todo)) for j in todo]
        for f in futures:
            try:
                if f.result() != "ok":
                    errors += 1
            except Exception as e:  # docker trouble: report, keep going
                errors += 1
                print(f"  error: {type(e).__name__}: {e}", flush=True)
    print(f"done: {counter[0]} answers, {errors} errors (rerun with --retry-errors to redo them)")


# --------------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def model_opts(sp):
        sp.add_argument("--model", default=common.MODEL,
                        help=f"default {common.MODEL}, the model TraceAssist and the other baselines use")
        sp.add_argument("--reasoning-effort", default="match",
                        choices=["match", "none", "minimal", "low", "medium", "high", "xhigh", "max"],
                        help="match (default): ask the API which effort it uses for "
                             "--baseline-alias by default and pin Codex to that")
        sp.add_argument("--baseline-alias", default=common.MODEL,
                        help="model name the other systems request (default %(default)s)")
        sp.add_argument("--auth", choices=["api-key", "chatgpt"], default="api-key",
                        help="api-key (default): OPENAI_API_KEY")

    sp = sub.add_parser("build", help="build the agent and proxy images")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("check", help="verify network isolation and that the model answers")
    model_opts(sp)
    sp.add_argument("--no-model", action="store_true", help="skip the model call")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("run", help="every bench question, a fresh session each")
    model_opts(sp)
    sp.add_argument("--run", type=int, default=1)
    sp.add_argument("--out", help="save under results/codex/<out> instead of run<N>")
    sp.add_argument("--question", nargs="*", help="only these questions, e.g. Q15 Q23")
    sp.add_argument("--trace", nargs="*", help="only these runs, e.g. batch_server-1f3b")
    sp.add_argument("--wording", choices=("a", "b"))
    sp.add_argument("--limit", type=int, help="ask at most this many new questions")
    sp.add_argument("--question-timeout", type=int, default=1800,
                    help="seconds per question (default 1800 = 30 min, as in CASCON)")
    sp.add_argument("--jobs", type=int, default=2,
                    help="questions at once, each in its own container with AGENT_CPUS CPUs and "
                         "AGENT_MEM memory (default 2)")
    sp.add_argument("--retry-errors", action="store_true", help="redo answers saved with an error")
    sp.add_argument("--dry-run", action="store_true", help="only print the plan")
    sp.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
