#!/usr/bin/env python3
"""Checks every recording in runs/ against its answer key, with babeltrace2.

    python3 check_runs.py            # all runs; writes runs/check.json and prints a table

For each run it reports:
  - discarded events (the tracer's buffers overflowed: the trace has gaps);
  - whether every thread in the answer key appears in the trace (scheduled in at least once);
  - counts of the events the faults depend on: futex calls, block requests, packets sent,
    signals delivered, migrations, execs, and the program's own syscalls.
"""

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVENT = re.compile(r"\] \(\+[^)]*\) \S+ (\w+): ")
NEXT_TID = re.compile(r"next_tid = (\d+)")
TID_CTX = re.compile(r"\btid = (\d+)")
WATCH = ["sched_switch", "sched_migrate_task", "sched_process_exec", "sched_process_fork",
         "syscall_entry_futex", "syscall_entry_fdatasync", "syscall_entry_read",
         "syscall_entry_openat", "syscall_entry_poll", "syscall_entry_connect",
         "syscall_entry_mmap", "syscall_entry_munmap", "syscall_entry_madvise",
         "block_rq_issue", "net_dev_xmit", "signal_deliver", "signal_generate"]


def check(run: Path) -> dict:
    gt = json.loads((run / "ground_truth" / "ground_truth.json").read_text())
    cap = json.loads((run / "capture.json").read_text())
    tids = {t["tid"]: t["name"] for t in gt["threads"]}
    seen = Counter()
    counts = Counter()
    proc = subprocess.Popen(["babeltrace2", str(run / "trace")], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, errors="replace")
    total = 0
    for line in proc.stdout:
        total += 1
        m = EVENT.search(line)
        if not m:
            continue
        name = m.group(1)
        if name in WATCH:
            counts[name] += 1
        if name == "sched_switch":
            t = NEXT_TID.search(line)
            if t and int(t.group(1)) in tids:
                seen[int(t.group(1))] += 1
    err = proc.stderr.read()
    proc.wait()
    discarded = sum(int(n) for n in re.findall(r"discarded (\d+) event", err))
    missing = [f"{name}:{tid}" for tid, name in tids.items() if seen[tid] == 0]
    return {
        "run": run.name, "program": cap["program"], "fault": cap["fault"],
        "left_out": cap["events_left_out"], "events": total, "discarded": discarded,
        "threads": len(tids), "threads_never_scheduled": missing,
        "counts": dict(counts), "babeltrace_errors": err.strip()[-300:] if proc.returncode else "",
    }


def main() -> int:
    runs = sorted(p for p in (HERE / "runs").iterdir() if (p / "capture.json").exists())
    results = []
    for run in runs:
        r = check(run)
        results.append(r)
        c = r["counts"]
        print(f"{r['run']:<18} {r['program']:<13} {r['fault']:<19} "
              f"{'-' + ','.join(r['left_out']) if r['left_out'] else '':<8} "
              f"events {r['events']:>9,}  discarded {r['discarded']:>6,}  "
              f"unseen {len(r['threads_never_scheduled'])}/{r['threads']}  "
              f"futex {c.get('syscall_entry_futex', 0):>7,} blk {c.get('block_rq_issue', 0):>5,} "
              f"net {c.get('net_dev_xmit', 0):>4,} sig {c.get('signal_deliver', 0):>4,} "
              f"mig {c.get('sched_migrate_task', 0):>6,} exec {c.get('sched_process_exec', 0):>5,}",
              flush=True)
    (HERE / "runs" / "check.json").write_text(json.dumps(results, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
