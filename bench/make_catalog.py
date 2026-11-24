#!/usr/bin/env python3
"""Writes symptoms.json, the catalog of the 48 symptoms in thread_finder_symptoms_backlog.md,
and checks it against scenarios.json (the faults the programs declare, `make scenarios.json`).

    python3 make_catalog.py          # writes symptoms.json, then checks it

Each symptom has:
  id         used in every program's ground_truth.json ("present", "dont_care")
  group      the backlog's section
  v1         one of the six the framework already has an analysis for
  asked      how a user might ask about it (the backlog's wordings)
  criterion  what "present" means, for the grader
  requires   LTTng event groups without which the symptom cannot be established from the trace
             (see capture.sh; "base" is always recorded). With a required group missing, the
             right answer is "the trace cannot show this".
  helps      event groups that make the evidence direct, but whose absence still leaves it
             inferable from system calls and scheduling
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

S = []


def sym(id, group, name, asked, criterion, v1=False, requires=(), helps=()):
    S.append({"id": id, "group": group, "name": name, "v1": v1, "asked": list(asked),
              "criterion": criterion, "requires": list(requires), "helps": list(helps)})


T = "timing"
sym("one_off_delay", T, "One-off delay or missed deadline",
    ["it got delayed once", "one request took 15 ms"],
    "a single iteration (or a few in one stretch) of an otherwise regular activity takes at "
    "least 5x its usual time", v1=True)
sym("jitter", T, "Jitter", ["the timing varies a lot", "it's not steady"],
    "a periodic activity's lateness or duration varies continuously, by a quarter of its period or "
    "more, throughout the run")
sym("tail_latency", T, "Many slow outliers (tail latency)",
    ["some requests are slow", "the p99 is bad"],
    "a small share (about 1-5%) of requests or iterations are many times slower than the median, "
    "spread over the whole run")
sym("gradual_slowdown", T, "Gradual slowdown", ["it gets slower over time"],
    "iterations get steadily slower from the start of the run to the end, to at least twice their "
    "initial length")
sym("sudden_change", T, "Sudden change",
    ["it was fine, then got slow around 40 s"],
    "iterations are fast up to one point in the run and at least twice as slow from then on (a "
    "step)")
sym("slow_startup", T, "Slow start-up", ["it takes long to start doing work"],
    "the program takes seconds from its start to its first unit of work")
sym("slow_shutdown", T, "Slow shutdown", ["it takes forever to exit"],
    "the program takes seconds from its last unit of work to its exit")

W = "waiting"
sym("long_blocked_waits", W, "Long blocked waits", ["it waits a long time", "it's blocked a lot"],
    "a thread that has work to do is blocked for a quarter or more of its time, or for seconds at a "
    "time (not counting idle waits for new work or its own timed sleeps)", v1=True)
sym("bottleneck_thread", W, "Slowest thread or bottleneck",
    ["why is the program slow?", "what's the bottleneck?"],
    "one thread (or one stage) holds up the whole program, which would run at least 25% faster "
    "without its delay", v1=True)
sym("hang", W, "Hang or freeze", ["it's stuck", "it stopped responding"],
    "the program stops making progress for good: its threads stay blocked until the end of the "
    "trace")
sym("deadlock", W, "Deadlock", ["two things are waiting on each other"],
    "two or more threads each hold a lock the other needs, and stay blocked for good")
sym("lock_contention", W, "Lock contention", ["threads fight over a lock"],
    "threads block on the same lock many times per second because another thread holds it")
sym("lock_holder_blocking", W, "Lock holder sleeping or doing I/O while holding it",
    ["something holds the lock too long"],
    "a lock is held across a sleep, I/O or a preemption, and other threads wait on it meanwhile")
sym("convoy", W, "Convoy or serialization",
    ["the threads run one after another instead of in parallel"],
    "threads that could run in parallel run one at a time because of a shared lock")
sym("priority_inversion", W, "Priority inversion",
    ["the high-priority task waits on a low-priority one"],
    "a high-priority thread waits on a lock held by a lower-priority thread, which is itself "
    "kept off the CPU by a medium-priority thread")
sym("waiting_on_process", W, "Waiting on another process",
    ["it's waiting on the database or the other service"],
    "threads spend a quarter or more of their time blocked waiting for replies from another "
    "process")
sym("waiting_on_network", W, "Waiting on network", ["it's slow talking to the server"],
    "a thread spends a quarter or more of its time blocked on network communication with another "
    "machine",
    helps=["net"])
sym("waiting_on_disk", W, "Waiting on disk", ["saving is slow", "fsync takes long"],
    "a thread spends a quarter or more of its time blocked on storage I/O (writes, syncs, reads)",
    helps=["block"])
sym("oversleeping", W, "Oversleeping", ["the timer fires late", "it sleeps longer than asked"],
    "most sleeps end 1 ms or more later than requested while the CPU is free (late timer expiry, "
    "not CPU contention)")

C = "cpu"
sym("cpu_hog", C, "CPU hog or busiest thread",
    ["what's using all the CPU?", "which thread is busiest?"],
    "one thread keeps a CPU close to 100% busy for most of the run", v1=True)
sym("scheduling_delay", C, "Slow to get scheduled",
    ["it's ready but has to wait for the CPU", "scheduling delay"],
    "a runnable thread is kept waiting to run for 1 ms or more at least 50 times in the trace, or "
    "for 10 ms or more at least once", v1=True)
sym("busy_wait", C, "Busy-waiting or spinning", ["high CPU but nothing gets done"],
    "a thread uses a full CPU while waiting for something, making no progress")
sym("cpu_starvation", C, "CPU starvation", ["it's ready but never gets to run"],
    "a runnable thread gets (almost) no CPU time for a long stretch (seconds)")
sym("noisy_neighbour", C, "Noisy neighbour", ["another program is slowing mine down"],
    "another process competes for the program's CPUs and slows its work down by 25% or more")
sym("load_imbalance", C, "Load imbalance", ["one worker does all the work", "uneven load"],
    "work is unevenly divided: some threads of a group get at least twice as much of it as others")
sym("barrier_straggler", C, "Straggler at a barrier", ["everyone waits for one slow thread"],
    "threads that meet at a barrier keep waiting for the same late thread")
sym("oversubscription", C, "Oversubscription", ["too many threads for the cores"],
    "at least twice as many runnable threads as CPUs, so threads queue for the CPU")
sym("excessive_migrations", C, "Excessive migrations", ["it keeps jumping between CPUs"],
    "threads move between CPUs very often (hundreds of times per second)")
sym("interrupt_storm", C, "Interrupt storm", ["interrupts are eating the CPU"],
    "interrupt handling (hardware interrupt handlers) takes a large share of one CPU, 10% or "
    "more for seconds at a time, where a CPU normally spends about 1% in them")
sym("rt_preempted", C, "Real-time thread preempted", ["my real-time thread gets interrupted"],
    "a real-time (SCHED_FIFO/RR) thread is repeatedly preempted by a higher-priority one")

IO = "syscalls_io"
sym("slow_syscalls", IO, "Slow system calls or I/O",
    ["which calls are slow?", "file access is slow"],
    "a thread spends 10% or more of its time waiting inside system calls (not counting sleeps or "
    "waits for events), some of which take milliseconds", v1=True)
sym("many_small_calls", IO, "Too many small calls", ["it makes thousands of tiny reads"],
    "the program makes tens of thousands of tiny system calls per second where a few large ones "
    "would do")
sym("idle_polling", IO, "Polling with no work", ["it keeps checking for nothing"],
    "a thread repeatedly checks for work or data (poll, select, read with no wait) that is "
    "never there")
sym("failing_retry_loop", IO, "Failing calls in a retry loop",
    ["it keeps retrying", "lots of errors"],
    "the same system call fails over and over (an error return each time)")
sym("file_churn", IO, "File churn", ["it opens and closes files constantly"],
    "files are created, opened, closed or deleted at a high rate (hundreds per second)")
sym("memory_pressure", IO, "Memory pressure or page faults",
    ["it's swapping", "memory is slow"],
    "the program spends a quarter or more of its time in page faults or memory reclaim",
    requires=["mem"])
sym("allocation_churn", IO, "Allocation churn", ["it keeps allocating and freeing memory"],
    "memory is mapped and unmapped (mmap/munmap, brk) hundreds of times per second or more")

L = "lifecycle"
sym("crash", L, "Crash or abnormal exit", ["it crashed", "it died", "it got killed"],
    "a process of the program dies from a signal (segfault, abort, kill) rather than exiting",
    requires=["signal"])
sym("fork_exec_storm", L, "Fork or exec storm", ["it spawns tons of short processes"],
    "the program starts short-lived processes at a high rate (tens per second or more)")
sym("thread_churn", L, "Thread churn", ["it keeps creating threads"],
    "the program creates and ends threads at a high rate (tens per second or more)")
sym("never_exits", L, "Never exits", ["it doesn't quit"],
    "the program has finished its work but its process stays alive until the end of the trace")

P = "pipelines"
sym("slowest_stage", P, "Slowest pipeline stage", ["which stage is the bottleneck?"],
    "one stage of a pipeline is too slow for its input, and the stages around it wait for it")
sym("producer_consumer_mismatch", P, "Producer and consumer out of step",
    ["the queue keeps filling or emptying"],
    "a queue between two threads keeps swinging between full and empty")
sym("thundering_herd", P, "Thundering herd",
    ["many threads wake up but only one does anything"],
    "each event wakes many waiting threads, and all but one go straight back to sleep")
sym("idle_workers", P, "Idle workers", ["the workers are idle while one works"],
    "most workers of a pool stay idle while one or a few do all the work")

U = "unexpected"
sym("unexpected_activity", U, "Unexpected activity",
    ["what is this process doing?", "why is it touching that file?"],
    "the program does something unrelated to its job (here: reads files that have nothing to do "
    "with it)")
sym("idle_thread", U, "Idle thread", ["this thread does nothing"],
    "a thread exists for the whole run but never does any work")
sym("thread_differences", U, "Thread differences",
    ["why does worker-2 behave differently from the others?"],
    "one thread of a group of similar threads behaves differently in a way the rest do not share "
    "(e.g. at least twice their CPU time, blocking, or system calls of a kind they make none of)")


# The kind of question asked about each symptom, with the CASCON paper's categories and TAAF's
# hub scope. Comprehension: what the program does. Root cause: why it is slow or wrong.
# Dependency: how threads or processes wait on and wake each other. Quantitative: a measured
# value. Remediation: what change would fix it ("is there X, and if so what would fix it?").
# Single-hub: one central thread or process and its direct relationships answer it;
# multi-hub: the answer combines or compares evidence across several.
C, RC, D, Q, R = "comprehension", "root_cause", "dependency", "quantitative", "remediation"
QUESTION_TYPE = {
    "one_off_delay": (Q, "single"), "jitter": (Q, "single"), "tail_latency": (Q, "multi"),
    "gradual_slowdown": (Q, "single"), "sudden_change": (Q, "single"),
    "slow_startup": (C, "single"), "slow_shutdown": (RC, "multi"),
    "long_blocked_waits": (D, "single"), "bottleneck_thread": (RC, "multi"),
    "hang": (RC, "multi"), "deadlock": (D, "multi"), "lock_contention": (D, "multi"),
    "lock_holder_blocking": (R, "multi"), "convoy": (D, "multi"),
    "priority_inversion": (D, "multi"), "waiting_on_process": (D, "multi"),
    "waiting_on_network": (D, "single"), "waiting_on_disk": (D, "single"),
    "oversleeping": (RC, "single"),
    "cpu_hog": (Q, "multi"), "scheduling_delay": (Q, "single"), "busy_wait": (C, "single"),
    "cpu_starvation": (RC, "multi"), "noisy_neighbour": (RC, "multi"),
    "load_imbalance": (Q, "multi"), "barrier_straggler": (RC, "multi"),
    "oversubscription": (R, "multi"), "excessive_migrations": (R, "single"),
    "interrupt_storm": (RC, "multi"), "rt_preempted": (RC, "multi"),
    "slow_syscalls": (Q, "single"), "many_small_calls": (R, "single"),
    "idle_polling": (R, "single"), "failing_retry_loop": (C, "single"),
    "file_churn": (C, "single"), "memory_pressure": (RC, "single"),
    "allocation_churn": (R, "single"),
    "crash": (C, "single"), "fork_exec_storm": (C, "multi"), "thread_churn": (C, "multi"),
    "never_exits": (C, "single"),
    "slowest_stage": (RC, "multi"), "producer_consumer_mismatch": (D, "multi"),
    "thundering_herd": (R, "multi"), "idle_workers": (C, "multi"),
    "unexpected_activity": (C, "single"), "idle_thread": (C, "single"),
    "thread_differences": (Q, "multi"),
}
for s in S:
    s["category"], s["hub"] = QUESTION_TYPE[s["id"]]
assert set(QUESTION_TYPE) == {s["id"] for s in S}


EVENT_GROUPS = {
    "base": "sched_*, timer/IRQ, x86 IRQ vectors, all syscalls, statedump (always recorded)",
    "net": "net_*, netif_* (packets sent and received)",
    "block": "block_* (disk requests issued and completed)",
    "signal": "signal_generate, signal_deliver",
    "mem": "kmem_* and page-fault events (no probe for them on this machine's kernel)",
}


def main() -> int:
    catalog = {
        "about": "The 48 symptoms of thread_finder_symptoms_backlog.md. Generated by "
                 "make_catalog.py; edit that file, not this one.",
        "event_groups": EVENT_GROUPS,
        "symptoms": S,
    }
    (HERE / "symptoms.json").write_text(json.dumps(catalog, indent=2) + "\n")
    ids = [s["id"] for s in S]
    assert len(ids) == len(set(ids)) == 48, (len(ids), len(set(ids)))
    print(f"wrote symptoms.json: {len(ids)} symptoms")

    scenarios_path = HERE / "scenarios.json"
    if not scenarios_path.exists():
        print("scenarios.json missing: run `make scenarios.json` to check the programs")
        return 0
    problems = 0
    positives = {i: [] for i in ids}
    for prog in json.loads(scenarios_path.read_text()):
        for fault in prog["faults"]:
            for key in ("present", "dont_care"):
                for i in fault[key]:
                    if i not in positives:
                        print(f"  {prog['program']} --fault {fault['name']}: unknown id {i!r}")
                        problems += 1
            both = set(fault["present"]) & set(fault["dont_care"])
            if both:
                print(f"  {prog['program']} --fault {fault['name']}: in both lists: {both}")
                problems += 1
            for i in fault["present"]:
                if i in positives:
                    positives[i].append(f"{prog['program']}:{fault['name']}")
    missing = [i for i, p in positives.items() if not p]
    for i in missing:
        print(f"  no fault makes {i} present")
    print(f"{48 - len(missing)}/48 symptoms have a positive scenario; "
          f"{problems} problem(s) in scenarios.json")
    return 1 if problems or missing else 0


if __name__ == "__main__":
    sys.exit(main())
