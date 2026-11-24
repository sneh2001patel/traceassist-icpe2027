#!/usr/bin/env python3
"""Writes questions.json and questions.md: the bench's questions, one per symptom and program
that can show it, each in two wordings.

    python3 make_questions.py        # needs symptoms.json and scenarios.json; checks runs/ too

Each question names the program and has a yes-or-no answer about its symptom, so it can be
graded as a TP, FP, TN or FN on any trace of that program (make_pairs.py picks up to 5):

  a  precise:  the symptom's criterion from symptoms.json, in a question;
  b  everyday: the same question as a user would ask it (the backlog's wordings).

Neither wording presupposes the symptom. Remediation questions ask "is there X? If so, what
would fix it?", so on a trace without X the right answer is that there is nothing to fix.

Questions name only the program and threads that exist in every trace of that program, so a
name never gives the fault away (checked below against runs/*/ground_truth).
"""

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

# For the grader, true of every program: the watchdog thread belongs to the test harness and
# sleeps until the run ends. A verdict that rests only on the watchdog (an idle thread, a long
# blocked wait) counts as "absent".
GRADER_NOTES = [
    "Every program has a 'watchdog' thread that sleeps until the run ends; it is part of the "
    "test harness. A verdict that rests only on the watchdog counts as absent.",
]

# (symptom, program, precise wording, everyday wording)
Q = [
    # ---- timing
    ("one_off_delay", "ticker",
     "Does any cycle of ticker's sampler thread take far longer than usual (at least 5 times "
     "its normal length)? If so, when did it happen, and how late was it?",
     "Did ticker's sampler hiccup once, with one cycle much later than all the others? When, "
     "and by how much?"),
    ("jitter", "ticker",
     "Does the wake-up lateness or cycle length of ticker's sampler thread vary by 0.5 ms or "
     "more (a quarter of its 2 ms period), throughout the run? If so, by how much?",
     "Is ticker's sampler running steadily, or does its timing jump around a lot? By how much?"),
    ("tail_latency", "kvstore",
     "In kvstore, are a small share of the clients' requests (around 1-5%) many times slower "
     "than the typical request? If so, how slow are they compared with the median?",
     "Are some of kvstore's requests a lot slower than the rest, is the p99 bad? By how much?"),
    ("gradual_slowdown", "ticker",
     "Do the cycles of ticker's sampler thread get steadily slower from the start of the trace"
     " to the end, to at least twice their initial length? If so, by how much?",
     "Does ticker get slower over time? How much slower is it by the end?"),
    ("sudden_change", "ticker",
     "Do the cycles of ticker's sampler thread change at one point in the trace from fast to "
     "at least twice as slow, and stay slow? If so, when, and by how much?",
     "Was ticker fine at first and then suddenly got slow? When did it change?"),
    ("slow_startup", "jobrunner",
     "Does jobrunner take seconds from its start to its first job? If so, how long, and what "
     "does it do in that time?",
     "Does jobrunner take long to start doing work? What is it doing before then?"),
    ("slow_shutdown", "jobrunner",
     "Does jobrunner take seconds from its last job to its exit? If so, how long, and what "
     "holds up its shutdown?",
     "Does jobrunner take forever to exit? Why?"),

    # ---- waiting
    ("long_blocked_waits", "batch_server",
     "Is any thread of batch_server blocked for a quarter or more of its time, or for seconds "
     "at a time, while it has work to do (not counting idle waits for new work or its own "
     "timed sleeps)? If so, which thread, and what is it waiting on?",
     "Is some thread in batch_server blocked a lot? Which one, and what is it waiting for?"),
    ("long_blocked_waits", "kvstore",
     "Is any thread of kvstore blocked for a quarter or more of its time, or for seconds at a "
     "time, while it has work to do (not counting idle waits for new work or its own timed "
     "sleeps)? If so, which thread, and what is it waiting on?",
     "Is anything in kvstore stuck waiting a long time? Which thread, and on what?"),
    ("bottleneck_thread", "batch_server",
     "Does one thread of batch_server hold up the whole program, so that the program would run"
     " at least 25% faster without that thread's delay? If so, which thread, and why is it "
     "slow?",
     "Is there a bottleneck in batch_server? If so, which thread is it, and why?"),
    ("bottleneck_thread", "crunch",
     "Does one thread of crunch hold up the whole program, so that the program would run at "
     "least 25% faster without that thread's delay? If so, which thread, and why is it slow?",
     "Is there a bottleneck in crunch? If so, which thread is it, and why?"),
    ("bottleneck_thread", "pipeline",
     "Does one thread of pipeline hold up the whole program, so that the program would run at "
     "least 25% faster without that thread's delay? If so, which thread, and why is it slow?",
     "Is there a bottleneck in pipeline? If so, which thread is it, and why?"),
    ("bottleneck_thread", "kvstore",
     "Does one thread or process of kvstore hold up the whole program, so that the program "
     "would run at least 25% faster without its delay? If so, which one, and why is it slow?",
     "Is there a bottleneck in kvstore? If so, which thread or process is it, and why?"),
    ("hang", "batch_server",
     "Does batch_server stop making progress at some point, with its threads staying blocked "
     "until the end of the trace? If so, when, and why?",
     "Did batch_server get stuck or stop responding? When, and why?"),
    ("deadlock", "batch_server",
     "Do two or more threads of batch_server each hold a lock that another of them needs, so "
     "that they stay blocked for good? If so, which threads?",
     "Are any threads in batch_server waiting on each other forever? Which ones?"),
    ("lock_contention", "batch_server",
     "Do batch_server's threads block on the same lock many times per second because another "
     "thread holds it? If so, which threads, and how much time do they lose?",
     "Are batch_server's threads fighting over a lock? Which ones, and how much does it cost "
     "them?"),
    ("lock_holder_blocking", "batch_server",
     "Does any thread of batch_server hold a lock while it sleeps, does I/O or is preempted, "
     "so that other threads wait for it? If so, which thread, and what change would fix it?",
     "Is something in batch_server holding a lock too long? If so, how would I fix it?"),
    ("convoy", "batch_server",
     "Do batch_server's worker threads run one at a time because they take turns on a shared "
     "lock, instead of running in parallel? If so, which lock holder do they wait on?",
     "Are batch_server's workers running one after another instead of in parallel? Why?"),
    ("priority_inversion", "batch_server",
     "Does a high-priority thread of batch_server wait on a lock held by a lower-priority "
     "thread, which is itself kept off the CPU by a medium-priority thread? If so, which "
     "threads are involved?",
     "Is a high-priority thread in batch_server stuck waiting on a low-priority one? Which "
     "threads?"),
    ("waiting_on_process", "kvstore",
     "Do kvstore's client threads spend a quarter or more of their time blocked waiting for "
     "replies from another process? If so, which process, and how long do they wait?",
     "Are kvstore's clients waiting a lot on the kvd server? How long are the waits?"),
    ("waiting_on_network", "kvstore",
     "Does any thread of kvstore spend a quarter or more of its time blocked on network "
     "communication with another machine? If so, which thread, and how long are its waits?",
     "Is kvstore slow talking to a remote server? Which thread is waiting, and for how long?"),
    ("waiting_on_disk", "filestore",
     "Does any thread of filestore spend a quarter or more of its time blocked on storage I/O "
     "(writes, syncs or reads)? If so, which thread, and what share of its time?",
     "Is saving slow in filestore, is it waiting on the disk? Which thread, and how much?"),
    ("oversleeping", "ticker",
     "Do most of the sleeps of ticker's sampler thread end 1 ms or more later than requested, "
     "while its CPU is free? If so, by how much, and why?",
     "Does ticker's timer fire late, so the sampler sleeps longer than it asked? Why?"),

    # ---- CPU
    ("cpu_hog", "crunch",
     "Does any thread of crunch keep a CPU close to 100% busy for most of the run? If so, "
     "which thread, and how much CPU does it use?",
     "Is any thread in crunch hogging a CPU? Which one, and how much does it use?"),
    ("scheduling_delay", "ticker",
     "Is ticker's sampler thread kept waiting to run after it becomes runnable, for 1 ms or "
     "more at least 50 times in the trace, or for 10 ms or more at least once? If so, how "
     "long, and how often?",
     "Is ticker's sampler ready to run but stuck waiting for the CPU? For how long?"),
    ("scheduling_delay", "crunch",
     "Are crunch's calc threads kept waiting to run after they become runnable, for 1 ms or "
     "more at least 50 times in the trace (all calc threads together), or for 10 ms or more at"
     " least once? If so, which threads, and how long?",
     "Are crunch's threads ready to run but stuck waiting for a CPU? Which ones, and for how "
     "long?"),
    ("scheduling_delay", "reporter",
     "Is reporter's render thread kept waiting to run after it becomes runnable, for 1 ms or "
     "more at least 50 times in the trace, or for 10 ms or more at least once? If so, how "
     "long, and how often?",
     "Is reporter's render thread ready to run but stuck waiting for the CPU? For how long?"),
    ("busy_wait", "crunch",
     "Does any thread of crunch use a full CPU while waiting for something, without making "
     "progress? If so, which thread, and what is it waiting for?",
     "Is a thread in crunch burning CPU without getting anything done? Which one?"),
    ("cpu_starvation", "crunch",
     "Does any thread of crunch stay runnable but get almost no CPU time for a long stretch "
     "(seconds)? If so, which thread, and what keeps it off the CPU?",
     "Is a thread in crunch ready to run but never getting to? Which one, and why?"),
    ("noisy_neighbour", "reporter",
     "Does another process compete with reporter for its CPU and slow its work down by 25% or "
     "more? If so, which process, and how much does reporter lose?",
     "Is another program slowing reporter down? Which one, and by how much?"),
    ("load_imbalance", "crunch",
     "Is crunch's work divided unevenly, with some calc threads getting at least twice as much"
     " of it as others? If so, which threads, and how uneven is it?",
     "Is the load in crunch uneven, with one worker doing most of the work? How uneven?"),
    ("load_imbalance", "pipeline",
     "Is pipeline's work divided unevenly among its sink threads, with some getting at least "
     "twice as much of it as others? If so, which sinks, and how uneven is it?",
     "Is one of pipeline's sinks doing most of the work? How uneven is the load?"),
    ("barrier_straggler", "crunch",
     "Do crunch's calc threads keep waiting at their barrier for the same late thread? If so, "
     "which thread, and why is it late?",
     "Is everyone in crunch waiting for one slow thread? Which one, and why?"),
    ("oversubscription", "crunch",
     "Does crunch have at least twice as many runnable threads as CPUs, so that its threads "
     "queue for the CPU? If so, how many threads on how many CPUs, and what change would fix "
     "it?",
     "Does crunch have too many threads for the cores? If so, what should I change?"),
    ("excessive_migrations", "crunch",
     "Do crunch's threads move between CPUs very often (hundreds of times per second)? If so, "
     "which threads, how often, and what change would stop it?",
     "Do crunch's threads keep jumping between CPUs? How would I stop that?"),
    ("interrupt_storm", "reporter",
     "Does interrupt handling take a large share (10% or more) of the CPU that reporter's render "
     "thread runs on? If so, which interrupts, how much of that CPU do they take, and when?",
     "Are interrupts eating the CPU that reporter runs on? Which ones, and how much?"),
    ("rt_preempted", "ticker",
     "Is ticker's sampler thread repeatedly preempted by a higher-priority real-time thread? "
     "If so, by which thread, and how often?",
     "Does ticker's sampler keep getting interrupted by something more important? By what?"),

    # ---- system calls and I/O
    ("slow_syscalls", "filestore",
     "Does any thread of filestore spend 10% or more of its time waiting inside system calls "
     "(not counting sleeps or waits for events)? If so, which calls, and how long do they "
     "take?",
     "Is file access slow in filestore? Which calls are slow, and how slow?"),
    ("many_small_calls", "filestore",
     "Does filestore make tens of thousands of tiny system calls per second where a few larger "
     "ones would do? If so, which calls, and what change would fix it?",
     "Is filestore making thousands of tiny reads or writes? How should it be changed?"),
    ("idle_polling", "filestore",
     "Does any thread of filestore repeatedly check for work or data that is never there? If "
     "so, which thread and which call, and what change would fix it?",
     "Is something in filestore constantly checking for nothing? How would I fix it?"),
    ("failing_retry_loop", "filestore",
     "Does any thread of filestore make the same system call over and over, with it failing "
     "each time? If so, which call, and what error does it return?",
     "Is filestore retrying something that keeps failing? What is it?"),
    ("file_churn", "filestore",
     "Does filestore create, open, close or delete files at a high rate (hundreds per second)? "
     "If so, which thread, and which files?",
     "Is filestore opening and closing files all the time? Which thread, and which files?"),
    ("memory_pressure", "cachesvc",
     "Does cachesvc spend a quarter or more of its time in page faults or memory reclaim? If "
     "so, which thread, and how much of its time?",
     "Is cachesvc slow because of memory, is it swapping or page-faulting? Which thread?"),
    ("allocation_churn", "cachesvc",
     "Does cachesvc map and unmap memory (mmap and munmap, or brk) hundreds of times per "
     "second or more? If so, which thread, how often, and what change would fix it?",
     "Is cachesvc constantly allocating and freeing memory? How would I fix that?"),

    # ---- lifecycle
    ("crash", "jobrunner",
     "Does any process of jobrunner die from a signal (such as a segfault or an abort) instead "
     "of exiting normally? If so, which process, and which signal?",
     "Did anything in jobrunner crash or get killed? What was it?"),
    ("fork_exec_storm", "jobrunner",
     "Does jobrunner start short-lived processes at a high rate (tens per second or more)? If "
     "so, how many, and what do they run?",
     "Is jobrunner spawning tons of short processes? What are they?"),
    ("thread_churn", "jobrunner",
     "Does jobrunner create and end threads at a high rate (tens per second or more)? If so, "
     "how many, and which thread creates them?",
     "Does jobrunner keep creating new threads? How many?"),
    ("never_exits", "jobrunner",
     "Does jobrunner finish its work but keep its process alive until the end of the trace? If "
     "so, which threads are still alive, and what are they doing?",
     "Did jobrunner fail to quit after it was done? What is it still doing?"),

    # ---- pipelines
    ("slowest_stage", "pipeline",
     "Is one stage of pipeline (the reader, the parser or the sinks) too slow for its input, "
     "so that the stages around it wait for it? If so, which stage, and why?",
     "Is there a stage in pipeline that holds the others up? Which one, and why?"),
    ("producer_consumer_mismatch", "pipeline",
     "Does a queue between two of pipeline's threads keep swinging between full and empty? If "
     "so, between which threads?",
     "Do pipeline's queues keep filling up and then draining? Between which stages?"),
    ("thundering_herd", "pipeline",
     "In pipeline, does each new item wake many waiting threads, with all but one going "
     "straight back to sleep? If so, which threads, and what change would fix it?",
     "Do lots of pipeline's threads wake up when only one has anything to do? How would I fix "
     "it?"),
    ("idle_workers", "pipeline",
     "Do most of pipeline's sink threads stay idle while one or a few do all the work? If so, "
     "which sinks are idle?",
     "Are pipeline's sinks sitting idle while one of them does the work? Which ones?"),

    # ---- unexpected
    ("unexpected_activity", "filestore",
     "Does filestore do anything unrelated to storing and reading its own records, such as "
     "reading files that have nothing to do with it? If so, which thread, and what does it "
     "access?",
     "Is filestore touching files it shouldn't? What is it doing?"),
    ("idle_thread", "pipeline",
     "Apart from its watchdog thread, does pipeline have a thread that exists for the whole run "
     "but never does any work? If so, which thread?",
     "Apart from the watchdog, is there a thread in pipeline that just sits there doing "
     "nothing? Which one?"),
    ("thread_differences", "batch_server",
     "Does one of batch_server's worker threads behave differently from the other workers in a"
     " way they do not share (for example at least twice their CPU time or blocking, or system"
     " calls they make none of)? If so, which one, and how does it differ?",
     "Do batch_server's workers all behave the same, or is one of them different? How?"),
    ("thread_differences", "crunch",
     "Does one of crunch's calc threads behave differently from the other calc threads in a "
     "way they do not share (for example at least twice their CPU time or blocking, or system "
     "calls they make none of)? If so, which one, and how does it differ?",
     "Do crunch's calc threads all behave the same, or is one of them different? How?"),
]


def main() -> int:
    symptoms = {s["id"]: s for s in json.loads((HERE / "symptoms.json").read_text())["symptoms"]}
    scenarios = json.loads((HERE / "scenarios.json").read_text())
    problems = []

    # Exactly one question per (symptom, program) that has a positive scenario.
    expected = {(s, p["program"]) for p in scenarios for f in p["faults"] for s in f["present"]}
    have = [(s, p) for s, p, _, _ in Q]
    if len(have) != len(set(have)):
        problems.append("a (symptom, program) is listed twice")
    for missing in sorted(expected - set(have)):
        problems.append(f"no question for {missing}")
    for extra in sorted(set(have) - expected):
        problems.append(f"question for {extra}, which no scenario makes present")

    # Thread names that exist in only some of a program's traces would hint at the fault.
    partial = defaultdict(set)
    index = HERE / "runs" / "index.csv"
    if index.exists():
        seen = defaultdict(lambda: defaultdict(set))
        faults = defaultdict(set)
        for r in csv.DictReader(index.open()):
            faults[r["program"]].add(r["fault"])
            gt = HERE / "runs" / r["run_id"] / "ground_truth" / "ground_truth.json"
            for t in json.loads(gt.read_text())["threads"]:
                seen[r["program"]][t["name"]].add(r["fault"])
        for prog, names in seen.items():
            partial[prog] = {n for n, fs in names.items() if fs != faults[prog]}
    else:
        print("runs/index.csv missing: thread names not checked")

    questions = []
    # Numbered Q1..Q55 in reading order: by category, then hub scope, then symptom.
    order = list(symptoms)
    cats = list(CATEGORY_TITLES)

    def reading_order(q):
        s = symptoms[q[0]]
        return cats.index(s["category"]), s["hub"] == "multi", order.index(q[0])

    for n, (sid, prog, precise, everyday) in enumerate(sorted(Q, key=reading_order), start=1):
        s = symptoms[sid]
        for suffix, wording, text in (("a", "precise", precise), ("b", "everyday", everyday)):
            if prog not in text:
                problems.append(f"Q{n}{suffix} does not name {prog}")
            for name in partial[prog]:
                if re.search(rf"\b{re.escape(name)}\b", text):
                    problems.append(f"Q{n}{suffix} names {name!r}, which only some "
                                    f"{prog} traces have")
            questions.append({
                "id": f"Q{n}{suffix}", "question": f"Q{n}", "symptom": sid,
                "symptom_name": s["name"], "program": prog, "category": s["category"],
                "hub": s["hub"], "group": s["group"], "v1": s["v1"], "wording": wording,
                "text": text,
            })

    out = {
        "about": "The bench's questions: one per symptom and program, in a precise (a) and an "
                 "everyday (b) wording. Generated by make_questions.py; edit that file.",
        "grader_notes": GRADER_NOTES,
        "questions": questions,
    }
    (HERE / "questions.json").write_text(json.dumps(out, indent=2) + "\n")
    write_markdown(questions)

    for p in problems:
        print("  " + p)
    n = len(questions) // 2
    print(f"wrote questions.json and questions.md: {n} questions, {len(questions)} with both "
          f"wordings; {len(problems)} problem(s)")
    return 1 if problems else 0


CATEGORY_TITLES = {"comprehension": "Comprehension", "root_cause": "Root cause",
                   "dependency": "Dependency", "quantitative": "Quantitative",
                   "remediation": "Remediation"}


def write_markdown(questions: list) -> None:
    lines = [
        "# Symptom bench questions",
        "",
        "Generated by `make_questions.py` from its question list; edit that file, not this one.",
        "",
        "Each question names the program and is asked of up to 5 traces of that program",
        "(`pairs.json`, from `make_pairs.py`), so it is graded as a TP, FP, TN or FN against",
        "each trace's answer key. **a** is the precise",
        "wording, **b** the everyday one. The category and hub scope come from `symptoms.json`.",
        "",
        "Grader notes:",
        "",
    ] + [f"- {n}" for n in GRADER_NOTES] + [""]
    by_q = defaultdict(dict)
    for q in questions:
        by_q[q["question"]][q["wording"]] = q
    for cat, title in CATEGORY_TITLES.items():
        for hub in ("single", "multi"):
            rows = [v for v in by_q.values() if v["precise"]["category"] == cat
                    and v["precise"]["hub"] == hub]
            if not rows:
                continue
            lines += [f"## {title}, {hub}-hub ({len(rows)})", "",
                      "| # | Symptom | Program | a. Precise | b. Everyday |",
                      "|---|---|---|---|---|"]
            for v in rows:
                a, b = v["precise"], v["everyday"]
                star = " ★" if a["v1"] else ""
                lines.append(f"| {a['question']} | {a['symptom_name']}{star} | `{a['program']}` "
                             f"| {a['text']} | {b['text']} |")
            lines.append("")
    lines += ["★ one of the six symptoms TraceAssist's thread search supports.", ""]
    (HERE / "questions.md").write_text("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
