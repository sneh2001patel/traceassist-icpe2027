#!/usr/bin/env python3
"""Writes answer_key.json: for every question-trace pair, what a correct answer says.

    python3 make_answer_key.py       # needs pairs.json, questions.json and runs/*/ground_truth

The present / absent / cannot-see truth comes from pairs.json (from each run's answer key).
For the pairs where the symptom is present, the grader also checks the rest of the answer
against an entry here, keyed by (program, fault, symptom):

  where_any   the answer must name at least one of these threads or processes (the location);
  where_all   ... and all of these (e.g. both threads of a deadlock);
  cause       what the answer should say is going on (for the judge; wording is free);
  numbers     the quantities the question asks for, with a tolerance. "{name}" is filled in
              from that run's own measurements (ground_truth.json "metrics"), so two runs of
              the same fault each get their own numbers;
  fix_any     remediation questions: any one of these counts as a right fix.

Every entry comes from the fault's code and its recorded measurements, not from any system's
answer. The script checks that every present pair has an entry and every entry is used.

Like pairs.json, never give this file to the systems under test.
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from make_pairs import UNSEEABLE  # noqa: E402

K = {}


def key(program, fault, symptom, where_any=(), cause="", numbers=(), where_all=(), fix_any=()):
    assert (program, fault, symptom) not in K, (program, fault, symptom)
    K[(program, fault, symptom)] = {
        "where_any": list(where_any), "where_all": list(where_all), "cause": cause,
        "numbers": list(numbers), "fix_any": list(fix_any)}


# ---------------------------------------------------------------- batch_server
# Healthy: a round takes ~20.5 ms (4 workers x 5 ms, coordinator waits for all).
HS = "the flusher holds cache_lock across a 40 ms sleep every round"
key("batch_server", "holder_sleeps", "bottleneck_thread", ["worker-2", "flusher"],
    f"worker-2 sets the pace: every round waits for it, and it is blocked on cache_lock because "
    f"{HS} (chain: batch_server <- worker-2 <- flusher <- timer)",
    ["rounds take ~{round_ms_mean:.0f} ms against ~20.5 ms healthy (±25%)"])
key("batch_server", "holder_sleeps", "long_blocked_waits", ["worker-2"],
    f"worker-2 blocks on cache_lock (a futex) every round, because {HS}",
    ["worker-2 waits ~22 ms per round (±30%)"])
key("batch_server", "holder_sleeps", "thread_differences", ["worker-2"],
    f"worker-2, unlike the other workers, blocks ~22 ms per round on cache_lock, because {HS}",
    ["~22 ms of blocking per round, where the other workers have none (±30%)"])
key("batch_server", "holder_sleeps", "lock_holder_blocking", ["flusher"],
    f"{HS}; worker-2 waits for it", ["the lock is held ~40 ms per round (±25%)"],
    fix_any=["release cache_lock before sleeping (do the wait outside the critical section)",
             "shorten the critical section to the write-back itself",
             "do not sleep, block or do I/O while holding the lock",
             "use a separate lock or a copy of the data, so worker-2 does not need the flusher's lock"])
PI = ("worker-2 (SCHED_FIFO 10) needs cache_lock, held by the flusher (SCHED_FIFO 1), which is "
      "preempted by the compactor (SCHED_FIFO 5) burning 15 ms on the same CPU")
key("batch_server", "priority_inversion", "bottleneck_thread", ["worker-2", "flusher", "compactor"],
    f"worker-2 sets the pace of each round: {PI}",
    ["rounds take ~{round_ms_mean:.0f} ms against ~20.5 ms healthy (±25%)"])
key("batch_server", "priority_inversion", "long_blocked_waits", ["worker-2"],
    f"worker-2 blocks on cache_lock every round: {PI}",
    ["worker-2 waits ~18 ms per round (±30%)"])
key("batch_server", "priority_inversion", "thread_differences", ["worker-2"],
    f"worker-2, unlike the other workers, blocks ~18 ms per round on cache_lock: {PI}",
    ["~18 ms of blocking per round (±30%)"])
key("batch_server", "priority_inversion", "priority_inversion", ["compactor"],
    PI, where_all=["worker-2", "flusher"])
key("batch_server", "deadlock", "hang", ["worker-1", "worker-3"],
    "at ~12 s (40% of the run) worker-1 and worker-3 deadlock on locks A and B; the coordinator "
    "waits for their round forever, so the program makes no progress until the end",
    ["it stops at ~12 s (±1 s)"])
key("batch_server", "deadlock", "long_blocked_waits", ["worker-1", "worker-3"],
    "worker-1 holds lock A and waits for B; worker-3 holds B and waits for A; both stay blocked "
    "from ~12 s to the end (the coordinator, waiting for them, is a consequence)")
key("batch_server", "deadlock", "deadlock", [],
    "worker-1 holds lock A and waits for lock B; worker-3 holds B and waits for A, from ~12 s",
    where_all=["worker-1", "worker-3"])
key("batch_server", "hang", "hang", ["worker-3"],
    "at ~12 s (40% of the run) worker-3 blocks forever in read() on a pipe nobody writes to; the "
    "coordinator waits for the round forever. There is no lock cycle",
    ["it stops at ~12 s (±1 s)"])
key("batch_server", "hang", "long_blocked_waits", ["worker-3"],
    "worker-3 blocks in read() on a pipe nobody writes to, from ~12 s to the end")
key("batch_server", "contention", "lock_contention", ["worker-0", "worker-1", "worker-2", "worker-3"],
    "the workers, each on its own CPU, do their work as 40 short critical sections on one shared "
    "lock (stats_lock) and keep blocking on each other in short futex waits",
    ["rounds take ~{round_ms_mean:.0f} ms against ~20.5 ms healthy, so the workers lose a few ms "
     "per round (±30%)"])
key("batch_server", "convoy", "lock_contention", ["worker-0", "worker-1", "worker-2", "worker-3"],
    "each worker holds one global lock for its whole 5 ms of work, so the others wait for it",
    ["each waiting worker waits ~5 ms at a time; rounds take ~{round_ms_mean:.0f} ms (±30%)"])
key("batch_server", "convoy", "convoy", ["worker-0", "worker-1", "worker-2", "worker-3"],
    "the four workers hold one global lock for all of their 5 ms of work, so they run one after "
    "another instead of in parallel; each waits on whichever worker holds the lock (they take "
    "turns)", ["rounds take ~{round_ms_mean:.0f} ms (±25%)"])

# ---------------------------------------------------------------- ticker
# Healthy: the sampler wakes every 2 ms, ~0.25 ms of work, lateness ~0.
key("ticker", "one_off_delay", "one_off_delay", ["sampler", "maintenance"],
    "once, at ~15 s (50% of the run), the maintenance thread (SCHED_FIFO 10, same CPU) spins "
    "30 ms, so the sampler wakes ~30 ms late once",
    ["at ~15 s (±1 s)", "~{lateness_ms_max:.0f} ms late (±25%)"])
key("ticker", "one_off_delay", "scheduling_delay", ["sampler"],
    "the sampler is runnable but kept off its CPU by the maintenance thread (SCHED_FIFO 10) "
    "spinning for 30 ms, once at ~15 s",
    ["one wait of ~30 ms (±25%), once"])
key("ticker", "jitter", "jitter", ["sampler", "maintenance"],
    "the maintenance thread (SCHED_FIFO 10, same CPU) spins 0.3-1.8 ms at random every "
    "0.5-2.5 ms all run, so the sampler's wake-up lateness varies",
    ["lateness from 0 to ~1.5-2.6 ms (p99 ~{lateness_ms_p99:.1f} ms), against a 2 ms period"])
key("ticker", "jitter", "scheduling_delay", ["sampler"],
    "the sampler is runnable but waits behind the maintenance thread (SCHED_FIFO 10) spinning "
    "0.3-1.8 ms at random, all run",
    ["waits of up to ~1.5-2.6 ms, very often (every few ms)"])
key("ticker", "gradual_slowdown", "gradual_slowdown", ["sampler"],
    "the sampler's work per cycle grows steadily from ~0.1 ms to ~3 ms over the run; past ~65% "
    "of the run it overruns its 2 ms period",
    ["cycles ~{cycle_ms_mean_first_half:.1f} ms on average in the first half and "
     "~{cycle_ms_mean_second_half:.1f} ms in the second (or ~0.1 ms growing to ~3 ms) (±30%)"])
key("ticker", "sudden_change", "sudden_change", ["sampler"],
    "at ~15 s (50% of the run) the sampler's work per cycle jumps from ~0.2 ms to ~2.5 ms, so "
    "every later cycle overruns the 2 ms period",
    ["at ~15 s (±1 s)", "from ~{cycle_ms_mean_first_half:.2f} ms to ~{cycle_ms_mean_second_half:.1f} "
     "ms per cycle (±30%)"])
key("ticker", "oversleeping", "oversleeping", ["sampler"],
    "the sampler's sleeps end ~4 ms late while its CPU is free: its timer slack is 4 ms "
    "(prctl PR_SET_TIMERSLACK), so its timer expires late. Not CPU contention",
    ["~{lateness_ms_mean:.1f} ms late per wake-up (±30%)"])
key("ticker", "rt_preempted", "rt_preempted", ["maintenance"],
    "the sampler (SCHED_FIFO 20) is preempted by the maintenance thread (SCHED_FIFO 50, same "
    "CPU), which spins 5 ms every 300 ms",
    ["every ~300 ms (±20%), ~3 times a second", "for ~5 ms each time (±30%)"])
key("ticker", "rt_preempted", "scheduling_delay", ["sampler"],
    "the sampler is runnable but waits behind the higher-priority maintenance thread "
    "(SCHED_FIFO 50) spinning 5 ms every 300 ms",
    ["waits of up to ~5 ms (±30%)", "every ~300 ms"])

# ---------------------------------------------------------------- crunch
# Healthy: 8 calc threads, one per CPU, 10 ms of work every round; rounds ~10.5 ms.
key("crunch", "load_imbalance", "bottleneck_thread", ["calc-0"],
    "calc-0 gets 4x the work of the others (40 ms per round against 10 ms) and every round waits "
    "for it at the barrier", ["rounds take ~{round_ms_mean:.0f} ms against ~10.5 ms healthy (±25%)"])
key("crunch", "load_imbalance", "load_imbalance", ["calc-0"],
    "calc-0 gets 40 ms of work per round, the other seven 10 ms; they finish early and wait",
    ["calc-0 does ~4x the work of each other calc thread (±30%)"])
key("crunch", "load_imbalance", "thread_differences", ["calc-0"],
    "calc-0 runs ~4x longer per round than the other calc threads (40 ms against 10 ms), which "
    "spend the difference waiting at the barrier", ["~4x the CPU time of the others (±30%)"])
key("crunch", "cpu_starvation", "bottleneck_thread", ["calc-3", "monitor"],
    "every 5 s a monitor thread (SCHED_FIFO 10) spins 2 s on calc-3's CPU; calc-3 barely runs, "
    "and the whole round waits for it", ["those rounds stretch to ~1 s (±30%), 5 times"])
key("crunch", "cpu_starvation", "cpu_starvation", ["calc-3"],
    "calc-3 is runnable but gets almost no CPU for ~2 s at a time, every 5 s: the monitor thread "
    "(SCHED_FIFO 10) spins on its CPU", ["~2 s at a time (±30%), every ~5 s"],
    where_all=["monitor"])
key("crunch", "cpu_starvation", "barrier_straggler", ["calc-3"],
    "the other calc threads wait at the barrier for calc-3, which is kept off its CPU by the "
    "monitor thread (SCHED_FIFO 10) spinning 2 s every 5 s")
key("crunch", "cpu_starvation", "scheduling_delay", ["calc-3"],
    "calc-3 is runnable but waits for its CPU while the monitor thread (SCHED_FIFO 10) spins",
    ["waits of up to ~1-2 s (±30%), every ~5 s"])
key("crunch", "barrier_straggler", "bottleneck_thread", ["calc-5", "monitor"],
    "a monitor thread (SCHED_FIFO 10) on calc-5's CPU spins 20 ms at the start of every round, "
    "so calc-5 finishes last and every round waits for it",
    ["rounds take ~{round_ms_mean:.0f} ms against ~10.5 ms healthy (±25%)"])
key("crunch", "barrier_straggler", "barrier_straggler", ["calc-5"],
    "every round the calc threads wait at the barrier for calc-5, which is late because a monitor "
    "thread (SCHED_FIFO 10) spins 20 ms on its CPU at the start of the round")
key("crunch", "barrier_straggler", "scheduling_delay", ["calc-5"],
    "calc-5 is runnable but waits ~20 ms every round behind the monitor thread (SCHED_FIFO 10) "
    "on its CPU", ["~20 ms per round (±30%)"])
key("crunch", "oversubscription", "scheduling_delay",
    [f"calc-{i}" for i in range(32)],
    "32 calc threads share 4 CPUs, so they wait in the run queues for the CPU",
    ["waits of milliseconds (several ms to tens of ms) per round"])
key("crunch", "oversubscription", "oversubscription", [],
    "32 runnable calc threads share 4 CPUs (the healthy run has 8 threads on 8 CPUs); they queue "
    "for the CPU", ["32 threads", "4 CPUs"],
    fix_any=["use as many calc threads as CPUs (4 here)", "a thread pool sized to the CPUs",
             "give the threads more CPUs (widen the affinity mask to match the thread count)"])
# busy_wait on the busy_wait trace is graded "cannot tell" (make_pairs.UNSEEABLE): the spin-wait
# looks like nonstop computation in a kernel trace.
key("crunch", "busy_wait", "cpu_hog", ["collector"],
    "the collector thread uses a whole CPU all run, spinning on a flag while it waits",
    ["~100% of one CPU (at least 90%)"])
key("crunch", "cpu_hog", "cpu_hog", ["indexer"],
    "the indexer thread computes without pause on its own CPU for the whole run",
    ["~100% of one CPU (at least 90%)"])
key("crunch", "migrations", "excessive_migrations", [f"calc-{i}" for i in range(8)],
    "each calc thread moves itself to the next CPU (sched_setaffinity) after every 1 ms of work",
    ["~800 migrations per second in all, ~100 per thread (±40%)"],
    fix_any=["stop calling sched_setaffinity / stop changing the affinity during the work",
             "pin each calc thread to one CPU and leave it there",
             "let the scheduler place the threads (no per-millisecond affinity changes)"])
key("crunch", "odd_worker", "thread_differences", ["calc-6"],
    "calc-6, unlike the other calc threads, also writes 200 small log lines (write(), 64 bytes "
    "each) after its CPU work every round", ["~200 write() calls per round (±30%)"])

# ---------------------------------------------------------------- filestore
key("filestore", "disk_wait", "waiting_on_disk", ["writer"],
    "the writer fdatasync()s every record (1000 per second, ~0.3-0.6 ms each on the disk) plus "
    "an 8 MB checkpoint once a second, so it is blocked on the disk much of the time",
    ["35-50% of the writer's time (accept 25-60%)"])
key("filestore", "disk_wait", "slow_syscalls", ["writer"],
    "the writer spends about 35% of its time inside fdatasync(), syncing every record (~1000 per "
    "second, ~{sync_ms_p50:.1f} ms each) plus a once-a-second checkpoint sync of several ms",
    ["~35% of the writer's time in system calls (accept 20-50%)",
     "fdatasync() ~{sync_ms_p50:.1f}-{sync_ms_mean:.1f} ms typical, up to ~{sync_ms_max:.0f} ms (±50%)"])
key("filestore", "small_calls", "many_small_calls", ["reader"],
    "every 100 ms the reader reads 5000 bytes one byte per read() call",
    ["~50,000 read() calls per second (±30%)", "1 byte each"],
    fix_any=["read in larger chunks: one read of the whole 5000 bytes (or 64 KB)",
             "use a buffered reader (e.g. fread / a user-space buffer)", "mmap the file"])
key("filestore", "polling", "idle_polling", ["stats"],
    "the stats thread calls poll() with a zero timeout on a pipe that never has data, then sleeps "
    "200 us, over and over", ["~4000-5000 polls per second, none ready (±30%)"],
    fix_any=["block in poll() with a timeout (or -1) instead of a zero timeout",
             "wait on the pipe with a blocking read or an event (epoll / condition variable)",
             "poll much less often"])
key("filestore", "retry_loop", "failing_retry_loop", ["stats"],
    "the stats thread tries to open data/incoming/batch.ready every 1 ms; the file never exists, "
    "so every openat() fails with ENOENT (-2)", ["~1000 failures per second (±30%)"])
key("filestore", "file_churn", "file_churn", ["writer"],
    "the writer writes each 4 KB record to a new file (seg-NNNNNN.tmp, renamed to .dat) in the "
    "store's data folder, and deletes the file from 100 records earlier",
    ["~200 files created and ~200 deleted per second (±30%)"])
key("filestore", "unexpected_scan", "unexpected_activity", ["stats"],
    "every 2 s the stats thread walks /usr/share/doc, opening and reading the start of up to 300 "
    "files that have nothing to do with the store")

# ---------------------------------------------------------------- pipeline
key("pipeline", "slow_stage", "bottleneck_thread", ["parser"],
    "the parser spends 1.5 ms per item, too slow for the reader's 2000 items per second: its "
    "input queue stays full, the reader blocks on it and the sinks starve",
    ["~1.5 ms per item (±30%), ~{items_parsed:.0f} items in the run against 60,000 healthy"])
key("pipeline", "slow_stage", "slowest_stage", ["parser"],
    "the parser (stage 2) spends 1.5 ms per item: its input queue stays full, the reader blocks "
    "on it and the sinks wait for items")
key("pipeline", "bursty", "producer_consumer_mismatch", ["reader", "parser"],
    "the reader produces in bursts (500 items as fast as it can, then nothing for 400 ms), so the "
    "reader-parser queue (and the parser-sink queues) fill up during a burst and drain empty "
    "between bursts")
key("pipeline", "herd", "thundering_herd", [f"sink-{i}" for i in range(16)],
    "16 sink threads share one queue and the parser wakes all of them "
    "(pthread_cond_broadcast) for every item; only one gets it and the rest go back to sleep",
    ["16 threads woken per item"],
    fix_any=["wake one waiter per item (pthread_cond_signal instead of broadcast)",
             "one queue per sink (hand items to a specific sink)", "fewer sink threads"])
key("pipeline", "idle_workers", "idle_workers", ["sink-1", "sink-2", "sink-3"],
    "the parser hands every item to sink-0 instead of round-robin: sink-1, sink-2 and sink-3 "
    "never get any work")
key("pipeline", "idle_workers", "load_imbalance", ["sink-0"],
    "the parser hands every item to sink-0; sink-1, sink-2 and sink-3 get nothing",
    ["sink-0 gets all ~{items_sink-0:.0f} items, the other sinks 0"])
key("pipeline", "idle_thread", "idle_thread", ["compressor"],
    "the compressor thread is started at launch and waits forever for work that never comes")

# ---------------------------------------------------------------- kvstore
# Healthy: a request takes ~0.4 ms.
NW = ("once a second each client tries to connect to a replica at 10.255.255.1:7070, which "
      "never answers, and gives up after 300 ms")
key("kvstore", "network_wait", "long_blocked_waits", ["client-0", "client-1", "client-2", "client-3"],
    f"the clients block in connect(): {NW}", ["~300 ms each time (±20%), once a second"])
key("kvstore", "network_wait", "waiting_on_network", ["client-0", "client-1", "client-2", "client-3"],
    NW, ["~300 ms per wait (±20%), ~30% of each client's time"])
key("kvstore", "slow_backend", "bottleneck_thread", ["kvd", "kvd-conn-0", "kvd-conn-1", "kvd-conn-2", "kvd-conn-3"],
    "the server process kvd spends 3 ms per request instead of 0.1 ms, all on one CPU: it is "
    "saturated and the clients wait for its replies",
    ["~3 ms of server work per request (±30%); requests take ~{request_ms_mean:.0f} ms against "
     "~0.4 ms healthy"])
key("kvstore", "slow_backend", "waiting_on_process", ["kvd", "kvd-conn-0", "kvd-conn-1", "kvd-conn-2", "kvd-conn-3"],
    "the clients spend most of their time blocked waiting for replies from the server process "
    "kvd, which takes 3 ms per request on one CPU",
    ["~{request_ms_mean:.0f} ms per request (±30%) against ~0.4 ms healthy"])
key("kvstore", "tail_latency", "tail_latency", ["kvd", "kvd-conn-0", "kvd-conn-1", "kvd-conn-2", "kvd-conn-3"],
    "2% of requests, at random, take a 25 ms slow path in the server; the rest are as fast as "
    "healthy", ["~2% of requests (1-5%)", "~25 ms against a median of ~{request_ms_p50:.2f} ms "
                "(~100x or more)"])

# ---------------------------------------------------------------- cachesvc
key("cachesvc", "allocation_churn", "allocation_churn", ["server-0", "server-1"],
    "for every lookup batch the servers allocate a 256 KB buffer, fill it and free it; each "
    "allocation is an mmap() and each free an munmap()",
    ["~1000 mmap() and ~1000 munmap() per second per server (±30%)"],
    fix_any=["reuse one buffer per server instead of allocating each batch",
             "a buffer pool / free list", "allocate on the stack or a smaller buffer",
             "raise malloc's mmap threshold (M_MMAP_THRESHOLD) so the memory is reused"])

# ---------------------------------------------------------------- jobrunner
key("jobrunner", "slow_startup", "slow_startup", ["jobrunner"],
    "before the first job, the main thread spends ~1.5 s on CPU (initialisation) and then sleeps "
    "~1.5 s", ["~3 s from the start to the first job (±20%), against ~20 ms healthy"])
key("jobrunner", "slow_shutdown", "slow_shutdown", ["job-0", "job-1", "job-2", "job-3"],
    "after the last job, the four job threads, one after another, each hold a shared lock for "
    "1.5 s while they flush their state; the main thread waits to join them",
    ["~6 s from the last job to the exit (±20%)"])
key("jobrunner", "crash", "crash", ["job-helper"],
    "a helper process (job-helper, pid {crashed_helper_pid:.0f}) dies of a segmentation fault "
    "(SIGSEGV, signal 11) at ~15 s; the dispatcher carries on", ["SIGSEGV / signal 11"])
key("jobrunner", "fork_storm", "fork_exec_storm", ["job-0", "job-1", "job-2", "job-3"],
    "every job runs a short-lived process: the job threads fork and exec /usr/bin/true for each "
    "job", ["~100 processes per second, ~{processes_started:.0f} in all (±30%)",
            "they run /usr/bin/true"])
key("jobrunner", "thread_churn", "thread_churn", ["jobrunner"],
    "every job runs on a brand-new thread, created and joined by the dispatcher (the main thread "
    "jobrunner), instead of on the pool", ["~100 threads per second, ~{threads_created:.0f} in all (±30%)"])
key("jobrunner", "never_exits", "never_exits", ["job-2"],
    "at ~12 s all jobs are done and the pool is shut down, but job-2 is blocked forever in read() "
    "on a pipe nobody writes to, so the main thread waits forever to join it and the process "
    "stays alive", ["from ~12 s (±1 s) to the end of the trace"])

# ---------------------------------------------------------------- reporter
# Healthy: a report takes ~8.2 ms.
key("reporter", "neighbour", "noisy_neighbour", ["indexd", "indexd-0", "indexd-1", "indexd-2"],
    "from ~9 s to ~24 s a separate process, indexd (pid {neighbour_pid:.0f}), runs three CPU-bound "
    "threads on render's CPU; render gets about a quarter of its CPU",
    ["reports take ~4x longer, ~30 ms against ~8 ms (±30%), from ~9 s to ~24 s"])
key("reporter", "neighbour", "scheduling_delay", ["render"],
    "render is runnable but waits for its CPU behind the three indexd threads, from ~9 s to ~24 s",
    ["waits of milliseconds (several ms) per report"])
key("reporter", "irq_storm", "interrupt_storm", ["nvme0q3", "nvme"],
    "from ~9 s to ~21 s, the disk's (NVMe, nvme0q3) completion interrupts on CPU 3, render's CPU, "
    "take about a fifth of that CPU; they come from the archive thread's direct 4 KB reads",
    ["~20% of CPU 3 (accept 10-35%)", "from ~9 s to ~21 s (±1 s)",
     "~2.3 million interrupts (~190,000 per second) (±30%)"])


def resolve(entry: dict, metrics: dict) -> dict:
    class Missing(dict):
        def __missing__(self, k):
            raise KeyError(f"no metric {k!r}")
    m = Missing(metrics)
    fill = lambda s: s.format_map(m)
    out = dict(entry)
    out["cause"] = fill(entry["cause"])
    out["numbers"] = [fill(n) for n in entry["numbers"]]
    return out


def main() -> int:
    pairs = json.loads((HERE / "pairs.json").read_text())["pairs"]
    texts = {q["id"]: q["text"] for q in json.loads((HERE / "questions.json").read_text())["questions"]}
    used, problems, out = set(), [], []
    for p in pairs:
        gt = json.loads((HERE / "runs" / p["run_id"] / "ground_truth" / "ground_truth.json").read_text())
        item = {k: p[k] for k in ("question", "symptom", "program", "category", "hub", "run_id",
                                  "fault", "truth")}
        item["fault_summary"] = gt["fault_summary"]
        item["wordings"] = {"a": texts[p["question"] + "a"], "b": texts[p["question"] + "b"]}
        if p["truth"] == "present":
            k = (p["program"], p["fault"], p["symptom"])
            if k not in K:
                problems.append(f"{p['question']} {p['run_id']}: no answer-key entry for {k}")
                continue
            used.add(k)
            metrics = {**gt["metrics"], **{n.replace("-", "_"): v for n, v in gt["metrics"].items()}}
            metrics.update({n: v for n, v in gt["metrics"].items()})
            try:
                item["expected"] = resolve(K[k], metrics)
            except KeyError as e:
                problems.append(f"{p['question']} {p['run_id']}: {e}")
                continue
            names = {t["name"] for t in gt["threads"]} | {"nvme", "nvme0q3"}
            for n in item["expected"]["where_any"] + item["expected"]["where_all"]:
                if n not in names:
                    problems.append(f"{p['question']} {p['run_id']}: {n!r} is not a thread of the run")
            if p["category"] == "remediation" and not item["expected"]["fix_any"]:
                problems.append(f"{p['question']}: remediation question without fix_any")
        elif p["truth"] == "absent":
            item["expected"] = {"verdict": "no: the symptom is absent from the program"}
        elif p["truth"] == "cannot_see" and (p["symptom"], p["program"], p["fault"]) in UNSEEABLE:
            item["expected"] = {"verdict": "cannot tell: " + UNSEEABLE[(p["symptom"], p["program"], p["fault"])]}
        elif p["truth"] == "cannot_see":
            item["expected"] = {"verdict": "cannot tell: the trace lacks the events this symptom "
                                           "needs (" + (p["events_left_out"] or "not available "
                                           "on this kernel") + ")"}
        out.append(item)
    for k in sorted(set(K) - used):
        problems.append(f"answer-key entry never used: {k}")
    (HERE / "answer_key.json").write_text(json.dumps({
        "about": "What a correct answer says, for every question-trace pair. Generated by "
                 "make_answer_key.py. Never give this file to the systems under test.",
        "pairs": out}, indent=1) + "\n")
    for p in problems:
        print("  " + p)
    present = sum(1 for i in out if i["truth"] == "present")
    print(f"wrote answer_key.json: {len(out)} pairs, {present} with a full answer key "
          f"({len(K)} entries); {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
