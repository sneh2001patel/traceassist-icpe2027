# Symptom bench

Programs that reproduce 48 performance symptoms engineers ask about, each with a known
answer, to measure true and false positives and negatives (Section 4 of the paper).

The recorded traces are archives in `../data/`; `../data/unpack.sh traces` puts each in
`runs/<run>/trace/`.

Each program is one workload with a **fault switch**. `--fault none` is the healthy baseline,
the negative control for every symptom of that program. Every other fault injects one problem.
The program writes its own answer key: the symptoms the fault makes present, the threads and
their TIDs, when the fault acts, and its own measurements.

The 9 programs have 44 faults, which with the 9 healthy runs make 53 scenarios. Together they
cover **all 48 symptoms**.

## Programs and faults

| Program | Workload | Faults (besides `none`) |
|---|---|---|
| `batch_server` | A coordinator hands a batch to 4 workers per round and waits for all of them. This is the workload of our earlier prototype study. | `holder_sleeps`, `contention`, `convoy`, `deadlock`, `hang`, `priority_inversion` |
| `ticker` | A sampler that must run every 2 ms. | `one_off_delay`, `jitter`, `gradual_slowdown`, `sudden_change`, `oversleeping`, `rt_preempted` |
| `crunch` | 8 calc threads, one per CPU, do 10 ms of work every 100 ms and meet at a barrier. | `load_imbalance`, `barrier_straggler`, `cpu_hog`, `busy_wait`, `cpu_starvation`, `oversubscription`, `migrations`, `odd_worker` |
| `filestore` | A record store: writer, reader and stats threads. | `disk_wait`, `small_calls`, `polling`, `retry_loop`, `file_churn`, `unexpected_scan` |
| `pipeline` | reader → parser → 4 sinks, joined by bounded queues. | `slow_stage`, `bursty`, `herd`, `idle_workers`, `idle_thread` |
| `kvstore` | 4 clients send requests over loopback TCP to a server process, `kvd`. | `slow_backend`, `tail_latency`, `network_wait` |
| `cachesvc` | An in-memory cache: a 256 MB arena, a loader and 2 servers. | `memory_pressure`, `allocation_churn` |
| `jobrunner` | A dispatcher with a pool of 4 job threads. | `slow_startup`, `slow_shutdown`, `crash`, `fork_storm`, `thread_churn`, `never_exits` |
| `reporter` | A render thread produces a report every 50 ms. | `neighbour` (a separate process competes for its CPU), `irq_storm` (disk interrupts on its CPU) |

`./<program> --list-faults` prints each fault's description and its `present` and `dont_care`
symptoms. `scenarios.json` (from `make scenarios.json`) collects them all.

## Files

| File | |
|---|---|
| `bench.h` | Shared code: options, thread registry, answer-key writer, calibrated CPU work, watchdog. |
| `*.c`, `Makefile` | The programs. `make` builds them all. |
| `capture.sh` | Records one program and fault with LTTng. |
| `record_all.sh` | Records every scenario at 30 s, plus the three variants without events (`crash` without signals, `disk_wait` without block, `network_wait` without net). |
| `check_runs.py` | Checks every recording with `babeltrace2`: discarded events, whether every answer-key thread appears, and the event counts the faults depend on. It writes `runs/check.json`. |
| `make_catalog.py` | Writes `symptoms.json` and checks it against `scenarios.json`. |
| `symptoms.json` | The 48 symptoms: id, how users ask about it, what "present" means, which events it needs, and its question's category and hub scope. |
| `make_questions.py` | Writes `questions.json` and `questions.md`: 56 questions (one per symptom and program that can show it), each in a precise and an everyday wording. It checks that every question names its program, and that none names a thread only some of the program's traces have. |
| `questions.json`, `questions.md` | The 112 questions (generated), and the grader's notes. |
| `make_pairs.py` | Writes `pairs.json` and `pairs.csv`, the test matrix: each question with up to 5 traces of its program (every positive, the healthy run, then other faults at random, seeded by symptom and program) and the right answer on each. 258 pairs: 74 present, 178 absent, 6 cannot be seen. Like `index.csv`, never give it to the systems under test. |
| `scenarios.json` | Every program's faults (generated). |
| `make_answer_key.py` | Writes `answer_key.json`: for each of the 74 present pairs, the threads or processes a correct answer names, the cause, the numbers (filled in from that run's own measurements, with a tolerance) and, for remediation questions, the fixes that count. Every entry comes from the fault's code and measurements. Never give it to the systems under test. |
| `verdict.py` | The verdict line every system gets after every question ("Begin your answer with exactly one line: Verdict: yes / no / cannot tell from this trace"), and its parser. `python3 verdict.py` runs the parser's checks. |
| `run_traceassist.py` | Asks TraceAssist every pair in both wordings through the server's `/ask` (127.0.0.1:8092), one at a time, grouped by trace. Saves each answer to `results/traceassist/run<N>/<question>__<run>.json`; restartable. `--dry-run`, `--limit N`, `--v1`, `--question Q15`, `--trace batch_server-ff0f`, `--wording a`, `--run 2`. It turns the server's skill cache off, so repeats don't reuse run 1's skill decisions. |
| `score.py` | Scores saved answers from their verdict lines (no API calls): TP, FP, TN, FN, precision, recall, specificity, F1, balanced accuracy, abstentions, by category, hub, group and v1, plus wording sensitivity and the list of errors. `--system`, `--run`, `--v1`, `--csv`. Location, numbers and fixes are left to the LLM judge. |

## Recording a scenario

```bash
sudo lttng-sessiond --daemonize          # once per boot
make
./capture.sh batch_server holder_sleeps            # 30 s by default
./capture.sh jobrunner crash --without signal      # without the events that show the crash
```

Each recording goes to `runs/<program>-<4 hex digits>/` and adds a line to `runs/index.csv`. The
run id is random, so the trace's name never gives the fault away. Inside the run folder:

- `trace/` is the LTTng trace. It is the only thing to give the systems under test.
- `ground_truth/ground_truth.json` and `ground_truth/series.csv` are the answer key.
- `capture.json` lists the fault and which event groups were recorded or left out.
- `program.log` is the program's output.

## The answer key

`ground_truth.json` has:

- **`present`:** the symptoms the fault makes present.
- **`dont_care`:** symptoms that are arguably present too. For example, priority inversion also
  delays the low-priority thread, so "scheduling delay" isn't wrong there. They are graded
  neither way.
- **`threads`:** every thread the program started, with its name, PID, TID and role.
- **`intervals`:** when the fault acts, with which thread, as seconds from the program's start
  and as `CLOCK_MONOTONIC` nanoseconds (LTTng's kernel clock). `clock.start_realtime_ns` gives
  the offset to wall-clock time.
- **`metrics`:** the program's own measurements: round times, lateness percentiles, lock
  waits, sync times, and so on.

**Absent** is every symptom in `symptoms.json` that is neither `present` nor `dont_care`.

When a symptom's `requires` event group wasn't recorded (see `capture.json`), it can't be
established from the trace. The right answer is then "the trace cannot show this".

## Rules the programs follow

- **The trace is the only evidence.** Thread, process and file names are neutral and never name
  the fault. Run ids are random.
- **CPU work is a calibrated arithmetic loop,** never a loop around a syscall.
  `CLOCK_MONOTONIC` reads go through the vDSO on this machine (TSC clocksource), so a busy
  thread leaves no syscalls in the trace.
- **Pinning.** Threads with cross-thread wake-ups are pinned to one CPU where the fault allows
  it, as in CASCON, to avoid Trace Compass's cross-CPU wake-up misattribution
  ([critical_path_bug_report.md](../critical_path_bug_report.md), "Finding 2").
- **Stuck runs still end, outside the trace.** A watchdog ends runs whose threads stay stuck
  (`deadlock`, `hang`, `never_exits`) just after the end of the run. Under `capture.sh` it first
  asks for tracing to stop (through two FIFOs) and waits until it has, so the trace ends with
  the threads still blocked. Without this, its `_exit()` woke every blocked thread inside the
  trace, and the critical path named the watchdog as what they were waiting for. The three
  stuck runs were recorded again after this fix.

## Limits on this machine

- **No page-fault or kmem probe.** This kernel's LTTng has neither, so `memory_pressure` is
  always a "can't be seen" case here: its `requires` is `mem`. The `madvise` calls and the
  loader's CPU time are still in the trace.
- **`network_wait` needs a default route.** It connects to `10.255.255.1`, which is routed out
  of the machine but never answers. Offline, `connect()` fails at once instead of waiting.
- **Real-time faults need `SCHED_FIFO`.** This applies to `priority_inversion`, `one_off_delay`,
  `jitter`, `rt_preempted`, `barrier_straggler` and `cpu_starvation`. The user has `rtprio` 95,
  and RT throttling is off (`sched_rt_runtime_us` = 1000000), so every real-time burst is
  bounded and pinned to one CPU.
- **The rest of the machine is in the trace too.** The trace records everything running on the
  desktop. Absent symptoms are only reliable for the program itself, so the confusion matrix
  should use questions that name the program.
- **The desktop's own activity is in every trace.** In every 30 s recording the rest of the
  machine adds about 450 execs, 480 signals and 1,500 CPU migrations (`runs/check.json`).
  That is next to `fork_storm`'s ~3,400 execs, the crash's single SIGSEGV and `migrations`'
  ~26,000 migrations. So "the trace shows signals or execs" is not evidence by itself: the
  question has to be about the program's own processes.
- **`irq_storm` relies on this machine's NVMe disks.** They have one completion interrupt per
  CPU, raised on the CPU that issued the read, so the archive thread's direct 4 KB reads (64 in
  flight, about 280,000 a second) interrupt render's CPU: in the trace, about 22% of that CPU
  over the 12-second storm, against about 1% on the others. Disk interrupts with a single
  queue, or a fixed interrupt CPU, would land elsewhere. The storm adds about 2.3 million
  interrupts and 3.4 million block requests, so its trace is 883 MB, with no events discarded.
- **`disk_wait` must write to a real disk.** It writes to `runs/<id>/data` on the home disk.
  `/tmp` is tmpfs and would never wait on the disk.
