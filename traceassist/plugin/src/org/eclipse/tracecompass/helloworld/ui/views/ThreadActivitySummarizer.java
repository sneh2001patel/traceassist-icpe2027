package org.eclipse.tracecompass.helloworld.ui.views;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.tmf.core.event.ITmfEvent;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventField;
import org.eclipse.tracecompass.tmf.core.event.aspect.TmfCpuAspect;
import org.eclipse.tracecompass.tmf.core.request.ITmfEventRequest;
import org.eclipse.tracecompass.tmf.core.request.TmfEventRequest;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Answers "what does this thread do?" from the kernel trace itself: which
 * files, streams and sockets it used and how, in what order, and what else it
 * spent system calls on.
 *
 * The syscall-latency table that TMLL reads only has syscall names, durations
 * and return values. The arguments that say what a thread actually did --
 * openat's filename and flags, which fd each read/write/fsync/close used --
 * are only in the raw events, so this reads them directly in one pass.
 *
 * File descriptors are resolved to paths with a per-process fd table, filled
 * from open/dup/socket/pipe calls, from LTTng's startup statedump of already
 * open files, and inherited across fork.
 */
final class ThreadActivitySummarizer {

    private static final int MAX_TIMELINE_STEPS = 60;

    private static final int O_ACCMODE = 3;
    private static final int O_WRONLY = 1;
    private static final int O_RDWR = 2;
    private static final int O_CREAT = 64;
    private static final int O_EXCL = 128;
    private static final int O_TRUNC = 512;
    private static final int O_APPEND = 1024;
    private static final int O_DIRECTORY = 65536;
    private static final int O_CLOEXEC = 524288;
    private static final int F_DUPFD = 0;
    private static final int F_DUPFD_CLOEXEC = 1030;

    /** Writing a thread's comm file names it (pthread_setname_np). */
    private static final Pattern THREAD_COMM =
            Pattern.compile("^/proc/(self|\\d+)/task/(\\d+)/comm$");

    private static final Pattern SHARED_LIBRARY =
            Pattern.compile(".*\\.so(\\.[0-9]+)*$");

    private static final Map<String, String> CATEGORY = new HashMap<>();

    static {
        category("file open", "open", "openat", "openat2", "creat");
        category("file read/write", "read", "write", "pread64", "pwrite64",
                "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
                "sendfile64", "copy_file_range", "splice");
        category("file sync", "fsync", "fdatasync", "sync", "syncfs",
                "sync_file_range");
        category("file close", "close", "close_range");
        category("file metadata", "stat", "fstat", "lstat", "newfstatat",
                "statx", "access", "faccessat", "faccessat2", "readlink",
                "readlinkat", "getdents64", "lseek", "fcntl", "ioctl",
                "fstatfs", "statfs", "getcwd", "chdir", "fchdir", "umask",
                "fadvise64", "fallocate", "ftruncate", "truncate", "flock");
        category("file create/delete/rename", "unlink", "unlinkat", "rename",
                "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "link",
                "linkat", "symlink", "symlinkat", "chmod", "fchmod",
                "fchmodat", "chown", "fchown", "fchownat", "utimensat");
        category("memory management", "mmap", "munmap", "mprotect", "brk",
                "madvise", "mremap", "mlock", "munlock", "membarrier");
        category("process/thread management", "execve", "execveat", "clone", 
                "clone3", "fork", "vfork", "exit", "exit_group", "wait4",
                "waitid", "prctl", "arch_prctl", "set_tid_address",
                "set_robust_list", "rseq", "prlimit64", "getrlimit",
                "setrlimit", "sched_setaffinity", "sched_getaffinity",
                "sched_yield", "getpid", "gettid", "getppid", "getuid",
                "geteuid", "getgid", "getegid", "uname", "getrandom",
                "capget", "personality", "setpgid", "getpgid", "setsid");
        category("signals", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                "sigaltstack", "rt_sigtimedwait", "kill", "tgkill", "tkill",
                "rt_sigsuspend", "pause");
        category("sleep/timers", "nanosleep", "clock_nanosleep", "alarm",
                "setitimer", "timerfd_create", "timerfd_settime",
                "clock_gettime", "gettimeofday", "timer_create",
                "timer_settime", "clock_getres");
        category("synchronization (futex)", "futex", "futex_waitv");
        category("network", "socket", "socketpair", "connect", "accept",
                "accept4", "bind", "listen", "sendto", "recvfrom", "sendmsg",
                "recvmsg", "sendmmsg", "recvmmsg", "shutdown", "getsockopt",
                "setsockopt", "getsockname", "getpeername");
        category("polling/event waiting", "poll", "ppoll", "select",
                "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
                "epoll_pwait", "epoll_pwait2", "eventfd2", "inotify_add_watch");
        category("pipes/fd duplication", "pipe", "pipe2", "dup", "dup2",
                "dup3");
    }

    private static void category(String name, String... syscalls) {
        for (String syscall : syscalls) {
            CATEGORY.put(syscall, name);
        }
    }

    /** One entry in a process's fd table. */
    private static final class FdEntry {
        final String label;
        final String kind;
        final boolean cloexec;

        FdEntry(String label, String kind, boolean cloexec) {
            this.label = label;
            this.kind = kind;
            this.cloexec = cloexec;
        }
    }

    /** Everything the requested thread did to one file/stream/socket. */
    private static final class Target {
        final String label;
        final String kind;
        String openMode = "";
        int opens;
        int failedOpens;
        long bytesRead;
        int reads;
        long bytesWritten;
        int writes;
        int syncs;
        long syncNs;
        int closes;
        int otherOps;
        long firstNs = Long.MAX_VALUE;
        boolean touched;

        Target(String label, String kind) {
            this.label = label;
            this.kind = kind;
        }
    }

    private static final class Pending {
        final String name;
        final ITmfEvent entry;

        Pending(String name, ITmfEvent entry) {
            this.name = name;
            this.entry = entry;
        }
    }

    private final ITmfTrace fTrace;
    private final int fTid;
    private final long fWindowStart;
    private final long fWindowEnd;
    private final boolean fWindowed;
    private final long fTraceStart;
    private final KernelAnalysisModule fKernel;

    private final Map<String, Integer> fCurrentTid = new HashMap<>();
    private final Map<String, Integer> fPidOfTid = new HashMap<>();
    private final Map<String, Map<Long, FdEntry>> fFdTables = new HashMap<>();
    private final Map<String, Pending> fPending = new HashMap<>();

    private String fHost;
    /** Thread mode: one activity, for fTid. Process mode: one per PID. */
    private final boolean fProcessMode;
    private final Map<Integer, Activity> fActivities = new LinkedHashMap<>();
    /** Process mode: summarize only these PIDs (null: all). */
    private java.util.Set<Integer> fOnlyPids;
    /* Event name -> count, for events inside the window (process mode). */
    private final Map<String, Long> fEventCounts = new HashMap<>();
    private long fEventCount;
    /* Events per time bin over the window (process mode), for the busiest stretch. */
    private static final int EVENT_BINS = 500;
    private final long[] fEventBins = new long[EVENT_BINS];

    private ThreadActivitySummarizer(ITmfTrace trace, int tid,
            Long windowStart, Long windowEnd) {
        fTrace = trace;
        fTid = tid;
        fProcessMode = tid < 0;
        if (!fProcessMode) {
            fActivities.put(tid, new Activity(tid, false));
        }
        fTraceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        fWindowed = windowStart != null && windowEnd != null;
        fWindowStart = windowStart != null ? windowStart : fTraceStart;
        fWindowEnd = windowEnd != null ? windowEnd : traceEnd;
        fKernel = TmfTraceUtils.getAnalysisModuleOfClass(trace,
                KernelAnalysisModule.class, KernelAnalysisModule.ID);
        fRecordsSignals = recordsSignals(trace);
    }

    private final boolean fRecordsSignals;

    /**
     * @param windowStart
     *            window start in ns, or {@code null} for the whole trace
     * @param windowEnd
     *            window end in ns, or {@code null} for the whole trace
     */
    static JsonObject summarize(ITmfTrace trace, int tid,
            Long windowStart, Long windowEnd) {
        ThreadActivitySummarizer summarizer =
                new ThreadActivitySummarizer(trace, tid, windowStart,
                        windowEnd);
        return summarizer.run();
    }

    /**
     * Summarizes every process in one pass over the trace: what each one did
     * (as {@link #summarize} does for one thread, merged over its threads),
     * when it was created, ran a program and ended, and how many events of
     * each type the trace holds in the window.
     *
     * @return {"processes": {pid: summary, ...}, "event_counts": {...},
     *         "event_count": n}
     */
    static JsonObject summarizeProcesses(ITmfTrace trace, Long windowStart,
            Long windowEnd) {
        return summarizeProcesses(trace, windowStart, windowEnd, null);
    }

    /**
     * Recent all-process passes, by trace and window: reading every event of
     * a long trace takes minutes, and "what does this trace record" and "what
     * does each thread of X do" need the same pass.
     */
    private static final Map<String, JsonObject> PASS_CACHE = java.util.Collections.synchronizedMap(
            new LinkedHashMap<String, JsonObject>(4, 0.75f, true) {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, JsonObject> eldest) {
                    return size() > 2;
                }
            });

    /** As above, for only the processes in {@code onlyPids} (null: all); one shared pass per trace and window. */
    static JsonObject summarizeProcesses(ITmfTrace trace, Long windowStart,
            Long windowEnd, java.util.Set<Integer> onlyPids) {
        String key = trace.getPath() + "|" + windowStart + "|" + windowEnd;
        JsonObject full = PASS_CACHE.get(key);
        if (full == null) {
            full = new ThreadActivitySummarizer(trace, -1, windowStart, windowEnd).run();
            if (full.has("available") && full.get("available").getAsBoolean()) {
                PASS_CACHE.put(key, full);
            }
        }
        /*
         * Shared, not copied: on a long desktop trace this covers tens of
         * thousands of processes, and callers only read it.
         */
        if (onlyPids == null || !full.has("processes")) {
            return full;
        }
        JsonObject result = new JsonObject();
        for (Map.Entry<String, JsonElement> entry : full.entrySet()) {
            if (!"processes".equals(entry.getKey())) {
                result.add(entry.getKey(), entry.getValue());
            }
        }
        JsonObject processes = new JsonObject();
        for (Map.Entry<String, JsonElement> entry : full.getAsJsonObject("processes").entrySet()) {
            if (onlyPids.contains(Integer.valueOf(entry.getKey()))) {
                processes.add(entry.getKey(), entry.getValue().deepCopy());
            }
        }
        result.add("processes", processes);
        return result;
    }

    /** Give up reading when no new event has arrived for this long. */
    private static final long STALL_LIMIT_NS = 120_000_000_000L;

    /** Events delivered so far (read by the waiting thread). */
    private volatile long fEventsRead;

    private static JsonObject failed(String reason) {
        JsonObject failed = new JsonObject();
        failed.addProperty("available", false);
        failed.addProperty("reason", reason);
        return failed;
    }

    private JsonObject run() {
        /*
         * Read from the trace start even for a window: fds opened before the
         * window must already be in the fd table when the window begins.
         */
        TmfTimeRange range = new TmfTimeRange(
                TmfTimestamp.fromNanos(fTraceStart),
                TmfTimestamp.fromNanos(fWindowEnd));

        TmfEventRequest request = new TmfEventRequest(ITmfEvent.class, range,
                0, ITmfEventRequest.ALL_DATA,
                ITmfEventRequest.ExecutionType.FOREGROUND) {
            @Override
            public void handleData(ITmfEvent event) {
                super.handleData(event);
                fEventsRead++;
                handleEvent(event);
            }
        };

        fTrace.sendRequest(request);

        /*
         * Wait, but not forever: if Trace Compass's event reader dies (seen:
         * OutOfMemoryError with a 512 MB heap on a 2 GB trace), the request
         * never completes and a plain waitForCompletion() hangs for good.
         */
        long lastCount = -1;
        long lastProgress = System.nanoTime();
        try {
            while (!request.isCompleted()) {
                Thread.sleep(2_000);
                long count = fEventsRead;
                if (count != lastCount) {
                    lastCount = count;
                    lastProgress = System.nanoTime();
                } else if (System.nanoTime() - lastProgress > STALL_LIMIT_NS) {
                    request.cancel();
                    return failed(String.format(Locale.ROOT,
                            "Reading the trace's events stopped making progress after %,d events (no new event for %d s). "
                                    + "Trace Compass's event reader most likely ran out of memory: raise its heap (-Xmx, "
                                    + "e.g. -Xmx8g in the launch configuration's VM arguments) and restart it.",
                            count, STALL_LIMIT_NS / 1_000_000_000L));
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            request.cancel();
            return failed("Interrupted while reading events.");
        }
        if (request.isCancelled() || request.isFailed()) {
            return failed("Reading the trace's events was cancelled or failed after " + fEventsRead + " events.");
        }

        if (!fProcessMode) {
            return fActivities.get(fTid).buildResult();
        }
        JsonObject result = new JsonObject();
        result.addProperty("available", true);
        JsonObject processes = new JsonObject();
        for (Activity activity : fActivities.values()) {
            processes.add(String.valueOf(activity.fTid), activity.buildResult());
        }
        result.add("processes", processes);
        JsonObject counts = new JsonObject();
        fEventCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .forEach(entry -> counts.addProperty(entry.getKey(), entry.getValue()));
        result.add("event_counts", counts);
        result.addProperty("event_count", fEventCount);
        result.add("interrupts_by_cpu", interruptsJson());
        result.addProperty("timer_start_events_recorded", fSawHrtimerStart);
        JsonArray bins = new JsonArray();
        for (long count : fEventBins) {
            bins.add(count);
        }
        result.add("event_bins", bins);
        result.addProperty("event_bins_start_ns", fWindowStart);
        result.addProperty("event_bin_ns", Math.max(1, (fWindowEnd - fWindowStart + 1) / EVENT_BINS));
        return result;
    }

    // ------------------------------------------------------------------
    // Event handling
    // ------------------------------------------------------------------

    private void handleEvent(ITmfEvent event) {
        String name = event.getName();
        String host = event.getTrace().getHostId();
        long ts = event.getTimestamp().toNanos();
        if (fProcessMode && ts >= fWindowStart && ts <= fWindowEnd) {
            fEventCounts.merge(name, 1L, Long::sum);
            fEventCount++;
            int bin = (int) Math.min(EVENT_BINS - 1,
                    (ts - fWindowStart) * EVENT_BINS / Math.max(1, fWindowEnd - fWindowStart + 1));
            fEventBins[bin]++;
        }

        switch (name) {
        case "sched_switch":
            Long next = longField(event, "next_tid");
            Integer cpu = cpuOf(event);
            if (next != null && cpu != null) {
                fCurrentTid.put(host + "/" + cpu, next.intValue());
            }
            return;
        case "sched_process_fork":
            handleFork(event, host);
            return;
        case "lttng_statedump_process_state":
            Long sdTid = longField(event, "tid");
            Long sdPid = longField(event, "pid");
            if (sdTid != null && sdPid != null) {
                fPidOfTid.put(host + "/" + sdTid, sdPid.intValue());
            }
            return;
        case "lttng_statedump_file_descriptor":
            handleStatedumpFd(event, host);
            return;
        case "sched_process_exit":
            handleProcessExit(event, host, ts);
            return;
        case "sched_migrate_task":
            handleMigration(event, host, ts);
            return;
        case "sched_waking":
            handleWaking(event, host, ts);
            return;
        case "irq_handler_entry":
        case "irq_handler_exit":
        case "irq_softirq_entry":
        case "irq_softirq_exit":
            handleInterrupt(event, host, ts, name);
            return;
        case "timer_hrtimer_start":
        case "timer_hrtimer_expire_entry":
        case "timer_hrtimer_cancel":
            handleHrtimer(event, host, ts, name);
            return;
        case "signal_generate":
        case "signal_deliver":
            handleSignal(event, host, ts, name.equals("signal_deliver"));
            return;
        default:
            break;
        }

        boolean entry = name.startsWith("syscall_entry_");
        boolean exit = name.startsWith("syscall_exit_");

        if (!entry && !exit) {
            return;
        }

        Integer tid = currentTid(event, host, ts);

        if (tid == null) {
            return;
        }

        String syscall = name.substring(entry ? 14 : 13);
        String threadKey = host + "/" + tid;

        if (entry) {
            fPending.put(threadKey, new Pending(syscall, event));

            /* Calls that never return. */
            if (syscall.equals("exit_group") || syscall.equals("exit")) {
                fPending.remove(threadKey);
                handleSyscall(host, tid, syscall, event, null);
            }
            return;
        }

        Pending pending = fPending.remove(threadKey);

        if (pending == null || !pending.name.equals(syscall)) {
            return;
        }

        handleSyscall(host, tid, syscall, pending.entry, event);
    }

    private void handleFork(ITmfEvent event, String host) {
        Long parentPid = longField(event, "parent_pid");
        Long childTid = longField(event, "child_tid");
        Long childPid = longField(event, "child_pid");

        if (childTid == null || childPid == null) {
            return;
        }

        fPidOfTid.put(host + "/" + childTid, childPid.intValue());
        long ts = event.getTimestamp().toNanos();
        if (fProcessMode && childTid.equals(childPid) && ts >= fWindowStart && ts <= fWindowEnd) {
            Activity child = activity(childPid.intValue());
            if (child != null) {
                child.fForkNs = ts;
                child.fParentPid = parentPid == null ? null : parentPid.intValue();
            }
        }

        if (parentPid != null && !parentPid.equals(childPid)) {
            Map<Long, FdEntry> parentTable =
                    fFdTables.get(host + "/" + parentPid);

            if (parentTable != null) {
                fFdTables.put(host + "/" + childPid,
                        new HashMap<>(parentTable));
            }
        }
    }

    // ------------------------------------------------------------------
    // Migrations, wake-up context, interrupts, timer lateness (process mode)
    // ------------------------------------------------------------------

    private boolean inWindow(long ts) {
        return fProcessMode && ts >= fWindowStart && ts <= fWindowEnd;
    }

    private void handleMigration(ITmfEvent event, String host, long ts) {
        Long tid = longField(event, "tid");
        if (!inWindow(ts) || tid == null) {
            return;
        }
        Activity a = activity(pidOf(host, tid.intValue(), ts));
        if (a != null) {
            a.fMigrations.merge(tid.intValue(), 1L, Long::sum);
        }
    }

    /** CPU -> the softirq vector it is running (2 NET_TX, 3 NET_RX, ...), while one runs. */
    private final Map<String, Long> fSoftirq = new HashMap<>();
    /** CPU -> start of the hard interrupt or softirq it is in. */
    private final Map<String, Long> fIrqStart = new HashMap<>();
    private final Map<String, String> fIrqSource = new HashMap<>();
    /** CPU -> interrupt source -> ns; and CPU -> ns per twentieth of the window. */
    private final Map<Integer, Map<String, Long>> fIrqByCpu = new java.util.TreeMap<>();
    private final Map<Integer, long[]> fIrqBins = new HashMap<>();
    private static final String[] SOFTIRQ_NAMES = {"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
            "TASKLET", "SCHED", "HRTIMER", "RCU"};

    /**
     * Time in hard interrupts and softirqs per CPU, by source (the device's handler name, or the
     * softirq vector), and per twentieth of the window. A softirq interrupted by a hard interrupt is
     * counted for both.
     */
    private void handleInterrupt(ITmfEvent event, String host, long ts, String name) {
        Integer cpu = cpuOf(event);
        if (cpu == null) {
            return;
        }
        boolean soft = name.startsWith("irq_softirq");
        String key = host + "/" + cpu + (soft ? "/soft" : "/hard");
        if (name.endsWith("_entry")) {
            String source;
            if (soft) {
                Long vec = longField(event, "vec");
                source = vec == null ? "softirq" : "softirq " + (vec >= 0 && vec < SOFTIRQ_NAMES.length
                        ? SOFTIRQ_NAMES[vec.intValue()] : String.valueOf(vec));
                if (vec != null) {
                    fSoftirq.put(host + "/" + cpu, vec);
                }
            } else {
                String handler = stringField(event, "name");
                Long irq = longField(event, "irq");
                source = "irq " + (irq == null ? "?" : irq) + (handler == null ? "" : " (" + handler + ")");
            }
            fIrqStart.put(key, ts);
            fIrqSource.put(key, source);
            return;
        }
        if (soft) {
            fSoftirq.remove(host + "/" + cpu);
        }
        Long start = fIrqStart.remove(key);
        String source = fIrqSource.remove(key);
        if (start == null || !fProcessMode) {
            return;
        }
        long s = Math.max(start, fWindowStart);
        long e = Math.min(ts, fWindowEnd);
        if (e <= s) {
            return;
        }
        fIrqByCpu.computeIfAbsent(cpu, k -> new HashMap<>()).merge(source, e - s, Long::sum);
        long[] bins = fIrqBins.computeIfAbsent(cpu, k -> new long[20]);
        long length = Math.max(1, fWindowEnd - fWindowStart);
        bins[(int) Math.min(19, (s - fWindowStart) * 20 / length)] += e - s;
    }

    /**
     * A wake-up issued while a CPU processes received network packets (NET_RX softirq): the thread
     * running on that CPU is the context. On loopback, the receive is processed in the sender's
     * context, so a local process there means the other end is on this machine; the idle task means
     * the packet came from a network device (another machine).
     */
    private void handleWaking(ITmfEvent event, String host, long ts) {
        Long target = longField(event, "tid");
        Integer cpu = cpuOf(event);
        if (!inWindow(ts) || target == null || cpu == null) {
            return;
        }
        Long vec = fSoftirq.get(host + "/" + cpu);
        if (vec == null || vec != 3) {
            return;
        }
        Integer context = fCurrentTid.get(host + "/" + cpu);
        Activity a = activity(pidOf(host, target.intValue(), ts));
        if (a != null) {
            a.fNetworkWakeContext.merge(context == null ? -1 : context, 1L, Long::sum);
        }
    }

    /** hrtimer -> {softexpires, expires, tid} while armed. */
    private final Map<String, long[]> fArmedTimers = new HashMap<>();
    private boolean fSawHrtimerStart;

    /**
     * Timer lateness, when the trace records timer_hrtimer_start (requested expiry, and the latest
     * expiry the timer slack allows): how late each timer armed by a thread fired against the time it
     * asked for.
     */
    private void handleHrtimer(ITmfEvent event, String host, long ts, String name) {
        Long timer = longField(event, "hrtimer");
        if (timer == null) {
            return;
        }
        String key = host + "/" + timer;
        if (name.equals("timer_hrtimer_start")) {
            fSawHrtimerStart = true;
            Long soft = longField(event, "softexpires");
            Long hard = longField(event, "expires");
            Integer tid = currentTid(event, host, ts);
            if (soft != null && hard != null && tid != null) {
                fArmedTimers.put(key, new long[] {soft, hard, tid});
            }
            return;
        }
        long[] armed = fArmedTimers.remove(key);
        if (armed == null || name.equals("timer_hrtimer_cancel") || !inWindow(ts)) {
            return;
        }
        Long now = longField(event, "now");
        if (now == null) {
            return;
        }
        int tid = (int) armed[2];
        Activity a = activity(pidOf(host, tid, ts));
        if (a != null) {
            long[] stats = a.fTimerLateness.computeIfAbsent(tid, k -> new long[LATENCY_BUCKETS + 3]);
            long late = Math.max(0, now - armed[0]);
            stats[latencyBucket(Math.max(1, late))]++;
            stats[LATENCY_BUCKETS] = Math.max(stats[LATENCY_BUCKETS], late);
            stats[LATENCY_BUCKETS + 1] += armed[1] - armed[0];
            stats[LATENCY_BUCKETS + 2]++;
        }
    }

    // ------------------------------------------------------------------
    // Return values: errors, empty polls, connection attempts, futex addresses
    // ------------------------------------------------------------------

    private static final java.util.Set<String> POLL_CALLS = java.util.Set.of("poll", "ppoll", "select", "pselect6",
            "epoll_wait", "epoll_pwait", "epoll_pwait2");
    private static final java.util.Set<Integer> FUTEX_WAITS = java.util.Set.of(0, 6, 9, 11, 13);
    private static final java.util.Set<Integer> FUTEX_WAKES = java.util.Set.of(1, 3, 4, 5, 7, 10, 12);

    private static final Map<Integer, String> ERRNO = Map.ofEntries(
            Map.entry(1, "EPERM"), Map.entry(2, "ENOENT"), Map.entry(4, "EINTR"), Map.entry(9, "EBADF"),
            Map.entry(11, "EAGAIN"), Map.entry(12, "ENOMEM"), Map.entry(13, "EACCES"), Map.entry(14, "EFAULT"),
            Map.entry(17, "EEXIST"), Map.entry(20, "ENOTDIR"), Map.entry(21, "EISDIR"), Map.entry(22, "EINVAL"),
            Map.entry(25, "ENOTTY"), Map.entry(32, "EPIPE"), Map.entry(38, "ENOSYS"), Map.entry(61, "ENODATA"),
            Map.entry(62, "ETIME"), Map.entry(101, "ENETUNREACH"), Map.entry(104, "ECONNRESET"),
            Map.entry(107, "ENOTCONN"), Map.entry(110, "ETIMEDOUT"), Map.entry(111, "ECONNREFUSED"),
            Map.entry(113, "EHOSTUNREACH"), Map.entry(115, "EINPROGRESS"), Map.entry(512, "ERESTARTSYS"),
            Map.entry(516, "ERESTART_RESTARTBLOCK"));

    static String errnoName(long errno) {
        return ERRNO.getOrDefault((int) errno, "errno " + errno);
    }

    /** thread -> end of a non-blocking connect that returned EINPROGRESS, waiting for its poll. */
    private final Map<String, Long> fPendingConnect = new HashMap<>();

    private void recordResult(Activity a, String host, int tid, String syscall, ITmfEvent entry, Long ret,
            long start, long end) {
        String threadKey = host + "/" + tid;
        if (ret != null) {
            if (ret < 0) {
                a.fErrors.computeIfAbsent(syscall, k -> new HashMap<>()).merge(errnoName(-ret), 1L, Long::sum);
            } else if (ret == 0 && POLL_CALLS.contains(syscall)) {
                a.fZeroReturns.merge(syscall, 1L, Long::sum);
            }
        }
        if (syscall.equals("connect")) {
            if (ret != null && ret == -115) {
                fPendingConnect.put(threadKey, end);
            } else {
                a.recordConnect(tid, end - start, ret == null ? "unknown" : ret == 0 ? "connected"
                        : "failed: " + errnoName(-ret));
            }
        } else if (POLL_CALLS.contains(syscall)) {
            Long connected = fPendingConnect.remove(threadKey);
            if (connected != null && start - connected <= 2_000_000L) {
                a.recordConnect(tid, end - start, ret == null ? "unknown" : ret == 0
                        ? "timed out: no answer from the other side" : ret > 0 ? "answered (connected or refused)"
                                : "failed: " + errnoName(-ret));
            }
        } else if (fPendingConnect.containsKey(threadKey) && start - fPendingConnect.get(threadKey) > 2_000_000L) {
            fPendingConnect.remove(threadKey);
        }
        if (syscall.equals("futex")) {
            Long uaddr = longField(entry, "uaddr");
            Long op = longField(entry, "op");
            if (uaddr != null && op != null) {
                int base = (int) (op & 0x7f);
                FutexStat stat = a.fFutex.computeIfAbsent(uaddr, k -> new FutexStat());
                if (FUTEX_WAITS.contains(base)) {
                    long[] waits = stat.waiters.computeIfAbsent(tid, k -> new long[2]);
                    waits[0]++;
                    waits[1] += end - start;
                } else if (FUTEX_WAKES.contains(base)) {
                    stat.wakers.merge(tid, 1L, Long::sum);
                }
            }
        }
    }

    private static final class FutexStat {
        final Map<Integer, long[]> waiters = new HashMap<>();
        final Map<Integer, Long> wakers = new HashMap<>();
    }

    private String threadName(int tid) {
        String name = fKernel == null ? null : KernelThreadInformationProvider.getExecutableName(fKernel, tid);
        return name == null ? "?" : name;
    }

    /** Interrupt time per CPU over the window (process mode), for the result. */
    private JsonObject interruptsJson() {
        JsonObject result = new JsonObject();
        long length = Math.max(1, fWindowEnd - fWindowStart);
        for (Map.Entry<Integer, Map<String, Long>> entry : fIrqByCpu.entrySet()) {
            long total = entry.getValue().values().stream().mapToLong(Long::longValue).sum();
            JsonObject cpu = new JsonObject();
            cpu.addProperty("total_ms", total / 1e6);
            cpu.addProperty("percent_of_window", total * 100.0 / length);
            JsonObject sources = new JsonObject();
            entry.getValue().entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(4)
                    .forEach(source -> sources.addProperty(source.getKey(), source.getValue() / 1e6));
            cpu.add("by_source_ms", sources);
            JsonArray bins = new JsonArray();
            for (long ns : fIrqBins.getOrDefault(entry.getKey(), new long[20])) {
                bins.add(ns * 100.0 / (length / 20.0));
            }
            cpu.add("percent_per_twentieth", bins);
            result.add(String.valueOf(entry.getKey()), cpu);
        }
        return result;
    }

    /** The end of a process: its leader thread (TID = PID) exits. */
    private void handleProcessExit(ITmfEvent event, String host, long ts) {
        Long tid = longField(event, "tid");
        if (!fProcessMode || tid == null || ts < fWindowStart || ts > fWindowEnd) {
            return;
        }
        if (pidOf(host, tid.intValue(), ts) != tid.intValue()) {
            return;
        }
        Activity a = activity(tid.intValue());
        if (a != null) {
            a.fEndNs = ts;
        }
    }

    /**
     * A signal that ends a process by default (SIGSEGV, SIGABRT, SIGKILL, ...), generated for a
     * process (signal_generate's pid is the target thread) or delivered to it with the default
     * action (signal_deliver, in the target's context, sa_handler 0). Kept per process to tell
     * how a process that never called exit ended.
     */
    private void handleSignal(ITmfEvent event, String host, long ts, boolean deliver) {
        if (!fProcessMode || ts < fWindowStart || ts > fWindowEnd) {
            return;
        }
        Long sig = longField(event, "sig");
        if (sig == null || !FATAL_SIGNALS.containsKey(sig.intValue())) {
            return;
        }
        Integer target;
        if (deliver) {
            Long handler = longField(event, "sa_handler");
            if (handler != null && handler != 0) {
                return; /* the program handles it */
            }
            target = currentTid(event, host, ts);
        } else {
            Long pid = longField(event, "pid");
            target = pid == null ? null : pid.intValue();
        }
        if (target == null) {
            return;
        }
        Activity a = activity(pidOf(host, target, ts));
        if (a != null) {
            a.fSignal = sig.intValue();
            a.fSignalNs = ts;
            a.fSignalDelivered |= deliver;
        }
    }

    /** Signals whose default action ends the process, by number (x86-64 Linux). */
    private static final Map<Integer, String> FATAL_SIGNALS = Map.ofEntries(
            Map.entry(1, "SIGHUP"), Map.entry(2, "SIGINT"), Map.entry(3, "SIGQUIT"),
            Map.entry(4, "SIGILL"), Map.entry(5, "SIGTRAP"), Map.entry(6, "SIGABRT"),
            Map.entry(7, "SIGBUS"), Map.entry(8, "SIGFPE"), Map.entry(9, "SIGKILL"),
            Map.entry(11, "SIGSEGV"), Map.entry(13, "SIGPIPE"), Map.entry(14, "SIGALRM"),
            Map.entry(15, "SIGTERM"), Map.entry(24, "SIGXCPU"), Map.entry(25, "SIGXFSZ"),
            Map.entry(31, "SIGSYS"));

    /** Whether the trace records signal events at all (they are an optional event group). */
    static boolean recordsSignals(ITmfTrace trace) {
        if (trace instanceof org.eclipse.tracecompass.tmf.core.trace.ITmfTraceWithPreDefinedEvents) {
            for (org.eclipse.tracecompass.tmf.core.event.ITmfEventType type
                    : ((org.eclipse.tracecompass.tmf.core.trace.ITmfTraceWithPreDefinedEvents) trace).getContainedEventTypes()) {
                if (type.getName().startsWith("signal_")) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Per-call latency: a log histogram per system call (8 buckets per doubling, ~9% wide)
    // ------------------------------------------------------------------

    private static final int LATENCY_BUCKETS = 8 * 41;

    private static int latencyBucket(long ns) {
        if (ns <= 1) {
            return 0;
        }
        return (int) Math.min(LATENCY_BUCKETS - 1, Math.floor(8 * Math.log(ns) / Math.log(2)));
    }

    /** The middle of a bucket, in ns. */
    private static double bucketNs(int bucket) {
        return Math.pow(2, (bucket + 0.5) / 8.0);
    }

    /** The value at quantile q (0..1) of a latency histogram, in ns. */
    static double quantileNs(long[] histogram, long total, double q) {
        long rank = (long) Math.ceil(q * total);
        long seen = 0;
        for (int i = 0; i < histogram.length; i++) {
            seen += histogram[i];
            if (seen >= Math.max(1, rank)) {
                return bucketNs(i);
            }
        }
        return bucketNs(histogram.length - 1);
    }

    /** The share of calls above {@code ns}. */
    static double shareAboveNs(long[] histogram, long total, double ns) {
        long above = 0;
        for (int i = 0; i < histogram.length; i++) {
            if (bucketNs(i) > ns) {
                above += histogram[i];
            }
        }
        return total == 0 ? 0 : above / (double) total;
    }

    static final String KIND_STORAGE = "storage I/O (reads, writes and syncs of files)";
    static final String KIND_FILE_SYSTEM = "file system calls (open, close, stat, rename, delete)";
    static final String KIND_NETWORK = "network (sockets)";
    static final String KIND_DEVICES = "terminals, devices and other descriptors";
    static final String KIND_MEMORY = "memory management";
    static final String KIND_OTHER = "other calls";
    static final String KIND_PIPES = "waiting for data on pipes";
    static final String KIND_EVENTS = "waiting for events (poll, epoll, select)";
    static final String KIND_SLEEPS = "sleeps and timers";
    static final String KIND_LOCKS = "locks and condition waits (futex)";
    static final String KIND_CHILDREN = "waiting for child processes";
    static final String KIND_SIGNALS = "waiting for signals";

    /** Kinds whose time is waiting for another thread, an event or a time to come (not a request or I/O). */
    static final java.util.Set<String> WAITING_KINDS = java.util.Set.of(KIND_PIPES, KIND_EVENTS, KIND_SLEEPS,
            KIND_LOCKS, KIND_CHILDREN, KIND_SIGNALS);

    /**
     * What a call's time is spent on. Reads and writes go by their descriptor: on a file they are
     * storage I/O, on a socket network, on a pipe a wait for the other end.
     */
    private static String waitKind(String syscall, String category, FdEntry fdEntry) {
        switch (category) {
        case "file read/write":
            String kind = fdEntry == null ? "" : fdEntry.kind;
            switch (kind) {
            case "file":
            case "runtime/loader file":
                return KIND_STORAGE;
            case "socket":
                return KIND_NETWORK;
            case "pipe":
                return KIND_PIPES;
            default:
                return KIND_DEVICES;
            }
        case "file sync":
            return KIND_STORAGE;
        case "file open":
        case "file close":
        case "file metadata":
        case "file create/delete/rename":
            return KIND_FILE_SYSTEM;
        case "network":
            return KIND_NETWORK;
        case "memory management":
            return KIND_MEMORY;
        case "polling/event waiting":
            return KIND_EVENTS;
        case "synchronization (futex)":
            return KIND_LOCKS;
        case "sleep/timers":
            return KIND_SLEEPS;
        case "process/thread management":
            return syscall.startsWith("wait") ? KIND_CHILDREN : KIND_OTHER;
        case "signals":
            return syscall.equals("rt_sigtimedwait") || syscall.equals("rt_sigsuspend") || syscall.equals("pause")
                    ? KIND_SIGNALS : KIND_OTHER;
        default:
            return KIND_OTHER;
        }
    }

    /** Categories whose calls are requests or I/O, where a slow call is a slow request (not idle waiting). */
    private static final java.util.Set<String> LATENCY_CATEGORIES = java.util.Set.of(
            "network", "file read/write", "file sync", "file open", "file metadata",
            "file create/delete/rename", "polling/event waiting");

    private void handleStatedumpFd(ITmfEvent event, String host) {
        Long pid = longField(event, "pid");
        Long fd = longField(event, "fd");
        String path = stringField(event, "filename");
        Long flags = longField(event, "flags");

        if (pid == null || fd == null || path == null) {
            return;
        }

        int intFlags = flags == null ? 0 : flags.intValue();
        fdTable(host, pid.intValue()).putIfAbsent(fd,
                newFdEntry(fd, path, intFlags, true));
    }

    private void handleSyscall(String host, int tid, String syscall,
            ITmfEvent entry, ITmfEvent exit) {
        int pid = pidOf(host, tid, entry.getTimestamp().toNanos());
        Map<Long, FdEntry> table = fdTable(host, pid);
        Long ret = exit == null ? null : longField(exit, "ret");

        Activity a = fProcessMode ? activity(pid)
                : tid == fTid && (fHost == null || fHost.equals(host)) ? fActivities.get(fTid)
                : null;
        boolean requested = a != null;
        long start = entry.getTimestamp().toNanos();
        long end = exit == null ? start : exit.getTimestamp().toNanos();
        boolean inWindow = requested && start >= fWindowStart &&
                start <= fWindowEnd;

        if (requested && fHost == null) {
            fHost = host;
        }

        if (!fProcessMode && !requested && start >= fWindowStart && start <= fWindowEnd &&
                pid == pidOf(host, fTid, start)) {
            fActivities.get(fTid).recordPeerUse(table, tid, syscall, entry, ret);
        }
        if (inWindow && fProcessMode) {
            a.fThreads.add(tid);
        }

        FdEntry fdEntry = null;
        String step = null;
        String stepTarget = null;
        String stepDetail = null;
        String stepKind = null;
        long stepBytes = 0;

        switch (syscall) {
        case "open":
        case "openat":
        case "openat2":
        case "creat": {
            String path = stringField(entry, "filename");
            Long flags = longField(entry, "flags");
            int intFlags = syscall.equals("creat") ? O_CREAT | O_WRONLY | O_TRUNC
                    : flags == null ? 0 : flags.intValue();

            if (path == null) {
                break;
            }

            if (ret != null && ret >= 0) {
                fdEntry = newFdEntry(ret, path, intFlags, false);
                table.put(ret, fdEntry);
            }

            if (inWindow) {
                Target target = fdEntry != null ? a.targetOf(fdEntry)
                        : a.target(path, classifyPath(path));
                if (fdEntry != null) {
                    target.opens++;
                    target.openMode = describeOpenFlags(intFlags);
                    step = "open";
                    stepDetail = target.openMode;
                } else {
                    target.failedOpens++;
                    step = "failed open";
                    stepDetail = ret == null ? null : "error " + (-ret);
                }
                a.touch(target, start);
                stepTarget = target.label;
                stepKind = target.kind;
            }
            break;
        }
        case "dup":
        case "dup2":
        case "dup3":
        case "fcntl": {
            Long oldFd = longField(entry, syscall.equals("dup") ? "fildes"
                    : syscall.equals("fcntl") ? "fd" : "oldfd");
            Long cmd = longField(entry, "cmd");

            if (syscall.equals("fcntl") &&
                    (cmd == null || (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC))) {
                fdEntry = inWindow ? lookup(table, entry, "fd") : null;
                if (inWindow && fdEntry != null) {
                    a.targetOf(fdEntry).otherOps++;
                    a.touch(a.targetOf(fdEntry), start);
                }
                break;
            }

            if (oldFd != null && ret != null && ret >= 0) {
                FdEntry source = table.get(oldFd);
                if (source != null) {
                    table.put(ret, new FdEntry(source.label, source.kind,
                            false));
                }
            }
            break;
        }
        case "socket":
        case "accept":
        case "accept4":
            if (ret != null && ret >= 0) {
                String label = "socket fd " + ret + " (" +
                        describeSocket(entry) + ")";
                table.put(ret, new FdEntry(label, "socket", false));
                if (inWindow) {
                    Target target = a.target(label, "socket");
                    a.touch(target, start);
                    step = syscall.equals("socket") ? "create socket"
                            : "accept connection";
                    stepTarget = target.label;
                }
            }
            break;
        case "pipe":
        case "pipe2":
            if (exit != null) {
                long[] fds = longArrayField(exit, "fildes");
                if (fds != null && fds.length == 2) {
                    String label = "pipe (read end fd " + fds[0] + ", write end fd " + fds[1] + ")";
                    table.put(fds[0], new FdEntry(label, "pipe", false));
                    table.put(fds[1], new FdEntry(label, "pipe", false));
                    if (inWindow) {
                        Target target = a.target(label, "pipe");
                        a.touch(target, start);
                        step = "create pipe";
                        stepTarget = target.label;
                    }
                }
            }
            break;
        case "read":
        case "pread64":
        case "readv":
        case "preadv":
        case "preadv2":
        case "recvfrom":
        case "recvmsg":
            fdEntry = inWindow ? lookup(table, entry, "fd") : null;
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).reads++;
                if (ret != null && ret > 0) {
                    a.targetOf(fdEntry).bytesRead += ret;
                    stepBytes = ret;
                }
                a.touch(a.targetOf(fdEntry), start);
                step = "read";
                stepTarget = a.targetOf(fdEntry).label;
            }
            break;
        case "write":
        case "pwrite64":
        case "writev":
        case "pwritev":
        case "pwritev2":
        case "sendto":
        case "sendmsg":
            fdEntry = inWindow ? lookup(table, entry, "fd") : null;
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).writes++;
                if (ret != null && ret > 0) {
                    a.targetOf(fdEntry).bytesWritten += ret;
                    stepBytes = ret;
                }
                a.touch(a.targetOf(fdEntry), start);
                step = "write";
                stepTarget = a.targetOf(fdEntry).label;
            }
            break;
        case "fsync":
        case "fdatasync":
        case "sync_file_range":
            fdEntry = inWindow ? lookup(table, entry, "fd") : null;
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).syncs++;
                a.targetOf(fdEntry).syncNs += end - start;
                a.touch(a.targetOf(fdEntry), start);
                step = "flush to disk (" + syscall + ")";
                stepTarget = a.targetOf(fdEntry).label;
            }
            break;
        case "close": {
            Long fd = longField(entry, "fd");
            fdEntry = fd == null ? null : table.get(fd);
            if (fd != null && (ret == null || ret == 0)) {
                table.remove(fd);
            }
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).closes++;
                a.touch(a.targetOf(fdEntry), start);
                step = "close";
                stepTarget = a.targetOf(fdEntry).label;
            }
            break;
        }
        case "connect":
        case "bind":
        case "listen":
        case "shutdown":
            fdEntry = inWindow ? lookup(table, entry, "fd") : null;
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).otherOps++;
                a.touch(a.targetOf(fdEntry), start);
                step = syscall;
                stepTarget = a.targetOf(fdEntry).label;
            }
            break;
        case "unlink":
        case "unlinkat":
        case "mkdir":
        case "mkdirat":
        case "rmdir":
        case "truncate": {
            String path = stringField(entry, "pathname");
            if (path == null) {
                path = stringField(entry, "path");
            }
            if (inWindow && path != null) {
                step = syscall.startsWith("unlink") ? "delete"
                        : syscall.startsWith("mkdir") ? "create directory"
                        : syscall;
                stepTarget = path;
            }
            break;
        }
        case "rename":
        case "renameat":
        case "renameat2": {
            String from = stringField(entry, "oldname");
            String to = stringField(entry, "newname");
            if (inWindow && from != null && to != null) {
                step = "rename";
                stepTarget = from + " -> " + to;
            }
            break;
        }
        case "lseek":
        case "ftruncate":
        case "fstat":
        case "fallocate":
            fdEntry = inWindow ? lookup(table, entry, "fd") : null;
            if (inWindow && fdEntry != null) {
                a.targetOf(fdEntry).otherOps++;
                a.touch(a.targetOf(fdEntry), start);
            }
            break;
        case "execve":
            if (ret != null && ret == 0) {
                table.values().removeIf(candidate -> candidate.cloexec);
            }
            if (inWindow) {
                String program = stringField(entry, "filename");
                a.fExecutedProgram = program;
                a.fExecNs = start;
                step = "run program (execve)";
                stepTarget = program;
            }
            break;
        case "clone":
        case "clone3":
        case "fork":
        case "vfork":
            if (inWindow && ret != null && ret > 0) {
                a.fCreatedThreads.add(ret);
                step = "create thread/process";
                stepTarget = "TID " + ret;
            }
            break;
        case "exit_group":
        case "exit":
            /* In process mode only the end of the process counts. */
            if (inWindow && (!fProcessMode || syscall.equals("exit_group") || tid == pid)) {
                a.fExitCode = longField(entry, "error_code");
                a.fExitSyscall = syscall;
                a.fExitNs = start;
                step = syscall.equals("exit_group")
                        ? "end the whole process (exit_group)"
                        : "thread finished (exit)";
                stepTarget = "status " + a.fExitCode;
            }
            break;
        case "clock_nanosleep":
        case "nanosleep":
            if (inWindow) {
                step = "sleep";
                stepTarget = "timer";
            }
            break;
        case "futex":
            if (inWindow) {
                step = "futex (synchronization)";
                stepTarget = "futex";
            }
            break;
        case "poll":
        case "ppoll":
        case "select":
        case "pselect6":
        case "epoll_wait":
        case "epoll_pwait":
        case "epoll_pwait2":
            if (inWindow) {
                step = "wait for events (" + syscall + ")";
                stepTarget = "file descriptors";
            }
            break;
        default:
            break;
        }

        if (!inWindow) {
            return;
        }

        a.fSyscallCount++;
        long durationNs = end - start;
        String categoryName = CATEGORY.getOrDefault(syscall, "other");
        long[] categoryStat =
                a.fCategoryStats.computeIfAbsent(categoryName, k -> new long[2]);
        categoryStat[0]++;
        categoryStat[1] += durationNs;
        long[] syscallStat =
                a.fSyscallStats.computeIfAbsent(syscall, k -> new long[2]);
        syscallStat[0]++;
        syscallStat[1] += durationNs;
        if (exit != null && LATENCY_CATEGORIES.contains(categoryName)) {
            a.fLatency.computeIfAbsent(syscall, k -> new long[LATENCY_BUCKETS])[latencyBucket(durationNs)]++;
            a.fLatencyMax.merge(syscall, durationNs, Math::max);
        }
        if (fProcessMode) {
            a.fSyscallsByThread.computeIfAbsent(tid, k -> new HashMap<>()).merge(syscall, 1L, Long::sum);
        }
        long[] kindStat = a.fCallTimeByThread.computeIfAbsent(tid, k -> new LinkedHashMap<>())
                .computeIfAbsent(waitKind(syscall, categoryName, fdEntry), k -> new HashMap<>())
                .computeIfAbsent(syscall, k -> new long[2]);
        kindStat[0]++;
        kindStat[1] += durationNs;
        recordResult(a, host, tid, syscall, entry, ret, start, end);

        if (step != null) {
            a.addTimelineStep(start, durationNs, step, stepTarget, stepDetail,
                    stepBytes, stepKind != null ? stepKind
                            : fdEntry == null ? null : fdEntry.kind);
        }
    }

    /**
     * What one owner did: a single thread (thread mode) or every thread of
     * one process (process mode).
     */
    private final class Activity {
        /** The TID in thread mode, the PID in process mode. */
        private final int fTid;
        private final boolean fProcess;
        private final java.util.Set<Integer> fThreads = new java.util.TreeSet<>();
        private Long fForkNs;
        private Integer fParentPid;
        private long fExecNs;

        private final Map<String, Target> fTargets = new LinkedHashMap<>();
        private final List<JsonObject> fTimeline = new ArrayList<>();
        private int fTimelineOmitted;
        private final Map<String, long[]> fCategoryStats = new LinkedHashMap<>();
        private final Map<String, long[]> fSyscallStats = new HashMap<>();
        private int fSyscallCount;
        private String fExecutedProgram;
        private Long fExitCode;
        private String fExitSyscall;
        private long fExitNs;
        private final List<Long> fCreatedThreads = new ArrayList<>();
        /** Process mode: when the process's leader exited (sched_process_exit), or null. */
        private Long fEndNs;
        /** Process mode: the last fatal-by-default signal generated for or delivered to it. */
        private Integer fSignal;
        private long fSignalNs;
        private boolean fSignalDelivered;
        /** Per system call: a histogram of call durations (request and I/O calls only). */
        private final Map<String, long[]> fLatency = new HashMap<>();
        private final Map<String, Long> fLatencyMax = new HashMap<>();
        /** Process mode: TID -> system call -> calls. */
        private final Map<Integer, Map<String, Long>> fSyscallsByThread = new HashMap<>();
        /** TID -> what the call waits on (waitKind) -> system call -> {calls, ns inside the calls}. */
        private final Map<Integer, Map<String, Map<String, long[]>>> fCallTimeByThread = new HashMap<>();
        /** System call -> error name -> calls; poll-like call -> calls that found nothing ready. */
        private final Map<String, Map<String, Long>> fErrors = new HashMap<>();
        private final Map<String, Long> fZeroReturns = new HashMap<>();
        /** Connection attempts: outcome -> {count, wait ns, longest ns}; TID -> attempts. */
        private final Map<String, long[]> fConnects = new LinkedHashMap<>();
        private final Map<Integer, Long> fConnectsByThread = new HashMap<>();
        /** futex address -> its waiters and wakers. */
        private final Map<Long, FutexStat> fFutex = new HashMap<>();
        /** TID -> CPU migrations. */
        private final Map<Integer, Long> fMigrations = new HashMap<>();
        /** Context thread of the NET_RX softirq that woke one of its threads -> wake-ups (0: idle task). */
        private final Map<Integer, Long> fNetworkWakeContext = new HashMap<>();
        /** TID -> lateness histogram of the timers it armed, + {max, slack sum, count}. */
        private final Map<Integer, long[]> fTimerLateness = new HashMap<>();

        void recordConnect(int tid, long waitNs, String outcome) {
            long[] stat = fConnects.computeIfAbsent(outcome, k -> new long[3]);
            stat[0]++;
            stat[1] += waitNs;
            stat[2] = Math.max(stat[2], waitNs);
            fConnectsByThread.merge(tid, 1L, Long::sum);
        }

        /** Errors and empty polls per system call, with a label when a call mostly fails or finds nothing. */
        private JsonArray syscallResults() {
            double seconds = activeSeconds();
            JsonArray result = new JsonArray();
            java.util.Set<String> calls = new java.util.TreeSet<>(fErrors.keySet());
            calls.addAll(fZeroReturns.keySet());
            List<JsonObject> rows = new ArrayList<>();
            for (String syscall : calls) {
                long count = calls(syscall);
                if (count < 20) {
                    continue;
                }
                JsonObject row = new JsonObject();
                row.addProperty("syscall", syscall);
                row.addProperty("calls", count);
                row.addProperty("per_second", count / seconds);
                long errors = 0;
                Map<String, Long> byError = fErrors.getOrDefault(syscall, Map.of());
                JsonObject errorJson = new JsonObject();
                for (Map.Entry<String, Long> error : byError.entrySet()) {
                    errors += error.getValue();
                    errorJson.addProperty(error.getKey(), error.getValue());
                }
                row.add("errors", errorJson);
                row.addProperty("error_percent", errors * 100.0 / count);
                long empty = fZeroReturns.getOrDefault(syscall, 0L);
                if (POLL_CALLS.contains(syscall)) {
                    row.addProperty("found_nothing_ready", empty);
                    row.addProperty("found_nothing_ready_percent", empty * 100.0 / count);
                }
                String main = byError.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("");
                String label;
                boolean benign = main.equals("EAGAIN") || main.equals("EINTR") || main.equals("ETIMEDOUT")
                        || main.equals("EINPROGRESS")
                        || main.startsWith("ERESTART") || syscall.equals("futex");
                if (errors * 2 >= count && count >= 100 && !benign) {
                    label = String.format(Locale.ROOT, "fails most of the time (%.0f%% of calls, mostly %s), %.0f per second: "
                            + "a retry that keeps failing", errors * 100.0 / count, main, count / seconds);
                } else if (POLL_CALLS.contains(syscall) && empty * 10 >= count * 9 && count >= 100 && count / seconds >= 100) {
                    label = String.format(Locale.ROOT, "finds nothing ready %.0f%% of the time, %.0f calls per second: "
                            + "checking over and over for something that is not there", empty * 100.0 / count, count / seconds);
                } else if (errors == 0 && empty == 0) {
                    continue;
                } else {
                    label = "normal (errors or empty results are a small share, or expected)";
                }
                row.addProperty("label", label);
                rows.add(row);
            }
            rows.sort((a, b) -> Long.compare(b.get("calls").getAsLong(), a.get("calls").getAsLong()));
            rows.stream().limit(8).forEach(result::add);
            return result;
        }

        private JsonObject connectsJson() {
            if (fConnects.isEmpty()) {
                return null;
            }
            JsonObject json = new JsonObject();
            long attempts = 0;
            long waited = 0;
            long longest = 0;
            JsonObject outcomes = new JsonObject();
            for (Map.Entry<String, long[]> entry : fConnects.entrySet()) {
                attempts += entry.getValue()[0];
                waited += entry.getValue()[1];
                longest = Math.max(longest, entry.getValue()[2]);
                JsonObject outcome = new JsonObject();
                outcome.addProperty("attempts", entry.getValue()[0]);
                outcome.addProperty("waited_ms", entry.getValue()[1] / 1e6);
                outcome.addProperty("mean_wait_ms", entry.getValue()[1] / 1e6 / entry.getValue()[0]);
                outcomes.add(entry.getKey(), outcome);
            }
            json.addProperty("attempts", attempts);
            json.addProperty("per_second", attempts / activeSeconds());
            json.addProperty("waited_ms", waited / 1e6);
            json.addProperty("longest_wait_ms", longest / 1e6);
            json.add("outcomes", outcomes);
            JsonObject byThread = new JsonObject();
            fConnectsByThread.forEach((tid, count) -> byThread.addProperty(tid + " " + threadName(tid), count));
            json.add("by_thread", byThread);
            json.addProperty("note", "Time spent connecting to another host (a connect call, or the poll that waits for a "
                    + "non-blocking connect): a wait on the network, even though a timeout ends it. The trace does not record "
                    + "the address.");
            return json;
        }

        /** The futex addresses its threads waited on most, and who woke them: a lock they hand around, or a signal. */
        private JsonArray futexJson() {
            double seconds = activeSeconds();
            List<Map.Entry<Long, FutexStat>> rows = new ArrayList<>(fFutex.entrySet());
            java.util.function.ToLongFunction<FutexStat> waitNs = stat -> stat.waiters.values().stream().mapToLong(v -> v[1]).sum();
            rows.removeIf(entry -> entry.getValue().waiters.isEmpty());
            rows.sort((a, b) -> Long.compare(waitNs.applyAsLong(b.getValue()), waitNs.applyAsLong(a.getValue())));
            JsonArray result = new JsonArray();
            for (Map.Entry<Long, FutexStat> entry : rows.subList(0, Math.min(6, rows.size()))) {
                FutexStat stat = entry.getValue();
                long waits = stat.waiters.values().stream().mapToLong(v -> v[0]).sum();
                long ns = waitNs.applyAsLong(stat);
                java.util.Set<Integer> waiters = stat.waiters.keySet();
                long wakesByWaiters = 0;
                long wakes = 0;
                for (Map.Entry<Integer, Long> waker : stat.wakers.entrySet()) {
                    wakes += waker.getValue();
                    if (waiters.contains(waker.getKey())) {
                        wakesByWaiters += waker.getValue();
                    }
                }
                boolean mutexLike = wakes > 0 && wakesByWaiters * 2 >= wakes && waiters.size() >= 2;
                JsonObject row = new JsonObject();
                row.addProperty("address", "0x" + Long.toHexString(entry.getKey()));
                row.addProperty("waits", waits);
                row.addProperty("waits_per_second", waits / seconds);
                row.addProperty("waited_ms", ns / 1e6);
                row.addProperty("mean_wait_ms", ns / 1e6 / Math.max(1, waits));
                JsonArray waiterRows = new JsonArray();
                stat.waiters.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue()[1], a.getValue()[1])).limit(8)
                        .forEach(waiter -> {
                            JsonObject w = new JsonObject();
                            w.addProperty("tid", waiter.getKey());
                            w.addProperty("name", threadName(waiter.getKey()));
                            w.addProperty("waits", waiter.getValue()[0]);
                            w.addProperty("waited_ms", waiter.getValue()[1] / 1e6);
                            waiterRows.add(w);
                        });
                row.add("waiting_threads", waiterRows);
                row.addProperty("waiting_thread_count", waiters.size());
                JsonObject wakerJson = new JsonObject();
                stat.wakers.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(6)
                        .forEach(waker -> wakerJson.addProperty(waker.getKey() + " " + threadName(waker.getKey()), waker.getValue()));
                row.add("woken_by_threads", wakerJson);
                row.addProperty("kind", mutexLike
                        ? "lock-like: the threads waiting on it also release it to each other (a mutex they take turns on)"
                        : "signal-like: other threads wake the waiters (a condition variable, semaphore or event: waiting for "
                                + "work or a result)");
                row.addProperty("contention", mutexLike && waits / seconds >= 100 ? "contended: many waits per second"
                        : mutexLike ? "some" : "not a lock");
                result.add(row);
            }
            return result;
        }

        private JsonObject migrationsJson() {
            if (fMigrations.isEmpty()) {
                return null;
            }
            double seconds = activeSeconds();
            long total = fMigrations.values().stream().mapToLong(Long::longValue).sum();
            JsonObject json = new JsonObject();
            json.addProperty("total", total);
            json.addProperty("per_second", total / seconds);
            JsonArray threads = new JsonArray();
            fMigrations.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(10).forEach(entry -> {
                JsonObject row = new JsonObject();
                double rate = entry.getValue() / seconds;
                row.addProperty("tid", entry.getKey());
                row.addProperty("name", threadName(entry.getKey()));
                row.addProperty("migrations", entry.getValue());
                row.addProperty("per_second", rate);
                row.addProperty("level", rate >= 50 ? "high" : rate >= 5 ? "moderate" : "low");
                threads.add(row);
            });
            json.add("threads", threads);
            json.addProperty("scale", "per thread: low under 5 moves between CPUs per second, high from 50 (a thread that stays put moves less than once a second)");
            return json;
        }

        private JsonObject networkWakeJson() {
            if (fNetworkWakeContext.isEmpty()) {
                return null;
            }
            long total = fNetworkWakeContext.values().stream().mapToLong(Long::longValue).sum();
            JsonObject json = new JsonObject();
            json.addProperty("wake_ups", total);
            long local = 0;
            JsonArray contexts = new JsonArray();
            List<Map.Entry<Integer, Long>> sorted = new ArrayList<>(fNetworkWakeContext.entrySet());
            sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            for (Map.Entry<Integer, Long> entry : sorted) {
                int context = entry.getKey();
                if (context > 0) {
                    local += entry.getValue();
                }
                if (contexts.size() < 6) {
                    JsonObject row = new JsonObject();
                    row.addProperty("context_tid", context);
                    row.addProperty("context", context <= 0 ? "the idle task: a packet from a network device (another machine)"
                            : threadName(context));
                    if (context > 0) {
                        row.addProperty("context_pid", pidOf(fHost == null ? "" : fHost, context, fWindowEnd));
                    }
                    row.addProperty("wake_ups", entry.getValue());
                    contexts.add(row);
                }
            }
            json.add("contexts", contexts);
            json.addProperty("local_percent", local * 100.0 / total);
            json.addProperty("note", "Wake-ups issued while a CPU processed received packets. On loopback the packet is "
                    + "processed in the sender's context, so a local thread here is the other end of the connection, on this "
                    + "machine; the idle task means the packet arrived from a device. A busy CPU's thread can also be an "
                    + "innocent bystander when a device packet arrives while it runs.");
            return json;
        }

        private JsonArray timerLatenessJson() {
            JsonArray result = new JsonArray();
            for (Map.Entry<Integer, long[]> entry : fTimerLateness.entrySet()) {
                long[] stats = entry.getValue();
                long count = stats[LATENCY_BUCKETS + 2];
                if (count < 20) {
                    continue;
                }
                long[] histogram = java.util.Arrays.copyOf(stats, LATENCY_BUCKETS);
                double p50 = quantileNs(histogram, count, 0.5);
                double p99 = quantileNs(histogram, count, 0.99);
                double over1ms = shareAboveNs(histogram, count, 1_000_000);
                JsonObject row = new JsonObject();
                row.addProperty("tid", entry.getKey());
                row.addProperty("name", threadName(entry.getKey()));
                row.addProperty("timers", count);
                row.addProperty("median_late_ms", p50 / 1e6);
                row.addProperty("p99_late_ms", p99 / 1e6);
                row.addProperty("max_late_ms", stats[LATENCY_BUCKETS] / 1e6);
                row.addProperty("percent_late_1ms_or_more", over1ms * 100);
                double slackMs = stats[LATENCY_BUCKETS + 1] / 1e6 / count;
                row.addProperty("mean_timer_slack_ms", slackMs);
                // The kernel lets a timer fire up to its timer slack late (50 us by default for normal
                // threads) to batch wake-ups: lateness of that size is by design, not oversleeping.
                double medianMs = p50 / 1e6;
                String level = medianMs < 0.2 && over1ms < 0.01
                        ? "on time: within about the kernel's default 50 us timer slack, which lets timers fire that late by design"
                        : medianMs < 1 ? "slightly late: a median under 1 ms past the time asked for"
                                : "late: a median of 1 ms or more past the time asked for";
                row.addProperty("level", level);
                if (slackMs > 0.1) {
                    row.addProperty("slack_note", String.format(Locale.ROOT, "its timer slack (%.3f ms) is larger than the "
                            + "default 0.050 ms: the thread or process asked for it (prctl PR_SET_TIMERSLACK) or a cgroup "
                            + "set it, and timers may fire up to that late", slackMs));
                }
                result.add(row);
            }
            return result;
        }

        /* target key -> other TID of the same process -> {reads, bytes read, writes, bytes written} */
        private final Map<String, Map<Integer, long[]>> fPeerUse = new HashMap<>();

        Activity(int tid, boolean process) {
            fTid = tid;
            fProcess = process;
        }

        // ------------------------------------------------------------------
        // Timeline
        // ------------------------------------------------------------------

        private void addTimelineStep(long ts, long durationNs, String op,
                String target, String detail, long bytes,
                String kind) {

            /* Collapse loader/runtime work into one "program startup" step. */
            if ("runtime/loader file".equals(kind)) {
                op = "load shared libraries / runtime files";
                target = "(program startup)";
                detail = null;
            }

            String key = op + "|" + target;
            JsonObject last = fTimeline.isEmpty() ? null
                    : fTimeline.get(fTimeline.size() - 1);

            if (last != null && last.get("key").getAsString().equals(key)) {
                last.addProperty("count", last.get("count").getAsInt() + 1);
                last.addProperty("bytes", last.get("bytes").getAsLong() + bytes);
                last.addProperty("duration_ns",
                        last.get("duration_ns").getAsLong() + durationNs);
                return;
            }

            /* Milestones are rare and define the story; keep them even past the cap. */
            boolean milestone = op.startsWith("run program") || op.startsWith("create thread")
                    || op.equals("rename") || op.equals("delete") || op.startsWith("end the whole process")
                    || op.startsWith("thread finished");
            if (fTimeline.size() >= MAX_TIMELINE_STEPS && !milestone) {
                fTimelineOmitted++;
                return;
            }

            JsonObject step = new JsonObject();
            step.addProperty("key", key);
            step.addProperty("start_ns", ts);
            step.addProperty("offset_ms", (ts - fTraceStart) / 1_000_000.0);
            step.addProperty("operation", op);
            if (target != null) {
                step.addProperty("target", target);
            }
            if (detail != null) {
                step.addProperty("detail", detail);
            }
            step.addProperty("count", 1);
            step.addProperty("bytes", bytes);
            step.addProperty("duration_ns", durationNs);
            fTimeline.add(step);
        }

        // ------------------------------------------------------------------
        // Result
        // ------------------------------------------------------------------

        private JsonObject buildResult() {
            JsonObject result = new JsonObject();
            result.addProperty("available", true);
            result.addProperty(fProcess ? "pid" : "tid", fTid);
            if (fProcess) {
                JsonArray threads = new JsonArray();
                fThreads.forEach(threads::add);
                result.add("threads", threads);
                if (fForkNs != null) {
                    result.addProperty("created_at_offset_ms", (fForkNs - fTraceStart) / 1_000_000.0);
                    if (fParentPid != null) {
                        result.addProperty("parent_pid", fParentPid);
                    }
                }
                if (fExecutedProgram != null) {
                    result.addProperty("program_executed_at_offset_ms", (fExecNs - fTraceStart) / 1_000_000.0);
                }
            }

            String executable = null;
            Integer pid = null;
            if (fKernel != null) {
                executable = KernelThreadInformationProvider.getExecutableName(
                        fKernel, fTid, fWindowEnd);
                pid = KernelThreadInformationProvider.getProcessId(fKernel, fTid,
                        fWindowEnd);
            }
            if (executable != null) {
                result.addProperty("executable", executable);
            }
            if (pid != null && !fProcess) {
                result.addProperty("pid", pid);
            }

            JsonObject window = new JsonObject();
            window.addProperty("windowed", fWindowed);
            window.addProperty("start_ns", fWindowStart);
            window.addProperty("end_ns", fWindowEnd);
            window.addProperty("start_offset_ms",
                    (fWindowStart - fTraceStart) / 1_000_000.0);
            window.addProperty("end_offset_ms",
                    (fWindowEnd - fTraceStart) / 1_000_000.0);
            result.add("window", window);

            result.addProperty("syscall_count", fSyscallCount);
            if (fExecutedProgram != null) {
                result.addProperty("program_executed", fExecutedProgram);
            }
            if (fExitCode != null) {
                result.addProperty("exit_status", fExitCode);
                result.addProperty("exit_kind", fExitSyscall.equals("exit_group")
                        ? "ended the whole process (exit_group)"
                        : "this thread finished; the process kept running (exit)");
                result.addProperty("exited_at_offset_ms",
                        (fExitNs - fTraceStart) / 1_000_000.0);
            }

            JsonArray files = new JsonArray();
            JsonArray streams = new JsonArray();
            JsonArray runtime = new JsonArray();
            JsonArray other = new JsonArray();
            JsonArray threadNames = new JsonArray();

            for (Target target : fTargets.values()) {
                if (!target.touched) {
                    continue;
                }
                JsonObject json = targetJson(target);
                if ("thread name".equals(target.kind)) {
                    json.addProperty("named_tid", namedTid(target.label));
                    threadNames.add(json);
                    continue;
                }
                switch (target.kind) {
                case "file":
                    files.add(json);
                    break;
                case "standard stream":
                case "terminal":
                    streams.add(json);
                    break;
                case "runtime/loader file":
                    runtime.add(json);
                    break;
                default:
                    other.add(json);
                    break;
                }
            }

            result.add("files", files);
            result.add("standard_streams", streams);
            result.add("runtime_loader_files", runtime);
            result.add("sockets_pipes_devices_other", other);
            result.add("thread_names", threadNames);

            JsonArray timeline = new JsonArray();
            for (JsonObject step : fTimeline) {
                step.remove("key");
                step.addProperty("duration_ms",
                        step.get("duration_ns").getAsLong() / 1_000_000.0);
                step.remove("duration_ns");
                timeline.add(step);
            }
            result.add("timeline", timeline);
            result.addProperty("timeline_steps_omitted", fTimelineOmitted);

            JsonArray categories = new JsonArray();
            fCategoryStats.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                    .forEach(entry -> {
                        JsonObject json = new JsonObject();
                        json.addProperty("category", entry.getKey());
                        json.addProperty("calls", entry.getValue()[0]);
                        json.addProperty("total_ms", entry.getValue()[1] / 1_000_000.0);
                        categories.add(json);
                    });
            result.add("syscalls_by_category", categories);

            JsonArray top = new JsonArray();
            fSyscallStats.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                    .limit(10)
                    .forEach(entry -> {
                        JsonObject json = new JsonObject();
                        json.addProperty("syscall", entry.getKey());
                        json.addProperty("calls", entry.getValue()[0]);
                        json.addProperty("total_ms", entry.getValue()[1] / 1_000_000.0);
                        top.add(json);
                    });
            result.add("top_syscalls", top);

            JsonObject counts = new JsonObject();
            fSyscallStats.forEach((name, stat) -> counts.addProperty(name, stat[0]));
            result.add("syscall_counts", counts);

            if (!fCreatedThreads.isEmpty()) {
                JsonArray created = new JsonArray();
                fCreatedThreads.forEach(created::add);
                result.add("created_threads_or_processes", created);
            }

            result.add("rates", rates());
            result.add("syscall_latency", latencies());
            result.add("syscall_results", syscallResults());
            JsonObject connects = connectsJson();
            if (connects != null) {
                result.add("connect_attempts", connects);
            }
            result.add("futex_addresses", futexJson());
            JsonObject migrations = migrationsJson();
            if (migrations != null) {
                result.add("migrations", migrations);
            }
            JsonObject network = networkWakeJson();
            if (network != null) {
                result.add("network_wake_ups", network);
            }
            if (fSawHrtimerStart) {
                result.add("timer_lateness", timerLatenessJson());
            }
            addFileRelations(result, files);
            if (fProcess) {
                result.add("ended", ended());
                JsonObject byThread = new JsonObject();
                fSyscallsByThread.forEach((tid, calls) -> {
                    JsonObject json = new JsonObject();
                    calls.forEach(json::addProperty);
                    byThread.add(String.valueOf(tid), json);
                });
                result.add("syscalls_by_thread", byThread);
            }
            result.add("syscall_time_by_thread", callTimeJson());

            result.addProperty("summary", buildSummary(executable, pid));
            result.addProperty("note",
                    "Decoded from the raw syscall events of this thread (entry " +
                    "arguments and exit return values), with each fd resolved " +
                    "to the path it was opened with. Relative paths are " +
                    "relative to the process's working directory, which the " +
                    "trace does not record. A kernel trace records how many " +
                    "bytes were read or written, not their contents. fds opened " +
                    "before tracing started are resolved from LTTng's statedump " +
                    "when available.");
            return result;
        }

        /** How long the owner was around in the window, in seconds: rates are counts divided by this. */
        private double activeSeconds() {
            long start = fWindowStart;
            if (fForkNs != null) {
                start = Math.max(start, fForkNs);
            }
            long end = fWindowEnd;
            if (fProcess && fEndNs != null) {
                end = Math.min(end, fEndNs);
            } else if (fExitCode != null && fProcess) {
                end = Math.min(end, fExitNs);
            }
            return Math.max(1e-3, (end - start) / 1e9);
        }

        private long calls(String syscall) {
            long[] stat = fSyscallStats.get(syscall);
            return stat == null ? 0 : stat[0];
        }

        /**
         * Calls per second, per kind, each with a level, so the size of a rate is decided here and not
         * by the reader: a costly kind (opening, creating or deleting files, mapping memory, starting
         * threads or programs) is low under 20 per second and high from 100; any other kind is low
         * under 200 per second and high from 2,000.
         */
        private JsonArray rates() {
            double seconds = activeSeconds();
            List<JsonObject> rows = new ArrayList<>();
            for (Map.Entry<String, long[]> entry : fCategoryStats.entrySet()) {
                rows.add(rate(entry.getKey(), entry.getValue()[0], seconds, COSTLY_CATEGORIES.contains(entry.getKey())));
            }
            long created = calls("clone") + calls("clone3") + calls("fork") + calls("vfork");
            if (created > 0) {
                rows.add(rate("threads/processes created (clone/fork)", created, seconds, true));
            }
            long started = calls("execve") + calls("execveat");
            if (started > 0) {
                rows.add(rate("programs started (execve)", started, seconds, true));
            }
            rows.sort((a, b) -> Double.compare(b.get("per_second").getAsDouble(), a.get("per_second").getAsDouble()));
            JsonArray result = new JsonArray();
            rows.forEach(result::add);
            return result;
        }

        private JsonObject rate(String what, long count, double seconds, boolean costly) {
            double perSecond = count / seconds;
            JsonObject json = new JsonObject();
            json.addProperty("what", what);
            json.addProperty("calls", count);
            json.addProperty("per_second", perSecond);
            json.addProperty("level", costly
                    ? perSecond >= 100 ? "high" : perSecond >= 20 ? "moderate" : "low"
                    : perSecond >= 2000 ? "high" : perSecond >= 200 ? "moderate" : "low");
            json.addProperty("scale", costly ? "costly kind: low under 20/s, high from 100/s"
                    : "low under 200/s, high from 2,000/s");
            return json;
        }

        /**
         * The duration distribution of the request and I/O calls (not sleeps or lock waits, whose long
         * calls are idle time): median, p90, p99 and maximum, approximate to about 9%, with a label for
         * whether a small share of calls takes many times the median.
         */
        /**
         * Per thread: the time inside its system calls by what they wait on (waitKind), most time
         * first, each with its calls. TID -> [{kind, waiting, calls, total_ms, syscalls}].
         */
        private JsonObject callTimeJson() {
            JsonObject result = new JsonObject();
            fCallTimeByThread.forEach((tid, kinds) -> {
                List<JsonObject> rows = new ArrayList<>();
                kinds.forEach((kind, calls) -> {
                    long count = 0;
                    long ns = 0;
                    for (long[] stat : calls.values()) {
                        count += stat[0];
                        ns += stat[1];
                    }
                    JsonArray list = new JsonArray();
                    calls.entrySet().stream().sorted((x, y) -> Long.compare(y.getValue()[1], x.getValue()[1])).limit(4)
                            .forEach(call -> {
                                JsonObject json = new JsonObject();
                                json.addProperty("syscall", call.getKey());
                                json.addProperty("calls", call.getValue()[0]);
                                json.addProperty("total_ms", call.getValue()[1] / 1e6);
                                list.add(json);
                            });
                    JsonObject row = new JsonObject();
                    row.addProperty("kind", kind);
                    row.addProperty("waiting", WAITING_KINDS.contains(kind));
                    row.addProperty("calls", count);
                    row.addProperty("total_ms", ns / 1e6);
                    row.add("syscalls", list);
                    rows.add(row);
                });
                rows.sort((x, y) -> Double.compare(y.get("total_ms").getAsDouble(), x.get("total_ms").getAsDouble()));
                JsonArray array = new JsonArray();
                rows.forEach(array::add);
                result.add(String.valueOf(tid), array);
            });
            return result;
        }

        private JsonArray latencies() {
            List<Map.Entry<String, long[]>> rows = new ArrayList<>();
            for (Map.Entry<String, long[]> entry : fLatency.entrySet()) {
                if (calls(entry.getKey()) >= 20) {
                    rows.add(entry);
                }
            }
            rows.sort((a, b) -> Long.compare(fSyscallStats.get(b.getKey())[1], fSyscallStats.get(a.getKey())[1]));
            JsonArray result = new JsonArray();
            for (Map.Entry<String, long[]> entry : rows.subList(0, Math.min(8, rows.size()))) {
                long[] histogram = entry.getValue();
                long total = 0;
                for (long count : histogram) {
                    total += count;
                }
                double p50 = quantileNs(histogram, total, 0.50);
                double p90 = quantileNs(histogram, total, 0.90);
                double p99 = quantileNs(histogram, total, 0.99);
                long max = fLatencyMax.getOrDefault(entry.getKey(), 0L);
                double over10 = shareAboveNs(histogram, total, 10 * p50);
                String tail;
                if (p99 >= 5 * p50 && p99 - p50 >= 1_000_000 && over10 <= 0.10) {
                    tail = "long tail: the slowest 1% of calls take at least 5 times the median";
                } else if (p99 >= 5 * p50 && p99 - p50 >= 1_000_000) {
                    tail = "spread out: more than a tenth of the calls take over 10 times the median (two kinds of call, not a tail)";
                } else if (max >= 10 * p50 && max >= 5_000_000) {
                    tail = "no long tail; only a few isolated slow calls";
                } else {
                    tail = "no long tail";
                }
                JsonObject json = new JsonObject();
                json.addProperty("syscall", entry.getKey());
                json.addProperty("calls", total);
                json.addProperty("median_ms", p50 / 1e6);
                json.addProperty("p90_ms", p90 / 1e6);
                json.addProperty("p99_ms", p99 / 1e6);
                json.addProperty("max_ms", max / 1e6);
                json.addProperty("p99_over_median", p50 <= 0 ? 0 : p99 / p50);
                json.addProperty("percent_over_10x_median", over10 * 100);
                json.addProperty("tail", tail);
                result.add(json);
            }
            return result;
        }

        /**
         * Which files belong to the program: the ones it writes, and the ones under the folders it
         * writes to or runs from (sharing their first three path components), or named relative to
         * its working directory. Files it only reads from anywhere else are listed apart: they are
         * the candidates for activity unrelated to its own work. Also the average bytes per read and
         * write, for telling many tiny calls from a few large ones.
         */
        private void addFileRelations(JsonObject result, JsonArray files) {
            List<String> own = new ArrayList<>();
            if (fExecutedProgram != null) {
                own.add(parentOf(fExecutedProgram));
            }
            for (JsonElement element : files) {
                JsonObject file = element.getAsJsonObject();
                if (written(file) && file.get("name").getAsString().startsWith("/")) {
                    own.add(parentOf(file.get("name").getAsString()));
                }
            }
            int outside = 0;
            int outsideReads = 0;
            Map<String, Integer> folders = new LinkedHashMap<>();
            for (JsonElement element : files) {
                JsonObject file = element.getAsJsonObject();
                String name = file.get("name").getAsString();
                String relation;
                if (written(file)) {
                    relation = "written by the program (its own data or output)";
                } else if (!name.startsWith("/")) {
                    relation = "read, named relative to the program's working directory (its own files)";
                } else if (own.stream().anyMatch(folder -> sharedComponents(folder, name) >= 3)) {
                    relation = "read, under the program's own folders";
                } else {
                    relation = "read, outside the folders the program writes to or runs from";
                    outside++;
                    outsideReads += file.get("reads").getAsInt();
                    folders.merge(parentOf(name), 1, Integer::sum);
                }
                file.addProperty("relation", relation);
                long reads = file.get("reads").getAsLong();
                long writes = file.get("writes").getAsLong();
                if (reads > 0) {
                    file.addProperty("average_bytes_per_read", file.get("bytes_read").getAsLong() / (double) reads);
                }
                if (writes > 0) {
                    file.addProperty("average_bytes_per_write", file.get("bytes_written").getAsLong() / (double) writes);
                }
            }
            JsonObject relations = new JsonObject();
            relations.addProperty("files_outside_own_folders", outside);
            relations.addProperty("reads_of_those_files", outsideReads);
            JsonObject byFolder = new JsonObject();
            folders.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(8)
                    .forEach(entry -> byFolder.addProperty(entry.getKey(), entry.getValue()));
            relations.add("outside_folders", byFolder);
            relations.addProperty("note", "Shared libraries, the loader cache, locale files and /proc or /sys files are "
                    + "program startup or system queries, listed apart (runtime_loader_files, other), not here. The "
                    + "program's own files are the ones it writes and the ones next to them or to its executable.");
            result.add("file_relations", relations);
        }

        private boolean written(JsonObject file) {
            String mode = file.has("open_mode") ? file.get("open_mode").getAsString() : "";
            return file.get("writes").getAsLong() > 0 || mode.contains("write") || mode.contains("created");
        }

        /**
         * How a process ended: its exit status, or the fatal signal that killed it, or, when it ended
         * without calling exit and the trace records no signal events, that the cause cannot be told.
         */
        private JsonObject ended() {
            JsonObject json = new JsonObject();
            json.addProperty("signal_events_recorded", fRecordsSignals);
            if (fExitCode != null) {
                json.addProperty("how", "exited");
                json.addProperty("status", fExitCode);
                json.addProperty("at_offset_ms", (fExitNs - fTraceStart) / 1_000_000.0);
                json.addProperty("text", "exited normally with status " + fExitCode + " (" + fExitSyscall + ")");
            } else if (fEndNs != null) {
                json.addProperty("at_offset_ms", (fEndNs - fTraceStart) / 1_000_000.0);
                if (fSignal != null && fSignalNs <= fEndNs) {
                    String name = FATAL_SIGNALS.getOrDefault(fSignal, "signal " + fSignal);
                    json.addProperty("how", "killed by a signal");
                    json.addProperty("signal", name + " (" + fSignal + ")");
                    json.addProperty("text", "was killed by " + name + " (signal " + fSignal + ")"
                            + (fSignalDelivered ? ", delivered with its default action" : "")
                            + ", without calling exit");
                } else if (fRecordsSignals) {
                    json.addProperty("how", "ended without calling exit");
                    json.addProperty("text", "ended without calling exit, and no fatal signal was recorded for it");
                } else {
                    json.addProperty("how", "ended without calling exit; cause not recorded");
                    json.addProperty("text", "ended without calling exit; this trace records no signal events, so "
                            + "whether a signal (a crash or a kill) ended it cannot be told");
                }
            } else {
                json.addProperty("how", "still running");
                json.addProperty("text", "was still running at the end of the window");
            }
            return json;
        }

        private JsonObject targetJson(Target target) {
            JsonObject json = new JsonObject();
            json.addProperty("name", target.label);
            json.addProperty("kind", target.kind);
            if (!target.openMode.isEmpty()) {
                json.addProperty("open_mode", target.openMode);
            }
            json.addProperty("opens", target.opens);
            if (target.failedOpens > 0) {
                json.addProperty("failed_opens", target.failedOpens);
            }
            json.addProperty("reads", target.reads);
            json.addProperty("bytes_read", target.bytesRead);
            json.addProperty("writes", target.writes);
            json.addProperty("bytes_written", target.bytesWritten);
            json.addProperty("syncs_to_disk", target.syncs);
            json.addProperty("sync_ms", target.syncNs / 1_000_000.0);
            json.addProperty("closes", target.closes);
            JsonArray peers = peersJson(target);
            if (peers.size() > 0) {
                json.add("also_used_by_threads_of_same_process", peers);
            }
            return json;
        }

        private String buildSummary(String executable,
                Integer pid) {
            StringBuilder text = new StringBuilder();
            text.append(fWindowed
                    ? String.format(Locale.ROOT, "Between %.3f ms and %.3f ms " +
                            "after trace start, ",
                            (fWindowStart - fTraceStart) / 1_000_000.0,
                            (fWindowEnd - fTraceStart) / 1_000_000.0)
                    : "Over the whole trace, ");
            text.append(fProcess ? "process PID " : "TID ").append(fTid);
            if (executable != null) {
                text.append(" (").append(executable).append(")");
            }
            if (fProcess) {
                text.append(fThreads.size() > 1 ? ", over its " + fThreads.size() + " threads," : "");
            } else if (pid != null && pid != fTid) {
                text.append(", a thread of PID ").append(pid).append(",");
            }
            text.append(" made ").append(fSyscallCount).append(" system calls.");

            if (fExecutedProgram != null) {
                text.append(" It started the program ").append(fExecutedProgram)
                        .append(" (execve).");
            }

            List<String> fileParts = new ArrayList<>();
            List<String> streamParts = new ArrayList<>();
            int runtimeFiles = 0;
            long runtimeBytes = 0;
            List<String> otherParts = new ArrayList<>();
            List<String> namedThreads = new ArrayList<>();

            for (Target target : fTargets.values()) {
                if (!target.touched) {
                    continue;
                }
                switch (target.kind) {
                case "thread name":
                    namedThreads.add(namedTid(target.label));
                    break;
                case "file":
                    fileParts.add(describeTarget(target));
                    break;
                case "standard stream":
                case "terminal":
                    streamParts.add(describeTarget(target));
                    break;
                case "runtime/loader file":
                    runtimeFiles++;
                    runtimeBytes += target.bytesRead;
                    break;
                default:
                    otherParts.add(describeTarget(target));
                    break;
                }
            }

            if (!fileParts.isEmpty()) {
                text.append(" Its own file activity: ")
                        .append(String.join("; ", fileParts)).append(".");
            }
            if (!streamParts.isEmpty()) {
                text.append(" Standard streams: ")
                        .append(String.join("; ", streamParts)).append(".");
            }
            if (!otherParts.isEmpty()) {
                text.append(" Sockets, pipes and devices: ")
                        .append(String.join("; ", otherParts)).append(".");
            }
            if (!namedThreads.isEmpty()) {
                text.append(" It set the names of thread(s) ")
                        .append(String.join(", ", namedThreads))
                        .append(" (by writing their /proc comm files).");
            }
            if (runtimeFiles > 0) {
                text.append(String.format(Locale.ROOT,
                        " Program startup (dynamic loader/runtime, not the " +
                        "program's own work): opened %d shared-library/runtime " +
                        "file(s) and read %,d bytes from them.",
                        runtimeFiles, runtimeBytes));
            }
            if (!fCreatedThreads.isEmpty()) {
                text.append(" It created ").append(fCreatedThreads.size())
                        .append(" thread(s)/process(es): TIDs ")
                        .append(fCreatedThreads).append(".");
            }

            List<String> nonFile = new ArrayList<>();
            for (Map.Entry<String, long[]> entry : fCategoryStats.entrySet()) {
                if (entry.getKey().startsWith("file") ||
                        entry.getKey().equals("pipes/fd duplication")) {
                    continue;
                }
                nonFile.add(String.format(Locale.ROOT, "%s %d call(s), %.3f ms",
                        entry.getKey(), entry.getValue()[0],
                        entry.getValue()[1] / 1_000_000.0));
            }
            if (!nonFile.isEmpty()) {
                text.append(" Other system calls: ")
                        .append(String.join("; ", nonFile)).append(".");
            }
            if (fExitCode != null) {
                text.append(fExitSyscall.equals("exit_group")
                        ? " It then ended the whole process with status "
                        : " The thread then finished (thread exit, not process " +
                                "exit) with status ").append(fExitCode)
                        .append(".");
            }
            if (fSyscallCount == 0) {
                text.append(" It made no system calls in this range, so any " +
                        "activity was pure computation in user mode or waiting; " +
                        "see the thread's scheduling states for which.");
            }
            return text.toString();
        }

        private String describeTarget(Target target) {
            List<String> parts = new ArrayList<>();
            if (target.opens > 0) {
                parts.add("opened" + (target.opens > 1 ? " " + target.opens + " times" : "") +
                        (target.openMode.isEmpty() ? "" : " " + target.openMode));
            }
            if (target.failedOpens > 0) {
                parts.add("failed to open " + target.failedOpens + " time(s)");
            }
            if (target.writes > 0) {
                parts.add(String.format(Locale.ROOT, "wrote %,d bytes in %d write(s)",
                        target.bytesWritten, target.writes));
            }
            if (target.reads > 0) {
                parts.add(String.format(Locale.ROOT, "read %,d bytes in %d read(s)",
                        target.bytesRead, target.reads));
            }
            if (target.syncs > 0) {
                parts.add(String.format(Locale.ROOT,
                        "flushed it to disk %d time(s) (%.3f ms)", target.syncs,
                        target.syncNs / 1_000_000.0));
            }
            if (target.closes > 0) {
                parts.add("closed it");
            }
            if (parts.isEmpty() && target.otherOps > 0) {
                parts.add(target.otherOps + " other operation(s)");
            }
            String text = target.label + ": " + String.join(", ", parts);
            for (JsonElement element : peersJson(target)) {
                JsonObject peer = element.getAsJsonObject();
                List<String> use = new ArrayList<>();
                if (peer.get("writes").getAsLong() > 0) {
                    use.add(String.format(Locale.ROOT, "wrote %,d bytes to it",
                            peer.get("bytes_written").getAsLong()));
                }
                if (peer.get("reads").getAsLong() > 0) {
                    use.add(String.format(Locale.ROOT, "read %,d bytes from it",
                            peer.get("bytes_read").getAsLong()));
                }
                text += " (TID " + peer.get("tid").getAsInt() +
                        (peer.has("name") ? " " + peer.get("name").getAsString() : "") +
                        " " + String.join(" and ", use) + ")";
            }
            return text;
        }


        private Target target(String label, String kind) {
            return fTargets.computeIfAbsent(kind + "|" + label,
                    k -> new Target(label, kind));
        }

        private void recordPeerUse(Map<Long, FdEntry> table, int tid,
                String syscall, ITmfEvent entry, Long ret) {
            boolean read = syscall.equals("read") || syscall.equals("pread64") ||
                    syscall.equals("readv") || syscall.equals("recvfrom") ||
                    syscall.equals("recvmsg");
            boolean write = syscall.equals("write") || syscall.equals("pwrite64") ||
                    syscall.equals("writev") || syscall.equals("sendto") ||
                    syscall.equals("sendmsg");
            if (!read && !write) {
                return;
            }
            Long fd = longField(entry, "fd");
            FdEntry fdEntry = fd == null ? null : table.get(fd);
            if (fdEntry == null) {
                return;
            }
            long[] use = fPeerUse
                    .computeIfAbsent(fdEntry.kind + "|" + fdEntry.label,
                            k -> new HashMap<>())
                    .computeIfAbsent(tid, k -> new long[4]);
            long bytes = ret != null && ret > 0 ? ret : 0;
            if (read) {
                use[0]++;
                use[1] += bytes;
            } else {
                use[2]++;
                use[3] += bytes;
            }
        }

        private JsonArray peersJson(Target target) {
            JsonArray peers = new JsonArray();
            Map<Integer, long[]> uses = fPeerUse.get(target.kind + "|" + target.label);
            if (uses == null) {
                return peers;
            }
            for (Map.Entry<Integer, long[]> use : uses.entrySet()) {
                JsonObject peer = new JsonObject();
                peer.addProperty("tid", use.getKey());
                String name = fKernel == null ? null
                        : KernelThreadInformationProvider.getExecutableName(
                                fKernel, use.getKey(), fWindowEnd);
                if (name != null) {
                    peer.addProperty("name", name);
                }
                peer.addProperty("reads", use.getValue()[0]);
                peer.addProperty("bytes_read", use.getValue()[1]);
                peer.addProperty("writes", use.getValue()[2]);
                peer.addProperty("bytes_written", use.getValue()[3]);
                peers.add(peer);
            }
            return peers;
        }

        private Target targetOf(FdEntry fdEntry) {
            return target(fdEntry.label, fdEntry.kind);
        }

        private void touch(Target target, long ts) {
            target.touched = true;
            target.firstNs = Math.min(target.firstNs, ts);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * @param inherited
     *            true for fds the process already had (statedump, inherited
     *            across fork), where 0-2 are its standard streams whatever
     *            they point to; false for an fd the process just opened
     */
    private static FdEntry newFdEntry(long fd, String path, int flags,
            boolean inherited) {
        boolean stream = inherited && fd >= 0 && fd <= 2;
        String kind = stream ? "standard stream" : classifyPath(path);
        String label = stream ? streamName(fd) + " (" + path + ")" : path;
        return new FdEntry(label, kind, (flags & O_CLOEXEC) != 0);
    }

    private FdEntry lookup(Map<Long, FdEntry> table, ITmfEvent entry,
            String field) {
        Long fd = longField(entry, field);
        if (fd == null) {
            return null;
        }
        FdEntry fdEntry = table.get(fd);
        if (fdEntry != null) {
            return fdEntry;
        }
        /* Not opened in the trace and not in the statedump. */
        String label = fd <= 2 ? streamName(fd)
                : "fd " + fd + " (opened before the trace or by another thread)";
        String kind = fd <= 2 ? "standard stream" : "unknown fd";
        FdEntry unknown = new FdEntry(label, kind, false);
        table.put(fd, unknown);
        return unknown;
    }

    private static final java.util.Set<String> COSTLY_CATEGORIES = java.util.Set.of(
            "file open", "file create/delete/rename", "memory management");

    private static String parentOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    /** How many leading path components two absolute paths share. */
    private static int sharedComponents(String a, String b) {
        String[] x = a.split("/");
        String[] y = b.split("/");
        int shared = 0;
        for (int i = 1; i < Math.min(x.length, y.length); i++) {
            if (!x[i].equals(y[i])) {
                break;
            }
            shared++;
        }
        return shared;
    }

    private static String namedTid(String commPath) {
        java.util.regex.Matcher matcher = THREAD_COMM.matcher(commPath);
        return matcher.matches() ? matcher.group(2) : commPath;
    }

    private static String streamName(long fd) {
        return fd == 0 ? "stdin" : fd == 1 ? "stdout" : "stderr";
    }

    private static String classifyPath(String path) {
        if (path.startsWith("socket:")) {
            return "socket";
        }
        if (path.startsWith("pipe:")) {
            return "pipe";
        }
        if (path.startsWith("anon_inode:")) {
            return "anonymous inode";
        }
        if (path.startsWith("/dev/pts/") || path.startsWith("/dev/tty")) {
            return "terminal";
        }
        if (path.startsWith("/dev/")) {
            return "device";
        }
        if (THREAD_COMM.matcher(path).matches()) {
            return "thread name";
        }
        if (path.startsWith("/proc/") || path.startsWith("/sys/")) {
            return "kernel pseudo-file";
        }
        if (path.equals("/etc/ld.so.cache") || path.equals("/etc/ld.so.preload") ||
                SHARED_LIBRARY.matcher(path).matches() ||
                path.contains("/locale") || path.contains("/gconv/")) {
            return "runtime/loader file";
        }
        return "file";
    }

    private static String describeOpenFlags(int flags) {
        List<String> parts = new ArrayList<>();
        int access = flags & O_ACCMODE;
        parts.add(access == O_WRONLY ? "write-only"
                : access == O_RDWR ? "read-write" : "read-only");
        if ((flags & O_CREAT) != 0) {
            parts.add((flags & O_EXCL) != 0 ? "created (must not exist)"
                    : "created if missing");
        }
        if ((flags & O_TRUNC) != 0) {
            parts.add("truncated to empty");
        }
        if ((flags & O_APPEND) != 0) {
            parts.add("append");
        }
        if ((flags & O_DIRECTORY) != 0) {
            parts.add("directory");
        }
        return "(" + String.join(", ", parts) + ")";
    }

    private static String describeSocket(ITmfEvent entry) {
        Long family = longField(entry, "family");
        if (family == null) {
            family = longField(entry, "domain");
        }
        if (family == null) {
            return "socket";
        }
        switch (family.intValue()) {
        case 1:
            return "Unix";
        case 2:
            return "IPv4";
        case 10:
            return "IPv6";
        case 16:
            return "netlink";
        default:
            return "family " + family;
        }
    }

    private Activity activity(int pid) {
        if (fOnlyPids != null && !fOnlyPids.contains(pid)) {
            return null;
        }
        return fActivities.computeIfAbsent(pid, key -> new Activity(key, true));
    }

    private Map<Long, FdEntry> fdTable(String host, int pid) {
        return fFdTables.computeIfAbsent(host + "/" + pid, k -> new HashMap<>());
    }

    private int pidOf(String host, int tid, long ts) {
        Integer pid = fPidOfTid.get(host + "/" + tid);
        if (pid == null && fKernel != null) {
            pid = KernelThreadInformationProvider.getProcessId(fKernel, tid, ts);
            if (pid != null) {
                fPidOfTid.put(host + "/" + tid, pid);
            }
        }
        return pid == null ? tid : pid;
    }

    private Integer currentTid(ITmfEvent event, String host, long ts) {
        Integer cpu = cpuOf(event);
        if (cpu == null) {
            return null;
        }
        String key = host + "/" + cpu;
        Integer tid = fCurrentTid.get(key);
        if (tid == null && fKernel != null) {
            tid = KernelThreadInformationProvider.getThreadOnCpu(fKernel, cpu, ts);
            if (tid != null) {
                fCurrentTid.put(key, tid);
            }
        }
        return tid;
    }

    private Integer cpuOf(ITmfEvent event) {
        Object cpu = TmfTraceUtils.resolveEventAspectOfClassForEvent(
                event.getTrace(), TmfCpuAspect.class, event);
        return cpu instanceof Integer ? (Integer) cpu : null;
    }

    private static Long longField(ITmfEvent event, String name) {
        ITmfEventField field = event.getContent().getField(name);
        if (field == null) {
            return null;
        }
        Object value = field.getValue();
        return value instanceof Number ? ((Number) value).longValue() : null;
    }

    private static String stringField(ITmfEvent event, String name) {
        ITmfEventField field = event.getContent().getField(name);
        if (field == null) {
            return null;
        }
        Object value = field.getValue();
        return value instanceof String ? (String) value : null;
    }

    private static long[] longArrayField(ITmfEvent event,
            String name) {
        ITmfEventField field = event.getContent().getField(name);
        if (field == null) {
            return null;
        }
        Object value = field.getValue();
        return value instanceof long[] ? (long[]) value : null;
    }
}
