package org.eclipse.tracecompass.helloworld.ui.views;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.IntFunction;

import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
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
import com.google.gson.JsonObject;

/**
 * Waits that never end: threads of a process still blocked when the trace ends, and a process
 * that stops making progress.
 *
 * The wait analyses built on the execution graph only see waits that ended: a wait is an edge
 * from the vertex where the thread blocked to the vertex where it was woken, and a thread that
 * is never woken has no vertex after it blocked. A hang, a deadlock or a process that never
 * exits is exactly such a wait. This class reads them from the state system instead (the
 * thread's last state interval runs to the end of the trace) and reads the arguments of the
 * system call each thread is blocked in from its entry event, so it can tell a thread that is
 * merely sleeping (a timed sleep or a wait with a timeout ends by itself) from one waiting on
 * something that never happened.
 *
 * Two findings, for the process explainer:
 * <ul>
 * <li>{@code blocked.unfinished}: each thread still blocked at the end of the trace in a wait of
 * at least {@link #MIN_STUCK_NS}, with its system call, arguments, how long, and its earlier
 * (completed) waits for comparison;</li>
 * <li>{@code process.stalled}: the process ran regularly, then none of its threads ran for the
 * rest of the trace.</li>
 * </ul>
 * Both apply only when the window reaches the end of the trace.
 */
final class StuckWaits {

    /** A wait shorter than this at the end of the trace is not reported. */
    static final long MIN_STUCK_NS = 1_000_000_000L;
    /** At most this many threads get their system call's arguments read (one tiny event request each). */
    private static final int MAX_ARG_READS = 12;
    /** Calls that are sleeps by nature: they end by themselves. */
    private static final Set<String> SLEEPS = Set.of("clock_nanosleep", "nanosleep");
    /** Waits whose start lie within this of each other are "about the same moment". */
    private static final long SAME_MOMENT_NS = 1_000_000_000L;

    private StuckWaits() {
    }

    /** One thread's last wait, which had not ended when the trace ended. */
    private static final class Stuck {
        int tid;
        String name;
        String syscall;
        long since;
        long blockedNs;
        JsonObject args;
        String kind;
        String detail;
        String futexKind;
        Long futexAddress;
        int earlierWaits;
        long earlierMedianNs;
        long earlierLongestNs;
        boolean ranBefore;
    }

    static void add(JsonArray findings, ITmfTrace trace, KernelAnalysisModule kernel, AnswerPipeline.History history,
            Collection<Integer> tids, IntFunction<String> nameOf, ExplainWindowView window, JsonObject win,
            String about, int pid, String processName) {
        ITmfStateSystem ss = kernel.getStateSystem();
        if (ss == null) {
            return;
        }
        long end = ss.getCurrentEndTime();
        /* Only a window that reaches the end of the trace can say a wait never ended. */
        if (window.end() < end - 1_000_000L) {
            return;
        }
        long windowNs = Math.max(1, Math.min(window.end(), end) - window.start());

        List<Stuck> stuck = new ArrayList<>();
        Map<Integer, List<long[]>> runs = new LinkedHashMap<>();
        Set<Integer> aliveAtEnd = new HashSet<>();
        for (int tid : tids) {
            int quark = ss.optQuarkAbsolute("Threads", String.valueOf(tid));
            if (quark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                continue;
            }
            List<ITmfStateInterval> intervals = history.intervals(quark, window.start(), window.end());
            List<Long> completed = new ArrayList<>();
            ITmfStateInterval last = null;
            boolean ran = false;
            for (ITmfStateInterval interval : intervals) {
                String state = state(interval);
                if (state.startsWith("RUNNING")) {
                    ran = true;
                    runs.computeIfAbsent(tid, k -> new ArrayList<>()).add(new long[] {
                            Math.max(interval.getStartTime(), window.start()), Math.min(interval.getEndTime(), window.end()) });
                }
                if ("BLOCKED".equals(state) && interval.getEndTime() < end) {
                    completed.add(interval.getEndTime() - interval.getStartTime());
                }
                last = interval;
            }
            if (last != null && last.getEndTime() >= end
                    && !Set.of("NOT_ALIVE", "EXITED", "ZOMBIE", "UNKNOWN").contains(state(last))) {
                aliveAtEnd.add(tid);
            }
            if (last == null || !"BLOCKED".equals(state(last)) || last.getEndTime() < end) {
                continue;
            }
            long since = last.getStartTime();
            if (end - since < MIN_STUCK_NS) {
                continue;
            }
            Stuck s = new Stuck();
            s.tid = tid;
            s.name = nameOf.apply(tid);
            s.since = since;
            s.blockedNs = end - since;
            s.earlierWaits = completed.size();
            completed.sort(Long::compare);
            s.earlierMedianNs = completed.isEmpty() ? 0 : completed.get(completed.size() / 2);
            s.earlierLongestNs = completed.isEmpty() ? 0 : completed.get(completed.size() - 1);
            s.ranBefore = ran;
            int syscallQuark = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "System_call");
            long entry = since;
            if (syscallQuark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                for (ITmfStateInterval call : history.intervals(syscallQuark, since, since)) {
                    if (call.getValue() instanceof String) {
                        s.syscall = (String) call.getValue();
                        entry = call.getStartTime();
                    }
                }
            }
            if (s.syscall != null && stuck.size() < MAX_ARG_READS) {
                s.args = entryArgs(trace, kernel, tid, s.syscall, entry);
            }
            classify(s);
            stuck.add(s);
        }
        if (!stuck.isEmpty()) {
            addUnfinished(findings, stuck, win, about, pid, processName, end, windowNs, window);
        }
        addStalled(findings, stuck, runs, aliveAtEnd, nameOf, win, about, pid, processName, end, windowNs, window);
    }

    /** The window, as the two numbers this class needs (AnswerPipeline's ExplainWindow is not visible here). */
    record ExplainWindowView(long start, long end, long traceStart) {
    }

    private static String state(ITmfStateInterval interval) {
        return AnswerPipeline.controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
    }

    // ------------------------------------------------------------------ the system call's arguments

    /** The fields of the thread's syscall_entry_<call> event at {@code entryNs}, or null. */
    static JsonObject entryArgs(ITmfTrace trace, KernelAnalysisModule kernel, int tid, String call, long entryNs) {
        String wanted = "syscall_entry_" + call;
        JsonObject[] found = { null };
        TmfTimeRange range = new TmfTimeRange(TmfTimestamp.fromNanos(entryNs), TmfTimestamp.fromNanos(entryNs));
        TmfEventRequest request = new TmfEventRequest(ITmfEvent.class, range, 0, ITmfEventRequest.ALL_DATA,
                ITmfEventRequest.ExecutionType.FOREGROUND) {
            @Override
            public void handleData(ITmfEvent event) {
                super.handleData(event);
                if (found[0] != null || !wanted.equals(event.getName())) {
                    return;
                }
                Object cpu = TmfTraceUtils.resolveEventAspectOfClassForEvent(event.getTrace(), TmfCpuAspect.class, event);
                if (cpu instanceof Integer) {
                    Integer on = KernelThreadInformationProvider.getThreadOnCpu(kernel, (Integer) cpu, entryNs);
                    if (on != null && on != tid) {
                        return;
                    }
                }
                JsonObject args = new JsonObject();
                for (ITmfEventField field : event.getContent().getFields()) {
                    Object value = field.getValue();
                    if (value instanceof Number) {
                        args.addProperty(field.getName(), ((Number) value).longValue());
                    } else if (value instanceof String) {
                        args.addProperty(field.getName(), (String) value);
                    }
                }
                found[0] = args;
            }
        };
        trace.sendRequest(request);
        try {
            request.waitForCompletion();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            request.cancel();
        }
        return found[0];
    }

    private static Long arg(JsonObject args, String name) {
        return args != null && args.has(name) && args.get(name).isJsonPrimitive()
                && args.get(name).getAsJsonPrimitive().isNumber() ? args.get(name).getAsLong() : null;
    }

    /**
     * kind: "sleep" (a timed sleep), "timed_wait" (a wait with a timeout: it ends by itself),
     * "wait" (no timeout: it ends only when something else happens), or "unknown".
     */
    private static void classify(Stuck s) {
        String call = s.syscall == null ? "" : s.syscall;
        if (SLEEPS.contains(call)) {
            s.kind = "sleep";
            s.detail = call + " (a timed sleep)";
            return;
        }
        if (s.args == null) {
            s.kind = "unknown";
            s.detail = call.isEmpty() ? "no system call recorded" : call + " (arguments not recorded)";
            return;
        }
        switch (call) {
        case "futex": {
            Long op = arg(s.args, "op");
            Long uaddr = arg(s.args, "uaddr");
            Long utime = arg(s.args, "utime");
            int cmd = op == null ? -1 : (int) (op & 0x7f);
            String opName = switch (cmd) {
            case 0 -> "FUTEX_WAIT";
            case 6 -> "FUTEX_LOCK_PI";
            case 9 -> "FUTEX_WAIT_BITSET";
            case 11 -> "FUTEX_WAIT_REQUEUE_PI";
            case 13 -> "FUTEX_LOCK_PI2";
            default -> op == null ? "futex" : "futex op " + cmd;
            };
            /* glibc: pthread_mutex_lock waits with FUTEX_WAIT (or LOCK_PI); condition variables, barriers
               and semaphores with FUTEX_WAIT_BITSET. A heuristic, said as such. */
            s.futexKind = cmd == 0 || cmd == 6 || cmd == 13 ? "lock" : cmd == 9 || cmd == 11 ? "condition" : null;
            s.futexAddress = uaddr;
            boolean timed = utime != null && utime != 0;
            s.kind = timed ? "timed_wait" : "wait";
            s.detail = String.format(Locale.ROOT, "futex %s on address 0x%x, %s%s", opName,
                    uaddr == null ? 0 : uaddr, timed ? "with a timeout" : "no timeout",
                    "lock".equals(s.futexKind) ? " (the way a mutex lock waits)"
                            : "condition".equals(s.futexKind) ? " (the way a condition variable, barrier or semaphore waits)" : "");
            return;
        }
        case "poll", "ppoll": {
            Long timeout = arg(s.args, "timeout_msecs");
            Long tsp = arg(s.args, "tsp");
            boolean timed = timeout != null ? timeout >= 0 : tsp != null && tsp != 0;
            s.kind = timed ? "timed_wait" : "wait";
            s.detail = call + (timed ? " with a timeout" : " with no timeout");
            return;
        }
        case "epoll_wait", "epoll_pwait", "epoll_pwait2": {
            Long timeout = arg(s.args, "timeout");
            boolean timed = timeout != null && timeout >= 0;
            s.kind = timed ? "timed_wait" : "wait";
            s.detail = call + (timed ? " with a timeout" : " with no timeout");
            return;
        }
        case "select", "pselect6": {
            Long tvp = arg(s.args, "tvp");
            if (tvp == null) {
                tvp = arg(s.args, "tsp");
            }
            boolean timed = tvp != null && tvp != 0;
            s.kind = timed ? "timed_wait" : "wait";
            s.detail = call + (timed ? " with a timeout" : " with no timeout");
            return;
        }
        default: {
            Long fd = arg(s.args, "fd");
            if (fd == null) {
                fd = arg(s.args, "sockfd");
            }
            s.kind = "wait";
            s.detail = fd != null ? String.format(Locale.ROOT, "%s on file descriptor %d", call, fd) : call;
        }
        }
    }

    // ------------------------------------------------------------------ findings

    private static double ms(long ns) {
        return ns / 1_000_000.0;
    }

    private static void addUnfinished(JsonArray findings, List<Stuck> stuck, JsonObject win, String about, int pid,
            String processName, long end, long windowNs, ExplainWindowView window) {
        stuck.sort((a, b) -> Long.compare(a.since, b.since));
        JsonArray rows = new JsonArray();
        List<String> waits = new ArrayList<>();
        List<String> sleeps = new ArrayList<>();
        for (Stuck s : stuck) {
            JsonObject row = new JsonObject();
            row.addProperty("tid", s.tid);
            row.addProperty("name", s.name);
            row.addProperty("syscall", s.syscall);
            row.addProperty("kind", s.kind);
            row.addProperty("what", s.detail);
            if (s.futexAddress != null) {
                row.addProperty("futex_address", String.format(Locale.ROOT, "0x%x", s.futexAddress));
            }
            if (s.args != null) {
                row.add("syscall_arguments", s.args);
            }
            row.addProperty("blocked_since_offset_ms", ms(s.since - window.traceStart()));
            row.addProperty("blocked_ms", ms(s.blockedNs));
            row.addProperty("percent_of_window", s.blockedNs * 100.0 / windowNs);
            row.addProperty("earlier_completed_waits", s.earlierWaits);
            row.addProperty("earlier_wait_median_ms", ms(s.earlierMedianNs));
            row.addProperty("earlier_wait_longest_ms", ms(s.earlierLongestNs));
            row.addProperty("ran_before_this_wait", s.ranBefore);
            rows.add(row);
            String earlier = s.earlierWaits > 0
                    ? String.format(Locale.ROOT, "its %d earlier waits: median %.3f ms, longest %.3f ms",
                            s.earlierWaits, ms(s.earlierMedianNs), ms(s.earlierLongestNs))
                    : s.ranBefore ? "no earlier completed wait" : "it never ran in this window";
            String line = String.format(Locale.ROOT, "TID %d (%s) in %s, since %.3f ms (%.3f ms, %.1f%% of the window; %s)",
                    s.tid, s.name, s.detail, ms(s.since - window.traceStart()), ms(s.blockedNs),
                    s.blockedNs * 100.0 / windowNs, earlier);
            if ("sleep".equals(s.kind) || "timed_wait".equals(s.kind)) {
                sleeps.add(line);
            } else {
                waits.add(line);
            }
        }

        JsonArray caveats = new JsonArray();
        caveats.add("These waits had not ended when the trace ended: no wake-up for them is in the trace, so the "
                + "wait-chain findings (blocked.wakers, process.wait_graph, process.bottleneck) do not include them, "
                + "and they are not one-off startup waits.");
        caveats.add("A thread in a timed sleep or a wait with a timeout ends it by itself; a thread that never ran in "
                + "the window, or waits for input such as a connection or a request, may simply be idle. A thread "
                + "that was active and then never woke up is stuck.");

        /* Threads blocked on futexes from about the same moment, never woken. */
        List<Stuck> futexWaits = new ArrayList<>();
        for (Stuck s : stuck) {
            if ("wait".equals(s.kind) && s.futexAddress != null && s.ranBefore) {
                futexWaits.add(s);
            }
        }
        JsonObject data = new JsonObject();
        data.addProperty("pid", pid);
        data.addProperty("process", processName);
        data.addProperty("trace_end_offset_ms", ms(end - window.traceStart()));
        data.add("threads", rows);
        List<String> notes = new ArrayList<>();
        Map<Long, List<Stuck>> byAddress = new LinkedHashMap<>();
        for (Stuck s : futexWaits) {
            byAddress.computeIfAbsent(s.futexAddress, k -> new ArrayList<>()).add(s);
        }
        for (Map.Entry<Long, List<Stuck>> entry : byAddress.entrySet()) {
            if (entry.getValue().size() > 1) {
                notes.add(String.format(Locale.ROOT, "%s wait on the same futex (0x%x): a lock or condition that was "
                        + "never released or signalled", threadList(entry.getValue()), entry.getKey()));
            }
        }
        List<Stuck> lockWaits = new ArrayList<>();
        for (Stuck s : futexWaits) {
            if ("lock".equals(s.futexKind)) {
                lockWaits.add(s);
            }
        }
        Set<Long> lockAddresses = new HashSet<>();
        lockWaits.forEach(s -> lockAddresses.add(s.futexAddress));
        if (lockWaits.size() >= 2 && lockAddresses.size() >= 2
                && lockWaits.get(lockWaits.size() - 1).since - lockWaits.get(0).since <= SAME_MOMENT_NS) {
            notes.add(String.format(Locale.ROOT, "%s each block, within %.0f ms of each other, in a lock-style futex wait "
                    + "on different addresses and are never woken: consistent with a deadlock (each holding a lock "
                    + "another needs). A kernel trace does not record who holds a lock, so this is the pattern, "
                    + "not a proof", threadList(lockWaits), ms(lockWaits.get(lockWaits.size() - 1).since - lockWaits.get(0).since)));
        }
        if (!notes.isEmpty()) {
            JsonArray list = new JsonArray();
            notes.forEach(list::add);
            data.add("patterns", list);
        }

        StringBuilder claim = new StringBuilder();
        claim.append(String.format(Locale.ROOT, "When the trace ended, %d thread(s) of process %d (%s) were still "
                + "blocked in a wait that had lasted at least %.0f ms and never ended.", stuck.size(), pid, processName,
                ms(MIN_STUCK_NS)));
        if (!waits.isEmpty()) {
            claim.append(" Waiting for something that never happened: ").append(String.join("; ", waits)).append('.');
        }
        if (!sleeps.isEmpty()) {
            claim.append(" Sleeping or waiting with a timeout (ends by itself): ").append(String.join("; ", sleeps)).append('.');
        }
        if (!notes.isEmpty()) {
            claim.append(' ').append(String.join(". ", notes)).append('.');
        }
        findings.add(AnswerPipeline.finding("blocked.unfinished", about, "blocked", claim.toString(), win,
                "tracecompass.state_system+syscall_arguments", data, "high", caveats));
    }

    private static String threadList(List<Stuck> list) {
        List<String> names = new ArrayList<>();
        list.forEach(s -> names.add(String.format(Locale.ROOT, "TID %d (%s)", s.tid, s.name)));
        return String.join(" and ", names);
    }

    /** A thread that ran at least this many times in the window was doing the process's work. */
    private static final int ACTIVE_RUNS = 10;

    /**
     * The process stopped making progress: at least half of its active threads (those that ran at least
     * {@link #ACTIVE_RUNS} times and are still alive at the end) are left in a wait with no timeout that never ended, at least 1 s and at
     * least 20 times their median earlier wait, and the stall covers at least 5% of the window. Whatever
     * the process's other threads still did afterwards (a heartbeat, a watchdog) is reported, not ignored.
     */
    private static void addStalled(JsonArray findings, List<Stuck> stuck, Map<Integer, List<long[]>> runs,
            Set<Integer> aliveAtEnd, IntFunction<String> nameOf, JsonObject win, String about, int pid, String processName, long end,
            long windowNs, ExplainWindowView window) {
        Set<Integer> active = new HashSet<>();
        /* Threads that finished their work and exited are not stuck: only threads still alive at the end count. */
        runs.forEach((tid, list) -> {
            if (list.size() >= ACTIVE_RUNS && aliveAtEnd.contains(tid)) {
                active.add(tid);
            }
        });
        List<Stuck> stuckActive = new ArrayList<>();
        for (Stuck s : stuck) {
            if (active.contains(s.tid) && ("wait".equals(s.kind) || "unknown".equals(s.kind))
                    && s.blockedNs >= Math.max(MIN_STUCK_NS, 20 * s.earlierMedianNs)) {
                stuckActive.add(s);
            }
        }
        if (stuckActive.isEmpty() || stuckActive.size() * 2 < active.size()) {
            return;
        }
        long from = Long.MAX_VALUE;
        for (Stuck s : stuckActive) {
            from = Math.min(from, s.since);
        }
        long stalledNs = end - from;
        if (stalledNs < windowNs / 20) {
            return;
        }
        List<String> stuckNames = new ArrayList<>();
        JsonArray stuckRows = new JsonArray();
        for (Stuck s : stuckActive) {
            stuckNames.add(String.format(Locale.ROOT, "TID %d (%s) in %s", s.tid, s.name, s.detail));
            JsonObject row = new JsonObject();
            row.addProperty("tid", s.tid);
            row.addProperty("name", s.name);
            row.addProperty("what", s.detail);
            stuckRows.add(row);
        }
        /* What the rest of the process still did after the stall began. */
        List<String> after = new ArrayList<>();
        JsonArray afterRows = new JsonArray();
        for (Map.Entry<Integer, List<long[]>> entry : runs.entrySet()) {
            int count = 0;
            long cpu = 0;
            for (long[] run : entry.getValue()) {
                if (run[1] > from) {
                    count++;
                    cpu += run[1] - Math.max(run[0], from);
                }
            }
            boolean isStuck = stuckActive.stream().anyMatch(s -> s.tid == entry.getKey());
            if (count == 0 || isStuck) {
                continue;
            }
            String name = nameOf.apply(entry.getKey());
            after.add(String.format(Locale.ROOT, "TID %d (%s) ran %d time(s), %.3f ms of CPU", entry.getKey(), name,
                    count, ms(cpu)));
            JsonObject row = new JsonObject();
            row.addProperty("tid", entry.getKey());
            row.addProperty("name", name);
            row.addProperty("runs", count);
            row.addProperty("cpu_ms", ms(cpu));
            afterRows.add(row);
        }
        JsonObject data = new JsonObject();
        data.addProperty("pid", pid);
        data.addProperty("process", processName);
        data.addProperty("stalled_since_offset_ms", ms(from - window.traceStart()));
        data.addProperty("stalled_ms", ms(stalledNs));
        data.addProperty("percent_of_window", stalledNs * 100.0 / windowNs);
        data.addProperty("active_threads", active.size());
        data.add("stuck_threads", stuckRows);
        data.add("still_running_after", afterRows);
        JsonArray caveats = new JsonArray();
        caveats.add("A process that is idle on purpose (all its threads waiting for input that does not come) looks "
                + "the same; a process whose working threads are left in waits with no timeout, far longer than "
                + "their earlier waits, is hung.");
        String claim = String.format(Locale.ROOT, "Process %d (%s) stopped making progress at about %.3f ms: %d of its "
                + "%d active threads have been blocked since then, for the last %.3f ms of the trace (%.1f%% of the "
                + "window), in waits with no timeout that never ended: %s. %s", pid, processName,
                ms(from - window.traceStart()), stuckActive.size(), active.size(), ms(stalledNs),
                stalledNs * 100.0 / windowNs, String.join("; ", stuckNames),
                after.isEmpty() ? "No other thread of the process ran after that."
                        : "After that, only: " + String.join("; ", after) + ".");
        findings.add(AnswerPipeline.finding("process.stalled", about, "blocked", claim, win,
                "tracecompass.state_system", data, "high", caveats));
    }

    /**
     * Whether a blocked interval, clipped to a window, runs to the end of the trace: its (inclusive)
     * end is within 1 ms of the state system's end. A window that ends earlier never qualifies.
     */
    static boolean reachesEnd(ITmfStateSystem ss, long intervalEnd) {
        return ss != null && intervalEnd >= ss.getCurrentEndTime() - 1_000_000L;
    }
}
