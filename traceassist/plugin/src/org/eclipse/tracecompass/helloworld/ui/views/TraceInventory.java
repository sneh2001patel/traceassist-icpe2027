package org.eclipse.tracecompass.helloworld.ui.views;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.arr;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.bool;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.dbl;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.num;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.obj;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.str;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The thread finder's view of a trace (thread_finder_design.md, step 1): a
 * compact, deterministic table of the processes that matter and their
 * threads, built from analyses the framework already has. The same trace
 * always gives the same inventory, rows in the same order, so the thread
 * finder sees the same input every time.
 */
final class TraceInventory {

    /** Rows kept, whatever the trace: the finder's input must stay small. */
    private static final int MAX_THREADS = 40;
    private static final int MAX_BACKGROUND = 5;
    /** Wake-ups needed before a thread's period is reported. */
    private static final int MIN_ACTIVATIONS = 20;

    /** One inventory per trace; it is recomputed only when the trace is reopened. */
    private static final Map<ITmfTrace, JsonObject> CACHE =
            Collections.synchronizedMap(new java.util.WeakHashMap<>());

    private TraceInventory() {
    }

    /** The trace's inventory (cached). Never null; {@code available} is false when the kernel analysis is missing. */
    static JsonObject of(ITmfTrace trace) {
        JsonObject cached = CACHE.get(trace);
        if (cached != null) {
            return cached;
        }
        JsonObject inventory = build(trace);
        if (bool(inventory, "available")) {
            CACHE.put(trace, inventory);
        }
        return inventory;
    }

    private static JsonObject build(ITmfTrace trace) {
        JsonObject inventory = new JsonObject();
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        if (kernel == null) {
            inventory.addProperty("available", false);
            inventory.addProperty("reason", "no Linux kernel analysis for this trace");
            return inventory;
        }
        kernel.schedule();
        kernel.waitForCompletion();
        ITmfStateSystem ss = kernel.getStateSystem();
        if (ss == null) {
            inventory.addProperty("available", false);
            inventory.addProperty("reason", "the kernel state system is not available");
            return inventory;
        }
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();

        JsonObject traceRow = new JsonObject();
        traceRow.addProperty("name", trace.getName());
        traceRow.addProperty("duration_ms", (end - start) / 1_000_000.0);
        traceRow.addProperty("event_count", trace.getNbEvents());
        inventory.add("trace", traceRow);

        // Processes and their roles: the whole-trace explainer's process list (its event pass is cached).
        AnswerPipeline.ExplainWindow whole = new AnswerPipeline.ExplainWindow(null, "whole_trace", start, end, null);
        JsonArray processes = new JsonArray();
        List<Integer> workload = new ArrayList<>();
        int background = 0;
        int backgroundOmitted = 0;
        for (JsonElement element : AnswerPipeline.TraceExplainer.explain(trace, whole)) {
            JsonObject finding = element.getAsJsonObject();
            if (!"trace.processes".equals(str(finding, "id"))) {
                continue;
            }
            JsonObject data = obj(obj(finding, "evidence"), "data");
            for (JsonElement processElement : arr(data, "processes")) {
                JsonObject process = processElement.getAsJsonObject();
                String role = str(process, "role");
                if ("tracer".equals(role)) {
                    continue;
                }
                if ("background".equals(role) && background++ >= MAX_BACKGROUND) {
                    backgroundOmitted++;
                    continue;
                }
                JsonObject row = new JsonObject();
                for (String key : new String[] {"pid", "name", "role", "cpu_ms", "cpu_percent_of_busy", "thread_count",
                        "created_at_offset_ms", "exited_at_offset_ms", "exit_status", "program_executed"}) {
                    if (process.has(key)) {
                        row.add(key, process.get(key));
                    }
                }
                processes.add(row);
                if ("workload".equals(role)) {
                    workload.add(process.get("pid").getAsInt());
                }
            }
            backgroundOmitted += (int) num(data, "processes_omitted", 0L);
        }
        inventory.add("processes", processes);
        inventory.addProperty("background_processes_omitted", backgroundOmitted);

        // Threads of the workload processes: state shares, CPUs, lifetime, period (one sweep).
        Map<Integer, Integer> pidOf = new LinkedHashMap<>();
        for (int pid : new TreeSet<>(workload)) {
            for (int tid : AnswerPipeline.ProcessExplainer.threadsOf(kernel, pid, start, end)) {
                pidOf.put(tid, pid);
            }
        }
        Map<Integer, Integer> statusQuark = new HashMap<>();
        Map<Integer, Integer> cpuQuark = new HashMap<>();
        List<Integer> quarks = new ArrayList<>();
        for (int tid : pidOf.keySet()) {
            int status = ss.optQuarkAbsolute("Threads", String.valueOf(tid));
            if (status != ITmfStateSystem.INVALID_ATTRIBUTE) {
                statusQuark.put(tid, status);
                quarks.add(status);
            }
            int cpu = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "Current_cpu_rq");
            if (cpu != ITmfStateSystem.INVALID_ATTRIBUTE) {
                cpuQuark.put(tid, cpu);
                quarks.add(cpu);
            }
        }
        AnswerPipeline.History history = AnswerPipeline.History.load(ss, quarks, start, end);
        List<JsonObject> threads = new ArrayList<>();
        for (Map.Entry<Integer, Integer> entry : pidOf.entrySet()) {
            int tid = entry.getKey();
            Integer quark = statusQuark.get(tid);
            if (quark == null) {
                continue;
            }
            JsonObject row = threadRow(kernel, history, tid, entry.getValue(), quark, cpuQuark.get(tid), start, end);
            if (row != null) {
                threads.add(row);
            }
        }
        int omitted = 0;
        if (threads.size() > MAX_THREADS) {
            // Keep the most active (running + waiting for a CPU), then restore the PID/TID order.
            List<JsonObject> byActivity = new ArrayList<>(threads);
            byActivity.sort((a, b) -> Double.compare(activeMs(b), activeMs(a)));
            List<JsonObject> kept = new ArrayList<>(byActivity.subList(0, MAX_THREADS));
            omitted = threads.size() - MAX_THREADS;
            threads.retainAll(kept);
        }
        JsonArray threadList = new JsonArray();
        threads.forEach(threadList::add);
        inventory.add("threads", threadList);
        inventory.addProperty("threads_omitted", omitted);
        inventory.addProperty("available", true);
        return inventory;
    }

    private static double activeMs(JsonObject row) {
        double lifetime = dbl(row, "lifetime_ms", 0);
        return lifetime * (dbl(row, "running_percent", 0)
                + dbl(row, "waiting_for_cpu_percent", 0)) / 100.0;
    }

    /** One thread: name, lifetime, state shares, CPUs it was queued on, and its period when its wake-ups are regular. */
    private static JsonObject threadRow(KernelAnalysisModule kernel, AnswerPipeline.History history, int tid, int pid,
            int statusQuark, Integer cpuQuark, long start, long end) {
        long running = 0;
        long waiting = 0;
        long blocked = 0;
        long first = Long.MAX_VALUE;
        long last = Long.MIN_VALUE;
        List<Long> wakeups = new ArrayList<>();
        boolean wasBlocked = false;
        for (ITmfStateInterval interval : history.intervals(statusQuark)) {
            ProcessStatus status = ProcessStatus.getStatusFromStateValue(interval.getStateValue());
            if (status == ProcessStatus.NOT_ALIVE || status == ProcessStatus.EXIT || status == ProcessStatus.UNKNOWN
                    || interval.getStateValue().isNull()) {
                wasBlocked = false;
                continue;
            }
            long s0 = Math.max(interval.getStartTime(), start);
            long e0 = Math.min(interval.getEndTime(), end);
            if (e0 < s0) {
                continue;
            }
            long length = e0 - s0 + 1;
            first = Math.min(first, s0);
            last = Math.max(last, e0);
            switch (status) {
            case RUN:
            case RUN_SYTEMCALL:
            case INTERRUPTED:
                running += length;
                break;
            case WAIT_CPU:
                waiting += length;
                break;
            case WAIT_BLOCKED:
                blocked += length;
                break;
            default:
                break;
            }
            if (wasBlocked && status != ProcessStatus.WAIT_BLOCKED) {
                wakeups.add(s0);
            }
            wasBlocked = status == ProcessStatus.WAIT_BLOCKED;
        }
        if (first == Long.MAX_VALUE) {
            return null;
        }
        long alive = Math.max(1, last - first + 1);
        JsonObject row = new JsonObject();
        row.addProperty("tid", tid);
        row.addProperty("pid", pid);
        String name = KernelThreadInformationProvider.getExecutableName(kernel, tid);
        row.addProperty("name", name == null ? "unknown" : name);
        row.addProperty("is_main_thread", tid == pid);
        row.addProperty("lifetime_ms", alive / 1_000_000.0);
        row.addProperty("running_percent", round1(running * 100.0 / alive));
        row.addProperty("waiting_for_cpu_percent", round1(waiting * 100.0 / alive));
        row.addProperty("blocked_percent", round1(blocked * 100.0 / alive));
        TreeSet<Integer> cpus = new TreeSet<>();
        if (cpuQuark != null) {
            for (ITmfStateInterval interval : history.intervals(cpuQuark)) {
                Object value = interval.getValue();
                if (value instanceof Integer) {
                    cpus.add((Integer) value);
                }
            }
        }
        JsonArray cpuList = new JsonArray();
        cpus.forEach(cpuList::add);
        row.add("cpus", cpuList);
        row.addProperty("wakeups", wakeups.size());
        JsonObject period = period(wakeups);
        if (period != null) {
            row.add("periodic", period);
        }
        return row;
    }

    /**
     * The thread's period, when most of the gaps between its wake-ups are
     * within 25% of their median; null when it has too few wake-ups or they
     * are irregular. A few outliers (a late cycle) do not stop a thread from
     * being periodic: that is what the late-cycle search looks for.
     */
    private static JsonObject period(List<Long> wakeups) {
        if (wakeups.size() < MIN_ACTIVATIONS) {
            return null;
        }
        List<Long> gaps = new ArrayList<>();
        for (int i = 1; i < wakeups.size(); i++) {
            gaps.add(wakeups.get(i) - wakeups.get(i - 1));
        }
        List<Long> sorted = new ArrayList<>(gaps);
        sorted.sort(Long::compare);
        long median = sorted.get(sorted.size() / 2);
        if (median <= 0) {
            return null;
        }
        long regular = gaps.stream().filter(gap -> Math.abs(gap - median) <= median / 4).count();
        double share = regular * 100.0 / gaps.size();
        if (share < 80) {
            return null;
        }
        JsonObject period = new JsonObject();
        period.addProperty("period_ms", median / 1_000_000.0);
        period.addProperty("regular_percent", round1(share));
        period.addProperty("longest_gap_ms", sorted.get(sorted.size() - 1) / 1_000_000.0);
        return period;
    }

    private static double round1(double value) {
        return Math.round(value * 10) / 10.0;
    }

    /**
     * Level 1 of the busiest-thread, long-blocked-waits, slow-scheduling and
     * slow-system-call searches (thread_finder_design.md, section 4): one
     * thread's time by state, its longest blocked interval and its longest
     * wait for a CPU (with when they happened), and its time inside system
     * calls (the System_call attribute: an interval with a value is one call,
     * including any time blocked or waiting inside it; the longest call skips exit and
     * exit_group, which last until the thread ends).
     */
    static JsonObject stateProfile(ITmfTrace trace, int tid) {
        JsonObject profile = new JsonObject();
        profile.addProperty("tid", tid);
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        ITmfStateSystem ss = kernel == null ? null : kernel.getStateSystem();
        int status = ss == null ? ITmfStateSystem.INVALID_ATTRIBUTE : ss.optQuarkAbsolute("Threads", String.valueOf(tid));
        if (status == ITmfStateSystem.INVALID_ATTRIBUTE) {
            profile.addProperty("available", false);
            profile.addProperty("reason", "the thread is not in the kernel state system");
            return profile;
        }
        int syscall = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "System_call");
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();
        List<Integer> quarks = new ArrayList<>(List.of(status));
        if (syscall != ITmfStateSystem.INVALID_ATTRIBUTE) {
            quarks.add(syscall);
        }
        AnswerPipeline.History history = AnswerPipeline.History.load(ss, quarks, start, end);
        long user = 0;
        long kernelMode = 0;
        long waiting = 0;
        long blocked = 0;
        long first = Long.MAX_VALUE;
        long last = Long.MIN_VALUE;
        long[] longestBlocked = null;
        long[] longestWait = null;
        for (ITmfStateInterval interval : history.intervals(status)) {
            ProcessStatus state = ProcessStatus.getStatusFromStateValue(interval.getStateValue());
            if (interval.getStateValue().isNull() || state == ProcessStatus.NOT_ALIVE
                    || state == ProcessStatus.EXIT || state == ProcessStatus.UNKNOWN) {
                continue;
            }
            long s0 = Math.max(interval.getStartTime(), start);
            long e0 = Math.min(interval.getEndTime(), end);
            if (e0 < s0) {
                continue;
            }
            long length = e0 - s0 + 1;
            first = Math.min(first, s0);
            last = Math.max(last, e0);
            switch (state) {
            case RUN:
                user += length;
                break;
            case RUN_SYTEMCALL:
            case INTERRUPTED:
                kernelMode += length;
                break;
            case WAIT_CPU:
                waiting += length;
                if (longestWait == null || length > longestWait[1] - longestWait[0]) {
                    longestWait = new long[] {s0, e0 + 1};
                }
                break;
            case WAIT_BLOCKED:
                blocked += length;
                if (longestBlocked == null || length > longestBlocked[1] - longestBlocked[0]) {
                    longestBlocked = new long[] {s0, e0 + 1};
                }
                break;
            default:
                break;
            }
        }
        if (first == Long.MAX_VALUE) {
            profile.addProperty("available", false);
            profile.addProperty("reason", "the thread was never alive in the trace");
            return profile;
        }
        long inCalls = 0;
        int calls = 0;
        long[] longestCall = null;
        String longestName = null;
        if (syscall != ITmfStateSystem.INVALID_ATTRIBUTE) {
            for (ITmfStateInterval interval : history.intervals(syscall)) {
                if (!(interval.getValue() instanceof String)) {
                    continue;
                }
                long s0 = Math.max(interval.getStartTime(), start);
                long e0 = Math.min(interval.getEndTime(), end);
                long length = e0 - s0 + 1;
                inCalls += length;
                calls++;
                // exit and exit_group never return: they last until the thread ends, not a slow call.
                if (AnswerPipeline.UnifiedExplainer.NEVER_RETURNS.contains((String) interval.getValue())) {
                    continue;
                }
                if (longestCall == null || length > longestCall[1] - longestCall[0]) {
                    longestCall = new long[] {s0, e0 + 1};
                    longestName = (String) interval.getValue();
                }
            }
        }
        long alive = Math.max(1, last - first + 1);
        profile.addProperty("available", true);
        profile.addProperty("lifetime_ms", alive / 1_000_000.0);
        profile.addProperty("running_ms", (user + kernelMode) / 1_000_000.0);
        profile.addProperty("user_mode_ms", user / 1_000_000.0);
        profile.addProperty("kernel_mode_ms", kernelMode / 1_000_000.0);
        profile.addProperty("waiting_for_cpu_ms", waiting / 1_000_000.0);
        profile.addProperty("blocked_ms", blocked / 1_000_000.0);
        addInterval(profile, "longest_blocked", longestBlocked, start);
        addInterval(profile, "longest_wait_for_cpu", longestWait, start);
        profile.addProperty("system_calls", calls);
        profile.addProperty("in_system_calls_ms", inCalls / 1_000_000.0);
        addInterval(profile, "longest_system_call", longestCall, start);
        if (longestName != null) {
            profile.addProperty("longest_system_call_name", longestName);
        }
        return profile;
    }

    private static void addInterval(JsonObject into, String prefix, long[] interval, long traceStart) {
        if (interval == null) {
            return;
        }
        into.addProperty(prefix + "_ms", (interval[1] - interval[0]) / 1_000_000.0);
        into.addProperty(prefix + "_start_ns", interval[0]);
        into.addProperty(prefix + "_end_ns", interval[1]);
        into.addProperty(prefix + "_start_offset_ms", (interval[0] - traceStart) / 1_000_000.0);
    }

    /**
     * Level 1 of the one-off-delay search (thread_finder_design.md, section
     * 4): the lengths of one thread's cycles, a cycle being the time from one
     * wake-up (leaving the blocked state) to the next, read from the state
     * history. Reports the median, the z-score of the longest cycle, and when
     * it happened. {@code available} is false with fewer than 3 wake-ups.
     */
    static JsonObject cycleStats(ITmfTrace trace, int tid) {
        JsonObject stats = new JsonObject();
        stats.addProperty("tid", tid);
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        ITmfStateSystem ss = kernel == null ? null : kernel.getStateSystem();
        int quark = ss == null ? ITmfStateSystem.INVALID_ATTRIBUTE : ss.optQuarkAbsolute("Threads", String.valueOf(tid));
        if (quark == ITmfStateSystem.INVALID_ATTRIBUTE) {
            stats.addProperty("available", false);
            stats.addProperty("reason", "the thread is not in the kernel state system");
            return stats;
        }
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();
        AnswerPipeline.History history = AnswerPipeline.History.load(ss, List.of(quark), start, end);
        List<Long> wakeups = new ArrayList<>();
        boolean wasBlocked = false;
        for (ITmfStateInterval interval : history.intervals(quark)) {
            ProcessStatus status = ProcessStatus.getStatusFromStateValue(interval.getStateValue());
            if (interval.getStateValue().isNull() || status == ProcessStatus.NOT_ALIVE
                    || status == ProcessStatus.EXIT || status == ProcessStatus.UNKNOWN) {
                wasBlocked = false;
                continue;
            }
            if (wasBlocked && status != ProcessStatus.WAIT_BLOCKED) {
                wakeups.add(Math.max(interval.getStartTime(), start));
            }
            wasBlocked = status == ProcessStatus.WAIT_BLOCKED;
        }
        stats.addProperty("wakeups", wakeups.size());
        if (wakeups.size() < 3) {
            stats.addProperty("available", false);
            stats.addProperty("reason", "fewer than 3 wake-ups");
            return stats;
        }
        int longest = 1;
        double sum = 0;
        List<Long> gaps = new ArrayList<>();
        for (int i = 1; i < wakeups.size(); i++) {
            long gap = wakeups.get(i) - wakeups.get(i - 1);
            gaps.add(gap);
            sum += gap;
            if (gap > wakeups.get(longest) - wakeups.get(longest - 1)) {
                longest = i;
            }
        }
        double mean = sum / gaps.size();
        double variance = 0;
        for (long gap : gaps) {
            variance += (gap - mean) * (gap - mean);
        }
        double std = Math.sqrt(variance / gaps.size());
        List<Long> sorted = new ArrayList<>(gaps);
        sorted.sort(Long::compare);
        long median = sorted.get(sorted.size() / 2);
        long longestGap = sorted.get(sorted.size() - 1);
        long second = sorted.size() > 1 ? sorted.get(sorted.size() - 2) : longestGap;
        stats.addProperty("available", true);
        stats.addProperty("cycles", gaps.size());
        stats.addProperty("median_cycle_ms", median / 1_000_000.0);
        stats.addProperty("longest_cycle_ms", longestGap / 1_000_000.0);
        stats.addProperty("second_longest_cycle_ms", second / 1_000_000.0);
        stats.addProperty("longest_over_median", median > 0 ? longestGap / (double) median : 0);
        stats.addProperty("longest_z_score", std > 0 ? (longestGap - mean) / std : 0);
        stats.addProperty("longest_start_ns", wakeups.get(longest - 1));
        stats.addProperty("longest_end_ns", wakeups.get(longest));
        stats.addProperty("longest_start_offset_ms", (wakeups.get(longest - 1) - start) / 1_000_000.0);
        return stats;
    }
}
