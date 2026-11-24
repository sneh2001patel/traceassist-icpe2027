package org.eclipse.tracecompass.helloworld.ui.views;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.analysis.graph.core.base.IGraphWorker;
import org.eclipse.tracecompass.analysis.graph.core.criticalpath.AbstractCriticalPathModule;
import org.eclipse.tracecompass.analysis.graph.core.criticalpath.OSCriticalPathModule;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfEdge;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfGraph;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfVertex;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsExecutionGraph;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsWorker;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.analysis.os.linux.core.model.OsStrings;
import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateSystemDisposedException;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystem;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.signal.TmfDataModelSelectedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfSignalManager;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimePreferences;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
import org.eclipse.tracecompass.tmf.core.trace.experiment.TmfExperiment;
import org.eclipse.tracecompass.analysis.os.linux.core.signals.TmfThreadSelectedSignal;
import org.eclipse.tracecompass.analysis.os.linux.core.signals.TmfCpuSelectedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfWindowRangeUpdatedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfSelectionRangeUpdatedSignal;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimestamp;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.BufferedInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import org.eclipse.tracecompass.lttng2.kernel.core.trace.LttngKernelTrace;
import org.eclipse.tracecompass.tmf.core.signal.TmfTraceOpenedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfTraceSelectedSignal;
import org.eclipse.tracecompass.tmf.ctf.core.event.CtfTmfEvent;

/**
 * TraceAssist's answer pipeline, without any UI: everything the chat does for a question
 * before the LLM call (target resolution, thread finder and search, explainers, TMLL, RAG,
 * view planning), and the local test endpoint. Moved out of {@link HelloWorldView} so the
 * same code runs in the Eclipse UI and, headless, inside the Trace Server
 * (TraceAssist server bundle). Nothing here may use SWT or the workbench.
 */
final class AnswerPipeline {


    /*
     * Maximum number of detailed thread records sent to OpenAI.
     */
    static final int MAX_THREAD_DETAILS = 100;

    static final String TMLL_THREAD_ANALYSIS_URL =
            "http://127.0.0.1:8000/analyze/thread";

    static final String TMLL_RAG_RETRIEVE_URL =
            "http://127.0.0.1:8000/rag/retrieve";

    static final String TMLL_PERIODIC_JITTER_URL =
            "http://127.0.0.1:8000/analyze/periodic_jitter";

    /**
     * Longest wait for one TMLL request. TMLL is supplementary evidence; on a
     * long trace the Trace Server can take very long (or run out of memory)
     * building a table for the first time, and the answer must not wait forever.
     */
    static final java.time.Duration TMLL_TIMEOUT = java.time.Duration.ofMinutes(10);

    /** TMLL's z-score over a series of durations measured here (no trace needed). */
    static final String TMLL_SERIES_ANOMALIES_URL =
            "http://127.0.0.1:8000/analyze/series_anomalies";

    static final Map<String, String> VIEW_ALIASES =
            createViewAliases();

    final HttpClient httpClient =
            HttpClient.newHttpClient();

    static Map<String, String> createViewAliases() {
        Map<String, String> aliases =
                new LinkedHashMap<>();

        aliases.put(
                "control flow",
                "org.eclipse.tracecompass.analysis.os.linux.views.controlflow");
        aliases.put(
                "controlflow",
                "org.eclipse.tracecompass.analysis.os.linux.views.controlflow");
        aliases.put(
                "resources",
                "org.eclipse.tracecompass.analysis.os.linux.views.resources");
        aliases.put(
                "resource",
                "org.eclipse.tracecompass.analysis.os.linux.views.resources");
        aliases.put(
                "cpu usage",
                "org.eclipse.tracecompass.analysis.os.linux.views.cpuusage");
        aliases.put(
                "cpu",
                "org.eclipse.tracecompass.analysis.os.linux.views.cpuusage");
        aliases.put(
                "system call latency",
                "org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.latency.syscall");
        aliases.put(
                "syscall latency",
                "org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.latency.syscall");
        aliases.put(
                "statistics",
                "org.eclipse.linuxtools.tmf.ui.views.statistics");
        aliases.put(
                "histogram",
                "org.eclipse.linuxtools.tmf.ui.views.histogram");
        aliases.put(
                "event density",
                "org.eclipse.tracecompass.tmf.ui.views.eventdensity");
        aliases.put(
                "critical path",
                "org.eclipse.linuxtools.tmf.analysis.graph.ui.criticalpath.view.criticalpathview");
        aliases.put(
                "filters",
                "org.eclipse.linuxtools.tmf.ui.views.filter");
        aliases.put(
                "filter",
                "org.eclipse.linuxtools.tmf.ui.views.filter");
        aliases.put(
                "colors",
                "org.eclipse.linuxtools.tmf.ui.views.colors");
        aliases.put(
                "time chart",
                "org.eclipse.linuxtools.tmf.ui.views.timechart");
        aliases.put(
                "hello world rag",
                "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldView");
        aliases.put(
                "rag",
                "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldView");
        aliases.put(
                "traceassist rag",
                "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldRagView");
        aliases.put(
                "hello world",
                "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldView");
        aliases.put(
                "traceassist",
                "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldView");

        return aliases;
    }

    static Integer extractTid(String question) {
        Pattern pattern = Pattern.compile(
                "(?i)\\b(?:tid|thread)\\s*[:#]?\\s*(\\d+)\\b");

        Matcher matcher = pattern.matcher(question);

        if (matcher.find()) {
            return Integer.valueOf(matcher.group(1));
        }

        return null;
    }

    /**
     * Optional "every 1ms"/"every 500us" clause in a periodic-jitter
     * question, used as the expected period instead of letting
     * {@code detect_periodic_jitter_anomalies()} auto-infer it from the
     * median observed period -- an explicit deadline stated by the user is
     * better evidence than a statistical guess.
     */
    static final String TIME_UNIT =
            "(ns|nanoseconds?|us|µs|microseconds?|ms|milliseconds?|" +
            "s|secs?|seconds?)";

    /** "between 1.2 ms and 1.5 ms" / "from 1.2 to 1.5 s" (unit optional). */
    static final Pattern RELATIVE_WINDOW_WITH_KEYWORD_PATTERN =
            Pattern.compile(
                    "(?i)\\b(?:between|from)\\s+(\\d+(?:\\.\\d+)?)\\s*" +
                    TIME_UNIT + "?\\s*(?:and|to|-|–|—)\\s*" +
                    "(\\d+(?:\\.\\d+)?)\\s*" + TIME_UNIT + "?(?![\\w:])");

    /** "1.2ms-1.5ms" / "400 to 450 ms" (a unit is required). */
    static final Pattern RELATIVE_WINDOW_PATTERN =
            Pattern.compile(
                    "(?i)(?<![\\w.:])(\\d+(?:\\.\\d+)?)\\s*" + TIME_UNIT +
                    "?\\s*(?:-|–|—|to)\\s*(\\d+(?:\\.\\d+)?)\\s*" +
                    TIME_UNIT + "(?![\\w:])");

    /** Absolute nanosecond timestamps, as in the event table's raw view. */
    static final Pattern ABSOLUTE_NS_WINDOW_PATTERN =
            Pattern.compile(
                    "(\\d{13,})\\s*(?:ns)?\\s*(?:and|to|-|–|—)\\s*" +
                    "(\\d{13,})");

    /** Clock times as Trace Compass displays them: 09:39:01.764 263 353. */
    static final Pattern CLOCK_WINDOW_PATTERN =
            Pattern.compile(
                    "(\\d{1,2}:\\d{2}:\\d{2}(?:[.,][\\d ]*\\d)?)\\s*" +
                    "(?:and|to|-|–|—)\\s*" +
                    "(\\d{1,2}:\\d{2}:\\d{2}(?:[.,][\\d ]*\\d)?)");

    static final Pattern EXPECTED_PERIOD_PATTERN =
            Pattern.compile(
                    "(?i)every\\s+(\\d+)\\s*(ms|milliseconds?|us|" +
                    "microseconds?)");

    // ---------------------------------------------------------------
    // Views: which Trace Compass views show an answer, and focusing them
    // ---------------------------------------------------------------

    /** Trace Compass's own names for the views the chat opens. */
    static final Map<String, String> VIEW_NAMES = Map.ofEntries(
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.views.controlflow", "Control Flow"),
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.views.resources", "Resources"),
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.views.cpuusage", "CPU Usage"),
            Map.entry("org.eclipse.linuxtools.tmf.analysis.graph.ui.criticalpath.view.criticalpathview", "Critical Path"),
            Map.entry("org.eclipse.linuxtools.tmf.ui.views.statistics", "Statistics"),
            Map.entry("org.eclipse.linuxtools.tmf.ui.views.histogram", "Histogram"),
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.views.latency.scatter", "System Call Latency vs Time"),
            Map.entry("org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.latency.syscall",
                    "System Call Latencies"),
            Map.entry("org.eclipse.tracecompass.internal.analysis.os.linux.ui.views.swslatency.scatter",
                    "Sched_Wakeup/Switch Latency vs Time"),
            Map.entry("org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.core.swslatency.sws",
                    "Sched_Wakeup/Switch Latencies"),
            Map.entry("org.eclipse.tracecompass.tmf.ui.views.eventdensity", "Event Density"),
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.views.diskioactivity", "Disk I/O Activity"),
            Map.entry("org.eclipse.tracecompass.analysis.os.linux.ui.kernelmemoryusageview", "Kernel Memory Usage"));

    static final String VIEW_CONTROL_FLOW = "org.eclipse.tracecompass.analysis.os.linux.views.controlflow";
    static final String VIEW_RESOURCES = "org.eclipse.tracecompass.analysis.os.linux.views.resources";
    static final String VIEW_CPU_USAGE = "org.eclipse.tracecompass.analysis.os.linux.views.cpuusage";
    static final String VIEW_CRITICAL_PATH = "org.eclipse.linuxtools.tmf.analysis.graph.ui.criticalpath.view.criticalpathview";
    static final String VIEW_STATISTICS = "org.eclipse.linuxtools.tmf.ui.views.statistics";
    static final String VIEW_HISTOGRAM = "org.eclipse.linuxtools.tmf.ui.views.histogram";
    static final String VIEW_SYSCALL_LATENCY_SCATTER = "org.eclipse.tracecompass.analysis.os.linux.views.latency.scatter";
    static final String VIEW_SYSCALL_LATENCY_TABLE =
            "org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.latency.syscall";
    static final String VIEW_SCHED_LATENCY_SCATTER = "org.eclipse.tracecompass.internal.analysis.os.linux.ui.views.swslatency.scatter";
    static final String VIEW_SCHED_LATENCY_TABLE =
            "org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.core.swslatency.sws";
    static final String VIEW_EVENT_DENSITY = "org.eclipse.tracecompass.tmf.ui.views.eventdensity";
    static final String VIEW_DISK_IO = "org.eclipse.tracecompass.analysis.os.linux.views.diskioactivity";
    static final String VIEW_KERNEL_MEMORY = "org.eclipse.tracecompass.analysis.os.linux.ui.kernelmemoryusageview";

    static final Pattern DISK_WORDS = Pattern.compile("(?i)\\b(disk|block\\s+(device|i/?o)|storage)\\b");
    static final Pattern MEMORY_WORDS = Pattern.compile("(?i)\\b(memory|kmem|page\\s+allocations?)\\b");

    static final Pattern CPU_USAGE_WORDS =
            Pattern.compile("(?i)\\bcpu\\s+(usage|use|utili[sz]ation|time|load)\\b|\\bhow\\s+much\\s+cpu\\b");
    static final Pattern CPU_PLACEMENT_WORDS =
            Pattern.compile("(?i)\\bwhich\\s+cpu|\\bcpu\\s*\\(s\\)|\\bcores?\\b|\\bmigrat|\\bpinned\\b");
    /** "when was X's CPU usage highest", "busiest", "peak CPU": the thread's busiest window. */
    static final Pattern CPU_PEAK_WORDS = Pattern.compile(
            "(?i)\\b(highest|peak|most|busiest|max(imum)?|heaviest|spike)\\b.*\\bcpu\\b|\\bcpu\\b.*\\b(highest|peak|most|busiest|max(imum)?|heaviest|spike)\\b");

    /** "when was the system busiest", "most activity", "event rate peak". */
    static final Pattern EVENT_PEAK_WORDS = Pattern.compile(
            "(?i)\\b(busiest|most\\s+(active|activity|events)|event\\s+rate|peak\\s+activity|activity\\s+peak|when\\s+was\\s+the\\s+(system|trace)\\s+busy)");

    /** "how long does X wait to be scheduled", "wake-up latency", "scheduling delay". */
    static final Pattern SCHED_LATENCY_WORDS = Pattern.compile(
            "(?i)\\bschedul(ing|er)\\s+(latenc|delay)|\\bwake[- ]?up\\s+(latenc|delay)|\\b(wait|waits|waiting)\\s+to\\s+be\\s+scheduled"
                    + "|\\bafter\\s+(it\\s+)?(is\\s+)?(wakes?|woken)\\b|\\brun\\s*queue\\s+(latenc|delay|wait)");

    static final Pattern SYSCALL_WORDS =
            Pattern.compile("(?i)\\bsys(tem)?\\s*calls?\\b|\\bsyscalls?\\b");

    /**
     * Which views show the answer, over which time range, focused on what.
     * Deterministic, from the plan and the findings (the same facts the
     * answer states), never from the LLM. Returns null when nothing fits.
     */
    static JsonObject planViews(String question, JsonObject plan, JsonArray findings, ITmfTrace trace) {
        if (trace == null || plan == null) {
            return null;
        }
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        String scope = UnifiedExplainer.str(plan, "scope");
        String intent = UnifiedExplainer.str(plan, "intent");
        List<String> views = new ArrayList<>();
        long start = traceStart;
        long end = traceEnd;
        Integer follow = null;
        Integer select = null;
        Integer cpu = null;
        List<Integer> plot = new ArrayList<>();
        // Entries to tick in a latency scatter's series list (it plots nothing until one is ticked).
        List<String> series = new ArrayList<>();
        String reason;

        JsonObject userWindow = null;
        for (JsonElement element : findings) {
            JsonObject window = UnifiedExplainer.obj(element.getAsJsonObject(), "window");
            if (window != null && "user".equals(UnifiedExplainer.str(window, "source"))) {
                userWindow = window;
            }
        }
        if (userWindow != null) {
            start = UnifiedExplainer.num(userWindow, "start_ns", traceStart);
            end = UnifiedExplainer.num(userWindow, "end_ns", traceEnd);
        }

        if ("trace".equals(scope)) {
            JsonObject eventPeak = dataOf(findings, "trace.event_peak");
            JsonObject recorded = dataOf(findings, "trace.recorded");
            List<String> categories = new ArrayList<>();
            if (recorded != null) {
                UnifiedExplainer.arr(recorded, "recorded")
                        .forEach(item -> categories.add(UnifiedExplainer.str(item.getAsJsonObject(), "category")));
            }
            if (eventPeak != null && eventPeak.has("peak_start_ns")) {
                views.add(VIEW_EVENT_DENSITY);
                views.add(VIEW_HISTOGRAM);
                boolean afterStart = eventPeak.has("after_start_peak_start_ns");
                start = eventPeak.get(afterStart ? "after_start_peak_start_ns" : "peak_start_ns").getAsLong();
                end = eventPeak.get(afterStart ? "after_start_peak_end_ns" : "peak_end_ns").getAsLong();
                reason = afterStart ? "the trace's busiest stretch by event rate after start-up (the start itself is the "
                        + "state dump)" : "the trace's busiest stretch by event rate";
            } else if (DISK_WORDS.matcher(question).find() && categories.contains("block (disk) I/O")) {
                views.add(VIEW_DISK_IO);
                reason = "disk I/O activity";
            } else if (MEMORY_WORDS.matcher(question).find() && categories.contains("memory")) {
                views.add(VIEW_KERNEL_MEMORY);
                reason = "kernel memory usage";
            } else {
                views.add(VIEW_STATISTICS);
                views.add(VIEW_HISTOGRAM);
                reason = "what the trace recorded";
            }
        } else if ("process".equals(scope)) {
            JsonObject bottleneck = dataOf(findings, "process.bottleneck");
            JsonObject example = dataOf(findings, "process.example_chain");
            int pid = (int) UnifiedExplainer.num(plan, "pid", 0L);
            if (bottleneck != null && bottleneck.has("main_tid")) {
                follow = bottleneck.get("main_tid").getAsInt();
                select = follow;
                views.add(VIEW_CRITICAL_PATH);
                views.add(VIEW_CONTROL_FLOW);
                if (example != null && example.has("interval_start_offset_ms") && userWindow == null) {
                    start = traceStart + Math.round(UnifiedExplainer.dbl(example, "interval_start_offset_ms", 0) * 1_000_000);
                    end = start + Math.round(UnifiedExplainer.dbl(example, "interval_ms", 0) * 1_000_000);
                    reason = ("typical".equals(UnifiedExplainer.str(example, "example_kind"))
                            ? "a typical wait of the main thread on its bottleneck TID " : "the longest wait on the bottleneck TID ")
                            + UnifiedExplainer.num(bottleneck, "bottleneck_tid", 0L) + ", with its critical path";
                } else {
                    reason = "the main thread's waits on its bottleneck";
                }
            } else {
                select = pid;
                views.add(VIEW_CONTROL_FLOW);
                reason = "the process's threads";
            }
        } else {
            int tid = (int) UnifiedExplainer.num(plan, "tid", 0L);
            select = tid;
            JsonObject lateCycle = dataOf(findings, "window.late_cycle");
            JsonObject waiting = dataOf(findings, "waiting.cpu_occupancy");
            JsonObject chain = dataOf(findings, "blocked.wake_chain");
            JsonObject peak = dataOf(findings, "running.cpu_peak");
            JsonObject schedLatency = dataOf(findings, "scheduling.latency");
            JsonObject longestCalls = dataOf(findings, "syscalls.longest");
            JsonArray longestList = longestCalls == null ? new JsonArray() : UnifiedExplainer.arr(longestCalls, "longest");
            if (schedLatency != null && schedLatency.has("worst_start_ns")) {
                views.add(VIEW_SCHED_LATENCY_SCATTER);
                views.add(VIEW_SCHED_LATENCY_TABLE);
                views.add(VIEW_CONTROL_FLOW);
                start = schedLatency.get("worst_start_ns").getAsLong();
                end = schedLatency.get("worst_end_ns").getAsLong();
                // Its wake-up delays are grouped under the thread's name.
                KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(trace, KernelAnalysisModule.class,
                        KernelAnalysisModule.ID);
                String name = kernel == null ? null : KernelThreadInformationProvider.getExecutableName(kernel, tid);
                if (name != null) {
                    series.add(name);
                }
                reason = "the thread's worst wake-up scheduling delay";
            } else if (longestList.size() > 0) {
                JsonObject longest = longestCalls.has("longest_completed")
                        ? UnifiedExplainer.obj(longestCalls, "longest_completed") : longestList.get(0).getAsJsonObject();
                views.add(VIEW_SYSCALL_LATENCY_SCATTER);
                views.add(VIEW_SYSCALL_LATENCY_TABLE);
                views.add(VIEW_CONTROL_FLOW);
                start = longest.get("start_ns").getAsLong();
                end = longest.get("end_ns").getAsLong();
                // Calls are grouped by name: plot the kinds among the longest.
                for (JsonElement call : longestList) {
                    String name = UnifiedExplainer.str(call.getAsJsonObject(), "system_call");
                    if (name != null && !series.contains(name)) {
                        series.add(name);
                    }
                }
                reason = "the thread's longest system call (" + UnifiedExplainer.str(longest, "system_call") + ")";
            } else if (peak != null && peak.has("peak_start_ns")) {
                views.add(VIEW_CPU_USAGE);
                views.add(VIEW_CONTROL_FLOW);
                plot.add(tid);
                start = peak.get("peak_start_ns").getAsLong();
                end = peak.get("peak_end_ns").getAsLong();
                reason = "the thread's busiest CPU window";
            } else if (CPU_USAGE_WORDS.matcher(question).find()) {
                views.add(VIEW_CPU_USAGE);
                plot.add(tid);
                reason = "the thread's CPU usage";
            } else if (CPU_PLACEMENT_WORDS.matcher(question).find()) {
                views.add(VIEW_RESOURCES);
                views.add(VIEW_CONTROL_FLOW);
                follow = tid;
                reason = "the CPUs the thread ran on";
            } else if (lateCycle != null) {
                JsonObject window = windowOf(findings, "window.late_cycle");
                if (window != null) {
                    start = UnifiedExplainer.num(window, "start_ns", start);
                    end = UnifiedExplainer.num(window, "end_ns", end);
                }
                follow = tid;
                if ("waiting_for_cpu".equals(UnifiedExplainer.str(lateCycle, "gap_kind")) && waiting != null) {
                    views.add(VIEW_RESOURCES);
                    views.add(VIEW_CONTROL_FLOW);
                    cpu = firstCpu(waiting);
                    reason = "the late cycle, and who held the CPU";
                } else if ("running".equals(UnifiedExplainer.str(lateCycle, "gap_kind"))) {
                    // Its own work: no other thread is involved, so a critical path shows only the thread running.
                    views.add(VIEW_CONTROL_FLOW);
                    reason = "the late cycle: the thread's own work (running, in user mode and system calls)";
                } else {
                    views.add(VIEW_CRITICAL_PATH);
                    views.add(VIEW_CONTROL_FLOW);
                    reason = "the late cycle, with the thread's critical path";
                }
            } else if ("describe_activity".equals(intent)) {
                views.add(VIEW_CONTROL_FLOW);
                reason = "the thread's activity";
            } else if (chain != null && UnifiedExplainer.bool(chain, "available") && chain.has("interval_start_ns")
                    && userWindow == null) {
                views.add(VIEW_CRITICAL_PATH);
                views.add(VIEW_CONTROL_FLOW);
                follow = tid;
                start = chain.get("interval_start_ns").getAsLong();
                end = chain.get("interval_end_ns").getAsLong();
                reason = "a typical wait of the thread, with its critical path (who woke it and what that waited on)";
            } else if (waiting != null && "waiting_for_cpu".equals(dominantState(findings))) {
                views.add(VIEW_RESOURCES);
                views.add(VIEW_CONTROL_FLOW);
                follow = tid;
                cpu = firstCpu(waiting);
                reason = "the CPU the thread waited for, and who held it";
            } else {
                views.add(VIEW_CONTROL_FLOW);
                reason = "the thread's states";
            }
            if (SYSCALL_WORDS.matcher(question).find() && !views.contains(VIEW_SYSCALL_LATENCY_SCATTER)) {
                views.add(VIEW_SYSCALL_LATENCY_SCATTER);
            }
        }

        // A view named in the question goes first; the focus and time range stay.
        String named = viewNamedInQuestion(question);
        if (named != null && !named.startsWith("org.eclipse.tracecompass.helloworld")) {
            views.remove(named);
            views.add(0, named);
            if (VIEW_CPU_USAGE.equals(named) && select != null && plot.isEmpty()) {
                plot.add(select);
            }
            if (VIEW_CRITICAL_PATH.equals(named) && follow == null) {
                follow = select;
            }
        }
        if (views.isEmpty()) {
            return null;
        }

        long length = Math.max(1, end - start);
        long pad = Math.max(length / 10, 1_000L);
        JsonObject viewPlan = new JsonObject();
        JsonArray viewList = new JsonArray();
        List<String> names = new ArrayList<>();
        for (String id : views) {
            JsonObject view = new JsonObject();
            view.addProperty("id", id);
            view.addProperty("name", displayNameForViewId(id));
            viewList.add(view);
            names.add(displayNameForViewId(id));
        }
        viewPlan.add("views", viewList);
        JsonObject window = new JsonObject();
        window.addProperty("start_ns", start);
        window.addProperty("end_ns", end);
        window.addProperty("start_offset_ms", (start - traceStart) / 1_000_000.0);
        window.addProperty("end_offset_ms", (end - traceStart) / 1_000_000.0);
        viewPlan.add("selection", window);
        JsonObject zoom = new JsonObject();
        zoom.addProperty("start_ns", Math.max(traceStart, start - pad));
        zoom.addProperty("end_ns", Math.min(traceEnd, end + pad));
        viewPlan.add("zoom", zoom);
        if (follow != null) {
            viewPlan.addProperty("follow_tid", follow);
        }
        if (select != null) {
            viewPlan.addProperty("select_tid", select);
        }
        if (cpu != null) {
            viewPlan.addProperty("cpu", cpu);
        }
        JsonArray plotList = new JsonArray();
        plot.forEach(plotList::add);
        viewPlan.add("plot_tids", plotList);
        JsonArray seriesList = new JsonArray();
        series.forEach(seriesList::add);
        viewPlan.add("plot_series", seriesList);
        viewPlan.addProperty("reason", reason);
        List<String> focus = new ArrayList<>();
        if (follow != null) {
            focus.add("following TID " + follow);
        } else if (select != null) {
            focus.add("TID " + select + " selected");
        }
        if (!plot.isEmpty()) {
            focus.add("TID " + plot.get(0) + " plotted");
        }
        if (!series.isEmpty()) {
            focus.add(String.join(", ", series) + " plotted");
        }
        if (cpu != null) {
            focus.add("CPU " + cpu);
        }
        // Both clocks: offsets (as the answer gives them) and the time of day the views show.
        String clock = TmfTimestamp.fromNanos(start).toString() + " – " + TmfTimestamp.fromNanos(end).toString();
        viewPlan.addProperty("clock_range", clock);
        viewPlan.addProperty("summary", String.format(Locale.ROOT, "%s, %,.3f–%,.3f ms into the trace (%s on the views' time axis)%s: %s.",
                String.join(" + ", names), (start - traceStart) / 1_000_000.0, (end - traceStart) / 1_000_000.0, clock,
                focus.isEmpty() ? "" : " (" + String.join(", ", focus) + ")", reason));
        return viewPlan;
    }

    /**
     * A view the question explicitly names: a multi-word name ("cpu usage",
     * "critical path", "control flow"), or a one-word name followed by
     * "view" ("the resources view"). The command aliases are looser ("cpu"
     * opens CPU Usage), which would turn "which CPU does X run on?" into a
     * request for the CPU Usage view.
     */
    static String viewNamedInQuestion(String question) {
        String normalized = normalizeCommandText(question);
        for (Map.Entry<String, String> entry : VIEW_ALIASES.entrySet()) {
            String alias = entry.getKey();
            boolean named = alias.contains(" ")
                    ? normalized.contains(alias)
                    : normalized.matches(".*\\b" + Pattern.quote(alias) + "\\s+view\\b.*");
            if (named && !entry.getValue().startsWith("org.eclipse.tracecompass.helloworld")) {
                return entry.getValue();
            }
        }
        return null;
    }

    static JsonObject dataOf(JsonArray findings, String id) {
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            if (id.equals(UnifiedExplainer.str(finding, "id"))) {
                return UnifiedExplainer.obj(UnifiedExplainer.obj(finding, "evidence"), "data");
            }
        }
        return null;
    }

    static JsonObject windowOf(JsonArray findings, String id) {
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            if (id.equals(UnifiedExplainer.str(finding, "id"))) {
                return UnifiedExplainer.obj(finding, "window");
            }
        }
        return null;
    }

    static Integer firstCpu(JsonObject waiting) {
        JsonArray cpus = UnifiedExplainer.arr(waiting, "cpus");
        return cpus.size() == 0 ? null : cpus.get(0).getAsInt();
    }

    /** The state holding the largest share of the most specific window's decomposition. */
    static String dominantState(JsonArray findings) {
        JsonObject best = null;
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            if ("decomposition".equals(UnifiedExplainer.str(finding, "id"))) {
                best = finding;
            }
        }
        if (best == null) {
            return null;
        }
        JsonObject states = UnifiedExplainer.obj(UnifiedExplainer.obj(UnifiedExplainer.obj(best, "evidence"), "data"), "states");
        String top = null;
        double topPercent = -1;
        if (states != null) {
            for (Map.Entry<String, JsonElement> entry : states.entrySet()) {
                double percent = UnifiedExplainer.dbl(entry.getValue().getAsJsonObject(), "percent", 0);
                if (percent > topPercent) {
                    topPercent = percent;
                    top = entry.getKey();
                }
            }
        }
        return top == null ? null : top.startsWith("RUNNING") ? "running"
                : "RUNNABLE_WAITING_FOR_CPU".equals(top) ? "waiting_for_cpu" : "BLOCKED".equals(top) ? "blocked" : top;
    }

    /** The trace's own critical-path analysis: the one "Follow thread" drives and the Critical Path view shows. */
    static final String CRITICAL_PATH_ANALYSIS_ID = "org.eclipse.tracecompass.analysis.graph.core.criticalpath";
    static final String CRITICAL_PATH_PROVIDER_ID = "org.eclipse.tracecompass.analysis.graph.core.dataprovider.CriticalPathDataProvider";

    /**
     * The Critical Path view's data comes from whichever critical-path
     * analysis last announced its start on the trace
     * (OSCriticalPathDataProviderFactory), and it rebuilds when one starts.
     * The pipeline starts temporary ones for its examples and disposes
     * them; afterwards, announce the analysis the view is showing again, so
     * a rebuild never binds to a disposed one (it would wait forever:
     * "Building Entries...").
     */
    static void restoreCriticalPathBinding(ITmfTrace trace) {
        if (trace == null) {
            return;
        }
        // Never the trace's own analysis: with no thread followed it never computes,
        // and a view bound to it shows "Building Entries..." forever.
        OSCriticalPathModule shown = sViewCriticalPath;
        OSCriticalPathModule live = shown != null && shown.getTrace() == trace ? shown
                : sLastTemporaryCriticalPath != null && sLastTemporaryCriticalPath.getTrace() == trace
                        ? sLastTemporaryCriticalPath : null;
        if (live != null) {
            TmfSignalManager.dispatchSignal(
                    new org.eclipse.tracecompass.tmf.core.signal.TmfStartAnalysisSignal(AnswerPipeline.class, live));
        }
    }

    /** The pipeline's most recent temporary critical-path analysis, kept alive (see retireTemporaryCriticalPath). */
    static volatile OSCriticalPathModule sLastTemporaryCriticalPath;

    /**
     * Every analysis the pipeline starts is announced to the Critical Path
     * view's data provider factory; a view that binds to one that is later
     * disposed polls forever. So the newest stays alive, and an older one is
     * disposed only if the view's provider is not bound to it.
     */
    static void retireTemporaryCriticalPath(ITmfTrace trace, OSCriticalPathModule module) {
        OSCriticalPathModule older = sLastTemporaryCriticalPath;
        sLastTemporaryCriticalPath = module;
        if (older == null || older == module) {
            return;
        }
        if (older == boundCriticalPath(trace)) {
            sRetiredViewCriticalPaths.add(older);
        } else {
            older.dispose();
        }
    }

    /** The analysis the Critical Path view's cached data provider reads from, or null. */
    static Object boundCriticalPath(ITmfTrace trace) {
        if (trace == null) {
            return null;
        }
        Object provider = org.eclipse.tracecompass.tmf.core.dataprovider.DataProviderManager.getInstance()
                .getExistingDataProvider(trace, CRITICAL_PATH_PROVIDER_ID,
                        org.eclipse.tracecompass.tmf.core.model.tree.ITmfTreeDataProvider.class);
        for (Class<?> type = provider == null ? null : provider.getClass(); type != null; type = type.getSuperclass()) {
            try {
                java.lang.reflect.Field field = type.getDeclaredField("fCriticalPathModule");
                field.setAccessible(true);
                return field.get(provider);
            } catch (NoSuchFieldException exception) {
                // look in the superclass
            } catch (ReflectiveOperationException | RuntimeException exception) {
                return null;
            }
        }
        return null;
    }

    /** Earlier view analyses, kept alive for the session (see showCriticalPath). */
    static final List<OSCriticalPathModule> sRetiredViewCriticalPaths =
            java.util.Collections.synchronizedList(new ArrayList<>());

    /** The critical-path analysis the chat last bound the Critical Path view to (kept alive while shown). */
    static volatile OSCriticalPathModule sViewCriticalPath;

    static String normalizeCommandText(
            String text) {

        return text
                .toLowerCase()
                .replaceAll("[^a-z0-9_.:-]+", " ")
                .trim();
    }

    static String displayNameForViewId(
            String viewId) {
        String known = VIEW_NAMES.get(viewId);
        if (known != null) {
            return known;
        }

        for (Map.Entry<String, String> entry : VIEW_ALIASES.entrySet()) {
            if (entry.getValue().equals(viewId)) {
                return entry.getKey();
            }
        }

        return viewId;
    }

    /**
     * Returns the local filesystem path of the trace currently active in
     * Trace Compass, or {@code null} if none is open.
     *
     * This is what gets sent to the local Python/TMLL service instead of a
     * Trace Server experiment UUID. Trace Server assigns a fresh UUID
     * every time it restarts or an experiment is recreated, so a
     * hand-maintained UUID constant (or VM argument) silently goes stale
     * the moment that happens -- the previous approach here -- and the
     * TMLL/RAG call then queries whatever trace that stale UUID used to
     * point at instead of the trace actually open in the editor, failing
     * fast with no useful signal that anything is wrong. The trace's own
     * path is exactly what Trace Compass already has for whatever is
     * open, and it survives Trace Server restarts, so the Python service
     * resolves the current experiment UUID from it on every request (see
     * {@code resolve_experiment_id_by_trace_path()} in
     * tmll_assistant_service_syscall_v1.py) instead of anyone maintaining
     * two separate configs in sync by hand.
     */
    static @Nullable String activeTracePath() {
        ITmfTrace trace =
                TmfTraceManager
                        .getInstance()
                        .getActiveTrace();

        if (trace == null) {
            return null;
        }

        /*
         * Confirmed directly (debug logging on the Python side, 2026-09-29):
         * when the active trace is opened as a Trace Compass "experiment"
         * (the normal way of opening a single kernel trace in the RCP UI),
         * ITmfTrace#getPath() on the experiment itself returns the
         * experiment's own name (e.g. "exp-20260916-104151"), NOT a real
         * filesystem path -- TmfExperiment never overrides getPath(), and
         * an experiment has no single physical location of its own. Trace
         * Server's registered experiments, on the other hand, always wrap
         * a real trace folder path (resolve_experiment_id_by_trace_path()
         * in tmll_assistant_service_syscall_v1.py matches against exactly
         * that). The individual sub-traces inside the experiment DO have a
         * real path, so use the first one's instead.
         */
        if (trace instanceof TmfExperiment) {
            List<ITmfTrace> subTraces =
                    ((TmfExperiment) trace).getTraces();

            /* A session folder can hold userspace traces too: the kernel trace is the one analyzed. */
            for (ITmfTrace subTrace : subTraces) {
                if (subTrace instanceof org.eclipse.tracecompass.analysis.os.linux.core.trace.IKernelTrace) {
                    return subTrace.getPath();
                }
            }
            return subTraces.isEmpty()
                    ? null
                    : subTraces.get(0).getPath();
        }

        return trace.getPath();
    }

    /**
     * Same as {@link #activeTracePath()}, but fails fast with a clear
     * message instead of silently sending a null/blank trace path to the
     * TMLL service.
     */
    static String requireActiveTracePath() {
        String tracePath = activeTracePath();

        if (tracePath == null) {
            throw new IllegalStateException(
                    "No trace is currently active in Trace Compass.");
        }

        return tracePath;
    }

    /** The context handed to the LLM, plus the TMLL service's own timing. */
    static final class PipelineContext {
        final JsonObject context;
        final JsonObject serverReportedTiming;
        /** Same results in the common findings format; not sent to the LLM yet. */
        final JsonArray findings;
        /** What the query planner decided, and why. */
        final JsonObject plan;
        /** The thread or process the question was about (with the trace), for follow-ups; null for the whole trace. */
        final JsonObject target;
        /** Which views show the answer, over which range, focused on what (null if none). */
        final JsonObject viewPlan;

        PipelineContext(JsonObject context, JsonObject serverReportedTiming, JsonArray findings,
                JsonObject plan, JsonObject target, JsonObject viewPlan) {
            this.context = context;
            this.serverReportedTiming = serverReportedTiming;
            this.findings = findings;
            this.plan = plan;
            this.target = target;
            this.viewPlan = viewPlan;
        }
    }

    /**
     * Everything the chat does for a question before the LLM call: collects
     * the trace context and every gated analysis into the JSON the LLM
     * receives. Shared by the chat ({@link #sendMessage}) and the local test
     * endpoint ({@link AgentTestServer}), so regression tests exercise exactly
     * the code the chat runs.
     */
    PipelineContext buildAnswerContext(
            String userMessage,
            Integer requestedTid,
            boolean ragEnabled,
            Map<String, Long> stageDurationsNs) throws Exception {
        return buildAnswerContext(userMessage, requestedTid, ragEnabled, stageDurationsNs, null);
    }

    /** Words asking about a process's threads together; with the main thread's TID, the question is about the process. */
    static final Pattern PROCESS_QUESTION_PATTERN =
            Pattern.compile("(?i)\\b(each|every|all|which)\\s+threads?\\b|\\bthreads\\s+of\\b|\\bbottleneck\\s+of\\b");

    /** The detail findings each thread-finder symptom needs (they give the views a moment to zoom to). */
    static final Map<String, Set<String>> SYMPTOM_DETAILS = Map.of(
            "busiest_cpu", Set.of("cpu_peak"),
            "slow_scheduling", Set.of("sched_latency"),
            "slow_syscalls_io", Set.of("syscalls"),
            "long_blocked_waits", Set.of("syscalls"));

    /** Words about the program as a whole; a follow-up using them continues with the previous thread's process. */
    static final Pattern PROGRAM_FOLLOWUP_PATTERN =
            Pattern.compile("(?i)\\b(rounds?|slowdown|program|process|application|server)\\b");

    /** The PID {@code tid} belonged to in the trace, or null. */
    static Integer processOf(ITmfTrace trace, int tid) {
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        if (kernel == null) {
            return null;
        }
        kernel.schedule();
        kernel.waitForCompletion();
        return ProcessExplainer.pidOfThread(kernel, tid, trace.getStartTime().toNanos(), trace.getEndTime().toNanos());
    }

    /** Words that make a question about the whole trace, never a follow-up about the last thread or process. */
    static final Pattern TRACE_SCOPE_PATTERN =
            Pattern.compile("(?i)\\b(trace|traces|system[- ]wide|all processes|every process)\\b");

    /**
     * @param previousTarget
     *            what the previous question was about ({@link PipelineContext#target}),
     *            or null; a question naming no thread, process or the trace
     *            continues with it, on the same trace
     */
    PipelineContext buildAnswerContext(
            String userMessage,
            Integer requestedTid,
            boolean ragEnabled,
            Map<String, Long> stageDurationsNs,
            JsonObject previousTarget) throws Exception {

        /*
         * No TID: the question may still name a process ("batch_server",
         * "PID 1234") or a thread by its name ("the reader thread").
         */
        ITmfTrace namedTrace = TmfTraceManager.getInstance().getActiveTrace();
        JsonObject named = requestedTid == null && namedTrace != null
                ? timed(stageDurationsNs, "target_resolver", () -> resolveNamedTarget(userMessage, namedTrace))
                : null;
        String tracePath = namedTrace == null ? null : activeTracePath();
        JsonObject samePrevious = previousTarget != null && tracePath != null
                && tracePath.equals(UnifiedExplainer.str(previousTarget, "trace_path")) ? previousTarget : null;

        /*
         * The thread finder (thread_finder_design.md): an AI skill decides
         * whether the question is about a thread, a process or the whole
         * trace, and which one, from the trace's inventory. The name resolver's
         * matches are its hints; when it fails, the resolver and the follow-up
         * rules below decide as before.
         */
        ThreadFinder.Decision found = null;
        String finderFailure = null;
        if (requestedTid == null && namedTrace != null) {
            JsonObject hint = named;
            try {
                found = timed(stageDurationsNs, "thread_finder",
                        () -> ThreadFinder.decide(userMessage, namedTrace, hint, samePrevious));
                named = found.target();
            } catch (Exception exception) {
                finderFailure = exception.getMessage() != null ? exception.getMessage() : exception.toString();
                System.err.println("Thread finder unavailable, using the name resolver: " + finderFailure);
            }
        }
        /*
         * No clear target: the adaptive search (code) checks every suspect
         * within the budget and picks the one the evidence points to. If it
         * fails, the finder's most likely suspect stands.
         */
        if (ThreadSearch.applies(found)) {
            ThreadFinder.Decision decided = found;
            try {
                found = timed(stageDurationsNs, "thread_search", () -> ThreadSearch.run(decided, userMessage, namedTrace,
                        tid -> findLateCycles(QueryPlan.of(userMessage, tid, null, namedTrace, true))));
                named = found.target();
            } catch (Exception exception) {
                String reason = exception.getMessage() != null ? exception.getMessage() : exception.toString();
                found.json().addProperty("search_failed", reason);
                System.err.println("Thread search failed, using the most likely suspect: " + reason);
            }
        }
        if (found == null && requestedTid == null && named == null && samePrevious != null
                && !TRACE_SCOPE_PATTERN.matcher(userMessage).find()) {
            named = previousTarget.deepCopy();
            named.addProperty("inherited_from_previous_question", true);
            /* "...how much faster would rounds be?" after a question about one thread: its program. */
            if (named.has("tid") && PROGRAM_FOLLOWUP_PATTERN.matcher(userMessage).find()) {
                int previousTid = named.get("tid").getAsInt();
                Integer owner = processOf(namedTrace, previousTid);
                if (owner != null) {
                    named.remove("tid");
                    named.remove("name");
                    named.addProperty("pid", owner);
                    named.addProperty("process_of_previous_thread", previousTid);
                }
            }
        }
        Integer resolvedTid = requestedTid != null ? requestedTid
                : named != null && named.has("tid") ? named.get("tid").getAsInt() : null;
        Integer resolvedPid = resolvedTid == null && named != null && named.has("pid")
                ? named.get("pid").getAsInt() : null;
        /* "Which thread is the bottleneck of batch_server (tid 159971)?": the main thread's TID names its process. */
        if (requestedTid != null && namedTrace != null && PROCESS_QUESTION_PATTERN.matcher(userMessage).find()) {
            Integer owner = processOf(namedTrace, requestedTid);
            if (owner != null && owner.intValue() == requestedTid.intValue()) {
                resolvedPid = requestedTid;
                resolvedTid = null;
                named = new JsonObject();
                named.addProperty("pid", requestedTid);
                named.addProperty("main_thread_tid_named_process", true);
            }
        }
        final Integer threadTid = resolvedTid;
        final Integer processPid = resolvedPid;

        JsonObject trace = JsonParser.parseString(
                timed(stageDurationsNs, "trace_overview",
                        () -> collectActiveTraceContext(threadTid)))
                .getAsJsonObject();

        JsonArray findings = new JsonArray();
        JsonObject planJson = null;
        JsonObject tmllTiming = null;
        ITmfTrace activeTrace = TmfTraceManager.getInstance().getActiveTrace();

        if (threadTid == null && processPid != null && activeTrace != null) {
            QueryPlan plan = QueryPlan.of(userMessage, null, processPid, activeTrace);
            planJson = plan.json;
            planJson.add("resolved_from_question", named);
            List<ExplainWindow> windows = chooseWindows(plan, activeTrace, null);
            ExplainWindow mostSpecific = windows.get(windows.size() - 1);
            int pid = processPid;
            boolean describeProcess = "describe_process".equals(UnifiedExplainer.str(plan.json, "intent"));
            ProcessAnalysis analysis = timed(stageDurationsNs, "process_explainer",
                    () -> processAnalysis(activeTrace, pid, mostSpecific, describeProcess));
            findings = analysis.findings;
            JsonObject side = analysis.side;
            /*
             * TMLL evidence about the bottleneck: its system calls from the
             * Trace Server tables, and whether the main thread's waits on it
             * are alike every round or come in spikes (TMLL's z-score).
             * Supplemental, like the thread path's TMLL evidence: skipped
             * with the RAG toggle off, and a failure becomes a finding.
             */
            if (ragEnabled && side.has("bottleneck_tid")) {
                int bottleneckTid = side.get("bottleneck_tid").getAsInt();
                try {
                    JsonObject response = JsonParser.parseString(
                            timed(stageDurationsNs, "tmll_analysis", () -> callTmllThreadAnalysis(bottleneckTid)))
                            .getAsJsonObject();
                    tmllTiming = UnifiedExplainer.obj(response, "timing_ms");
                    addBottleneckSyscalls(findings, UnifiedExplainer.obj(response, "analysis"), side, mostSpecific);
                } catch (Exception exception) {
                    findings.add(unavailableFinding("tmll.unavailable",
                            "TMLL syscall evidence for the bottleneck thread is unavailable: " + exception.getMessage()));
                }
                try {
                    JsonObject series = JsonParser.parseString(
                            timed(stageDurationsNs, "tmll_series", () -> callTmllSeriesAnomalies(side)))
                            .getAsJsonObject();
                    addRoundConsistency(findings, series, side, mostSpecific, activeTrace);
                } catch (Exception exception) {
                    findings.add(unavailableFinding("tmll.unavailable",
                            "TMLL's check of the main thread's waits for outliers is unavailable: " + exception.getMessage()));
                }
            }
            for (String key : new String[] {"active_threads", "active_executable_names",
                    "included_thread_details", "thread_details_truncated"}) {
                trace.remove(key);
            }
        }

        if (threadTid == null && processPid == null && activeTrace != null) {
            QueryPlan plan = QueryPlan.of(userMessage, null, activeTrace);
            planJson = plan.json;
            List<ExplainWindow> windows = chooseWindows(plan, activeTrace, null);
            ExplainWindow mostSpecific = windows.get(windows.size() - 1);
            findings = timed(stageDurationsNs, "trace_explainer",
                    () -> TraceExplainer.explain(activeTrace, mostSpecific, userMessage));
            if (findings.size() > 0) {
                /* The findings list the processes; the raw thread list would repeat them. */
                for (String key : new String[] {"active_threads", "active_executable_names",
                        "included_thread_details", "thread_details_truncated"}) {
                    trace.remove(key);
                }
            }
        }

        if (threadTid != null && activeTrace != null) {
            QueryPlan plan = QueryPlan.of(userMessage, threadTid, null, activeTrace,
                    found != null && "one_off_delay".equals(found.symptom()));
            planJson = plan.json;
            if (named != null) {
                planJson.add("resolved_from_question", named);
            }
            JsonObject finder = plan.findLateCycles
                    ? timed(stageDurationsNs, "window_finder", () -> findLateCycles(plan))
                    : null;
            /* The thread finder's symptom asks for its detail finding even when the words do not ("wait the longest to get a CPU"). */
            Set<String> symptomDetails = found == null ? Set.of() : SYMPTOM_DETAILS.getOrDefault(found.symptom(), Set.of());
            if (!symptomDetails.isEmpty()) {
                planJson.addProperty("details_from", "thread_finder symptom " + found.symptom() + ": " + symptomDetails);
            }
            findings = timed(
                    stageDurationsNs,
                    "unified_explainer",
                    () -> UnifiedExplainer.explain(
                            activeTrace,
                            threadTid,
                            chooseWindows(plan, activeTrace, finder),
                            plan.describe,
                            lateCycleScan(finder),
                            userMessage,
                            symptomDetails));

            /*
             * A thread of a multi-threaded process: its part in the process's
             * wait chain, per round (cached with the process analysis, so a
             * run of questions about one process computes it once).
             */
            Integer owner = processOf(activeTrace, threadTid);
            /*
             * The thread is still blocked when the trace ends, never woken: its process's other
             * threads may be stuck too (a hang, a deadlock), which only the process view shows.
             */
            if (owner != null && targetNeverWoken(findings)) {
                List<ExplainWindow> stuckWindows = chooseWindows(plan, activeTrace, null);
                ExplainWindow stuckWindow = stuckWindows.get(stuckWindows.size() - 1);
                JsonArray stuckFindings = findings;
                timed(stageDurationsNs, "stuck_waits", () -> {
                    addStuckWaits(stuckFindings, activeTrace, owner, stuckWindow);
                    return null;
                });
            }
            if (owner != null && owner.intValue() != threadTid.intValue()) {
                List<ExplainWindow> processWindows = chooseWindows(plan, activeTrace, null);
                ExplainWindow processWindow = processWindows.get(processWindows.size() - 1);
                JsonArray roleFindings = findings;
                timed(stageDurationsNs, "process_context", () -> {
                    addProcessRole(roleFindings, processAnalysis(activeTrace, owner, processWindow, false), threadTid);
                    return null;
                });
            }

            /*
             * TMLL evidence the explainers do not produce themselves: the
             * thread's syscall mix over the whole trace, and cross-host
             * message matching. Supplemental: a service error becomes a
             * finding, never a failed answer. Skipped with the RAG toggle off.
             */
            if (ragEnabled) {
                try {
                    JsonObject response = JsonParser.parseString(
                            timed(stageDurationsNs, "tmll_analysis",
                                    () -> callTmllThreadAnalysis(threadTid)))
                            .getAsJsonObject();
                    tmllTiming = UnifiedExplainer.obj(response, "timing_ms");
                    addTmllEvidence(findings, UnifiedExplainer.obj(response, "analysis"), activeTrace);
                } catch (Exception exception) {
                    findings.add(unavailableFinding("tmll.unavailable",
                            "TMLL evidence (syscall mix, cross-host messages) is unavailable: "
                                    + exception.getMessage()));
                }
            }
        }

        if (planJson != null && (found != null || finderFailure != null)) {
            JsonObject finderJson = found != null ? found.json() : new JsonObject();
            if (found == null) {
                finderJson.addProperty("available", false);
                finderJson.addProperty("reason", finderFailure);
            }
            planJson.add("thread_finder", finderJson);
        }

        JsonArray documents = new JsonArray();
        if (ragEnabled) {
            JsonArray forConcepts = findings;
            try {
                JsonObject rag = JsonParser.parseString(
                        timed(stageDurationsNs, "rag_retrieval",
                                () -> callRagRetrieve(userMessage, ragConcepts(forConcepts))))
                        .getAsJsonObject();
                documents = trimDocuments(UnifiedExplainer.arr(rag, "documents"));
            } catch (Exception exception) {
                System.err.println("RAG retrieval failed: " + exception.getMessage());
            }
        }

        JsonObject llmContext = new JsonObject();
        llmContext.addProperty("question", userMessage);
        llmContext.add("trace", trace);
        if (planJson != null) {
            llmContext.add("plan", planJson);
        }
        /* Shortened for the model: a program with thousands of threads overflowed its context. */
        llmContext.add("findings", FindingsCompactor.forModel(findings,
                threadTid != null ? Set.of(threadTid.longValue()) : Set.of()));
        llmContext.add("documents", documents);

        JsonObject target = null;
        if (tracePath != null && (threadTid != null || processPid != null)) {
            target = new JsonObject();
            if (threadTid != null) {
                target.addProperty("tid", threadTid);
            } else {
                target.addProperty("pid", processPid);
            }
            if (named != null && named.has("name")) {
                target.add("name", named.get("name"));
            }
            target.addProperty("trace_path", tracePath);
        }
        JsonObject viewPlan = null;
        try {
            viewPlan = planViews(userMessage, planJson, findings, activeTrace);
        } catch (RuntimeException exception) {
            System.err.println("View planning failed: " + exception);
        }
        /*
         * The view picker (AI skill, skills/view_picker/ with one card per
         * view in skills/views/): picks the views, the evidence moment, each
         * view's focus and what to look at; code computes the zoom and checks
         * every choice. The rule-based plan above is the fallback.
         */
        if (viewPlan != null && planJson != null && activeTrace != null) {
            JsonObject rules = viewPlan;
            JsonObject rulePlan = planJson;
            JsonArray viewFindings = findings;
            try {
                viewPlan = timed(stageDurationsNs, "view_picker",
                        () -> ViewPicker.plan(userMessage, rulePlan, viewFindings, activeTrace, rules));
            } catch (Exception exception) {
                String reason = exception.getMessage() != null ? exception.getMessage() : exception.toString();
                rules.addProperty("source", "rules");
                rules.addProperty("view_picker_failed", reason);
                System.err.println("View picker unavailable, using the rule-based views: " + reason);
            }
        }
        /* The Trace Server output of each view, for the VS Code trace viewer (from the view cards). */
        ViewPicker.addServerOutputs(viewPlan);
        return new PipelineContext(llmContext, tmllTiming, findings, planJson, target, viewPlan);
    }

    /**
     * Runs {@code work}, recording its wall-clock duration under
     * {@code stageName} in {@code stageDurationsNs}.
     *
     * If the same stage name is timed more than once in a single question
     * (not currently the case, but harmless if it ever is), durations
     * accumulate rather than overwrite, so the reported number always
     * reflects total time spent in that stage.
     */
    static <T> T timed(
            Map<String, Long> stageDurationsNs,
            String stageName,
            Callable<T> work) throws Exception {

        long startNanos = System.nanoTime();

        try {
            return work.call();
        } finally {
            stageDurationsNs.merge(
                    stageName,
                    System.nanoTime() - startNanos,
                    Long::sum);
        }
    }

    /**
     * Collects information from the currently active Trace Compass trace.
     *
     * @return trace information represented as JSON
     */
    String collectActiveTraceContext(
            Integer requestedTid) {
        JsonObject context = new JsonObject();

        ITmfTrace trace =
                TmfTraceManager
                        .getInstance()
                        .getActiveTrace();

        if (trace == null) {
            context.addProperty(
                    "trace_open",
                    false);

            context.addProperty(
                    "message",
                    "No trace is currently active in Trace Compass.");

            return context.toString();
        }

        context.addProperty(
                "trace_open",
                true);

        context.addProperty(
                "trace_name",
                trace.getName());

        context.addProperty(
                "trace_implementation",
                trace.getClass().getName());

        context.addProperty(
                "start_timestamp",
                trace.getStartTime().toString());

        context.addProperty(
                "end_timestamp",
                trace.getEndTime().toString());

        long start =
                trace.getStartTime().getValue();

        long end =
                trace.getEndTime().getValue();

        context.addProperty(
                "start_timestamp_ns",
                start);

        context.addProperty(
                "end_timestamp_ns",
                end);

        context.addProperty(
                "duration_nanoseconds",
                Math.max(0, end - start));

        /*
         * Find the Linux Kernel Analysis associated with the trace.
         */
        KernelAnalysisModule kernelModule =
                TmfTraceUtils.getAnalysisModuleOfClass(
                        trace,
                        KernelAnalysisModule.class,
                        KernelAnalysisModule.ID);

        if (kernelModule == null) {
            context.addProperty(
                    "kernel_analysis_available",
                    false);

            context.addProperty(
                    "classification",
                    "No Linux Kernel Analysis module was found.");

            context.addProperty(
                    "explanation",
                    "The active trace may not be a Linux kernel trace, " +
                    "or its trace type does not provide kernel analysis.");

            return context.toString();
        }

        context.addProperty(
                "kernel_analysis_available",
                true);

        context.addProperty(
                "classification",
                "Linux kernel trace or an experiment containing " +
                "a Linux kernel trace");

        /*
         * Schedule the kernel analysis used by views such as
         * Control Flow.
         */
        kernelModule.schedule();
        kernelModule.waitForCompletion();

        /*
         * For a question about one thread, name it; its time, waits and
         * activity come from the findings (UnifiedExplainer), not from here.
         */
        if (requestedTid != null) {
            JsonObject requested = new JsonObject();
            requested.addProperty("tid", requestedTid);
            requested.addProperty("executable",
                    KernelThreadInformationProvider.getExecutableName(kernelModule, requestedTid, end));
            Integer requestedPid =
                    KernelThreadInformationProvider.getProcessId(kernelModule, requestedTid, end);
            if (requestedPid != null) {
                requested.addProperty("pid", requestedPid);
            }
            context.add("requested_thread", requested);
        }

        /*
         * No list of active threads here: it meant reading the whole state
         * history (minutes on a 30-minute trace), and the trace, process and
         * thread explainers now report the threads a question is about.
         */
        return context.toString();
    }

    /**
     * Deterministically correlates a critical-path result with a single
     * "likely wake cause" verdict, instead of leaving that inference to the
     * LLM.
     *
     * Before this existed, the critical path's participant list was handed
     * to the LLM as-is, and the LLM was observed hedging on a conclusion the
     * data already supported -- e.g. declining to name a thread as the wake
     * cause even when it was the sole non-idle participant in the exact
     * window that explains the block. This method computes that conclusion
     * once, deterministically, so the LLM's job shrinks to phrasing an
     * already-decided verdict instead of performing the correlation itself
     * from a flat JSON list on every call.
     *
     * The rule is intentionally simple and auditable rather than another
     * layer of inference:
     * <ol>
     * <li>Drop the requested thread itself and any {@code swapper/N} (TID 0)
     * participant -- the idle task is never a real wake cause. Its presence
     * instead usually means the algorithm hit a known limitation: a
     * cross-CPU remote wakeup misattributed to the destination CPU's idle
     * task (critical_path_bug_report.md "Finding 2"), or a network/softirq
     * -delivered wakeup it cannot attribute to a task at all
     * (critical_path_network_wakeup_blindspot.md). Either way, that is
     * reported as {@code no_cause_found}, not guessed at.</li>
     * <li>If exactly one real candidate remains, it is the cause
     * ({@code single_likely_cause}, high confidence).</li>
     * <li>If more than one remains, prefer one sharing the requested
     * thread's own executable name (a sibling worker thread is a far more
     * likely wake source than unrelated system activity that merely shared
     * the same CPU during the window) -- {@code single_likely_cause},
     * medium confidence.</li>
     * <li>Otherwise, admit the ambiguity ({@code multiple_candidates}, low
     * confidence) rather than pick one arbitrarily.</li>
     * </ol>
     *
     * @param criticalPathResult
     *            the JSON object returned by
     *            {@link #collectCriticalPathIfIndicated}
     * @return a JSON object with a "verdict", an optional
     *         "likely_cause_tid"/"likely_cause_name", the full candidate and
     *         excluded-noise lists, a "confidence", and a human-readable
     *         "basis" for the verdict
     */
    static JsonObject correlateBlockedIntervalCause(
            JsonObject criticalPathResult) {

        JsonObject result = new JsonObject();

        boolean available =
                criticalPathResult.has("available") &&
                criticalPathResult.get("available").getAsBoolean();

        if (!available ||
                !criticalPathResult.has("participants") ||
                !criticalPathResult.get("participants").isJsonArray()) {

            result.addProperty("verdict", "not_available");
            result.add("likely_cause_tid", JsonNull.INSTANCE);
            result.add("likely_cause_name", JsonNull.INSTANCE);
            result.add("candidates", new JsonArray());
            result.add("excluded_as_noise", new JsonArray());
            result.addProperty("confidence", "n/a");
            result.addProperty(
                    "basis",
                    "Critical path was not available for this thread/" +
                    "window, so no wake-cause correlation could be " +
                    "attempted.");
            return result;
        }

        JsonArray participants =
                criticalPathResult.getAsJsonArray("participants");

        String requestedThreadName = "";
        JsonArray candidates = new JsonArray();
        JsonArray excludedAsNoise = new JsonArray();

        for (JsonElement element : participants) {
            JsonObject participant = element.getAsJsonObject();

            int tid = participant.get("tid").getAsInt();
            String name =
                    participant.has("name") &&
                    !participant.get("name").isJsonNull()
                            ? participant.get("name").getAsString()
                            : "";

            boolean isRequested =
                    participant.has("is_requested_thread") &&
                    participant.get("is_requested_thread").getAsBoolean();

            if (isRequested) {
                requestedThreadName = name;
                continue;
            }

            if (tid == 0 || name.startsWith("swapper")) {
                excludedAsNoise.add(participant);
                continue;
            }

            candidates.add(participant);
        }

        result.add("candidates", candidates);
        result.add("excluded_as_noise", excludedAsNoise);

        /*
         * The ordered chain names the thread the path hands off from right
         * before the requested thread resumes -- a direct observation, so it
         * beats the name-matching heuristic below (which cannot choose
         * between several same-named sibling threads). Skipped when that
         * hand-off is the idle task, per the cross-CPU limitation above.
         */
        JsonObject chain =
                criticalPathResult.has("chain") &&
                criticalPathResult.get("chain").isJsonObject()
                        ? criticalPathResult.getAsJsonObject("chain")
                        : null;

        if (chain != null &&
                chain.has("direct_waker") &&
                chain.get("direct_waker").isJsonObject()) {

            JsonObject waker = chain.getAsJsonObject("direct_waker");
            int wakerTid = waker.get("tid").getAsInt();
            String wakerName = waker.get("name").getAsString();

            if (wakerTid != 0 && !wakerName.startsWith("swapper")) {
                result.addProperty("verdict", "single_likely_cause");
                result.addProperty("likely_cause_tid", wakerTid);
                result.addProperty("likely_cause_name", wakerName);
                result.addProperty("confidence", "high");
                result.addProperty(
                        "basis",
                        "The critical path hands off from TID " + wakerTid +
                        " directly to the requested thread when it " +
                        "resumes, so TID " + wakerTid + " is what woke it.");
                result.add("root_activity", chain.get("root_activity"));
                return result;
            }
        }

        if (candidates.size() == 0) {
            result.addProperty("verdict", "no_cause_found");
            result.add("likely_cause_tid", JsonNull.INSTANCE);
            result.add("likely_cause_name", JsonNull.INSTANCE);
            result.addProperty("confidence", "n/a");
            result.addProperty(
                    "basis",
                    "No participant besides the requested thread" +
                    (excludedAsNoise.size() > 0
                            ? " (and the idle task)"
                            : "") +
                    " was found in the critical path for this window. " +
                    "This matches a known limitation, not necessarily a " +
                    "real absence of a cause: the wake may have come " +
                    "from a cross-CPU remote wakeup or a network/" +
                    "softirq-delivered event, neither of which " +
                    "OSCriticalPathModule can currently attribute to " +
                    "the real waking task.");
            return result;
        }

        if (candidates.size() == 1) {
            JsonObject sole = candidates.get(0).getAsJsonObject();

            result.addProperty(
                    "verdict",
                    "single_likely_cause");
            result.addProperty(
                    "likely_cause_tid",
                    sole.get("tid").getAsInt());
            result.add(
                    "likely_cause_name",
                    sole.get("name"));
            result.addProperty("confidence", "high");
            result.addProperty(
                    "basis",
                    "Exactly one non-idle participant besides the " +
                    "requested thread was found in the critical path " +
                    "for this window, so it is the wake cause.");
            return result;
        }

        /*
         * More than one candidate: prefer one sharing the requested
         * thread's own executable name -- a sibling worker thread of the
         * same program is a far more likely wake source than unrelated
         * system activity that merely shared the CPU during the window.
         */
        List<JsonObject> sameNameMatches = new ArrayList<>();

        for (JsonElement element : candidates) {
            JsonObject candidate = element.getAsJsonObject();
            String name =
                    candidate.has("name") &&
                    !candidate.get("name").isJsonNull()
                            ? candidate.get("name").getAsString()
                            : "";

            if (!requestedThreadName.isEmpty() &&
                    name.equals(requestedThreadName)) {
                sameNameMatches.add(candidate);
            }
        }

        if (sameNameMatches.size() == 1) {
            JsonObject match = sameNameMatches.get(0);

            result.addProperty(
                    "verdict",
                    "single_likely_cause");
            result.addProperty(
                    "likely_cause_tid",
                    match.get("tid").getAsInt());
            result.add(
                    "likely_cause_name",
                    match.get("name"));
            result.addProperty("confidence", "medium");
            result.addProperty(
                    "basis",
                    "Multiple non-idle participants were found, but " +
                    "only one shares the requested thread's own " +
                    "executable name (\"" + requestedThreadName + "\"), " +
                    "suggesting a sibling worker thread rather than " +
                    "unrelated system activity that happened to share " +
                    "the same CPU.");
            return result;
        }

        result.addProperty("verdict", "multiple_candidates");
        result.add("likely_cause_tid", JsonNull.INSTANCE);
        result.add("likely_cause_name", JsonNull.INSTANCE);
        result.addProperty("confidence", "low");
        result.addProperty(
                "basis",
                candidates.size() +
                " non-idle participants were found with no reliable " +
                "way to disambiguate the true wake source from this " +
                "data alone (e.g. real system activity that happened " +
                "to share a CPU with the requested thread during this " +
                "window). Treat all listed candidates as merely " +
                "correlated, not confirmed causal.");
        return result;
    }

    static final int MAX_CHAIN_SEGMENTS = 40;

    /**
     * Walks the critical path in time order and reports what each thread on
     * it was doing, instead of only which threads took part.
     *
     * The critical-path graph is a single chain: horizontal edges carry what
     * one thread was doing (RUNNING, TIMER, BLOCKED, PREEMPTED, ...), and a
     * vertical edge is a hand-off to another thread. A thread's timeline only
     * resumes where the path returns to it, so following the outgoing
     * vertical edge first (when there is one) and the horizontal edge
     * otherwise reproduces the path exactly.
     *
     * From that ordered walk this derives the two facts a "why was this wait
     * so long?" answer needs: the direct waker (the last other thread on the
     * path before the requested thread resumes) and the root activity (the
     * longest stretch any other thread spent on the path, with its state --
     * e.g. another thread sleeping on a timer while holding a lock).
     */
    static JsonObject describeCriticalPathChain(
            ITmfGraph criticalPathGraph,
            OsWorker requestedWorker,
            int requestedTid) {

        List<JsonObject> segments = new ArrayList<>();
        ITmfVertex vertex = criticalPathGraph.getHead(requestedWorker);
        int guard = 0;

        while (vertex != null && guard++ < 1_000_000) {
            ITmfEdge edge =
                    criticalPathGraph.getEdgeFrom(
                            vertex,
                            ITmfGraph.EdgeDirection.OUTGOING_VERTICAL_EDGE);

            if (edge != null) {
                vertex = edge.getVertexTo();
                continue;
            }

            edge = criticalPathGraph.getEdgeFrom(
                    vertex,
                    ITmfGraph.EdgeDirection.OUTGOING_HORIZONTAL_EDGE);

            if (edge == null) {
                break;
            }

            IGraphWorker parent =
                    criticalPathGraph.getParentOf(edge.getVertexFrom());
            long startNs = edge.getVertexFrom().getTimestamp();
            long endNs = edge.getVertexTo().getTimestamp();
            vertex = edge.getVertexTo();

            if (!(parent instanceof OsWorker) || endNs <= startNs) {
                continue;
            }

            OsWorker osWorker = (OsWorker) parent;
            int segmentTid = osWorker.getHostThread().getTid();
            String state =
                    String.valueOf(
                            edge.getEdgeContextState().getContextEnum());

            JsonObject last =
                    segments.isEmpty()
                            ? null
                            : segments.get(segments.size() - 1);

            if (last != null &&
                    last.get("tid").getAsInt() == segmentTid &&
                    last.get("state").getAsString().equals(state)) {
                last.addProperty("end_ns", endNs);
                continue;
            }

            JsonObject segment = new JsonObject();
            segment.addProperty("tid", segmentTid);
            segment.addProperty("name", osWorker.getName());
            segment.addProperty("state", state);
            segment.addProperty("start_ns", startNs);
            segment.addProperty("end_ns", endNs);
            segments.add(segment);
        }

        JsonObject directWaker = null;
        JsonObject rootActivity = null;
        long pathNs = 0;
        long idleNs = 0;

        for (JsonObject segment : segments) {
            long durationNs =
                    segment.get("end_ns").getAsLong() -
                    segment.get("start_ns").getAsLong();
            segment.addProperty("duration_ms", durationNs / 1_000_000.0);
            pathNs += durationNs;

            int segmentTid = segment.get("tid").getAsInt();

            if (segmentTid == requestedTid) {
                continue;
            }

            directWaker = segment;

            /*
             * The idle task is never a real cause (same rule as
             * correlateBlockedIntervalCause); time attributed to it is
             * reported separately as idle_task_ms instead.
             */
            if (segmentTid == 0) {
                idleNs += durationNs;
                continue;
            }

            if (rootActivity == null ||
                    durationNs > rootActivity.get("end_ns").getAsLong() -
                            rootActivity.get("start_ns").getAsLong()) {
                rootActivity = segment;
            }
        }

        JsonArray ordered = new JsonArray();
        boolean truncated = segments.size() > MAX_CHAIN_SEGMENTS;

        List<JsonObject> kept = segments;

        if (truncated) {
            kept = new ArrayList<>(segments);
            kept.sort((a, b) -> Double.compare(
                    b.get("duration_ms").getAsDouble(),
                    a.get("duration_ms").getAsDouble()));
            kept = new ArrayList<>(kept.subList(0, MAX_CHAIN_SEGMENTS));
            kept.sort((a, b) -> Long.compare(
                    a.get("start_ns").getAsLong(),
                    b.get("start_ns").getAsLong()));
        }

        for (JsonObject segment : kept) {
            ordered.add(segment);
        }

        JsonObject chain = new JsonObject();
        chain.add("segments", ordered);
        chain.addProperty("segment_count", segments.size());
        chain.addProperty("truncated_to_longest", truncated);
        chain.add(
                "direct_waker",
                directWaker == null ? JsonNull.INSTANCE : directWaker);
        chain.add(
                "root_activity",
                rootActivity == null ? JsonNull.INSTANCE : rootActivity);
        chain.addProperty("idle_task_ms", idleNs / 1_000_000.0);
        chain.addProperty(
                "idle_task_percent_of_path",
                pathNs == 0 ? 0.0 : idleNs * 100.0 / pathNs);

        /*
         * Confirmed on blocked_chain_demo.c's first capture: without
         * timer/interrupt events in the trace (timer_hrtimer_expire_*,
         * irq_*), Trace Compass cannot tell a timer wake-up from one done by
         * whatever task was running -- usually the idle task -- so the path
         * follows the idle task through every timer sleep instead of stopping
         * at a TIMER edge.
         */
        if (pathNs > 0 && idleNs * 2 > pathNs) {
            chain.addProperty(
                    "warning",
                    "Most of this critical path is attributed to the idle " +
                    "task. This usually means the trace has no timer/" +
                    "interrupt events (timer_hrtimer_expire_*, irq_*), so " +
                    "timer wake-ups could not be recognized and the real " +
                    "root activity may be missing from the path.");
        }

        chain.addProperty(
                "note",
                "segments is the critical path in time order: which thread " +
                "the requested thread's progress depended on at each moment " +
                "and what that thread was doing (state = the execution " +
                "graph's edge type, e.g. RUNNING, TIMER, BLOCKED, " +
                "PREEMPTED). direct_waker is the last other thread on the " +
                "path before the requested thread resumed; root_activity is " +
                "the longest stretch any other thread spent on the path.");
        return chain;
    }

    /**
     * Computes the OS critical path for one thread and summarizes which
     * other threads/processes are causally part of it.
     *
     * This is a deeper analysis than {@link #collectWakeUpDependencies}:
     * that method only checks for a single wake-up edge at the end of each
     * sampled BLOCKED interval. The critical path instead walks the full
     * execution graph to find the actual causal chain -- across however
     * many other threads and hosts are involved -- that this thread's
     * total duration is attributable to. Trace Compass's own
     * {@link OSCriticalPathModule} computes this; this method runs it
     * synchronously (schedule + waitForCompletion, the same pattern
     * already used for {@link OsExecutionGraph} itself) and summarizes the
     * result rather than exposing the raw graph.
     *
     * This method deliberately does not reuse the {@link ITmfGraph} or
     * {@link OsWorker} obtained inside collectWakeUpDependencies(): it
     * performs its own execution-graph lookup instead, so a change here
     * cannot affect that already-working method. Re-scheduling an
     * already-completed analysis module is a cheap, cached no-op in Trace
     * Compass, so this does not meaningfully duplicate work.
     *
     * Unbounded overload, kept for the manual "critical path" chat command
     * (see {@link #tryHandleCriticalPathCommand}), which has no specific
     * interval to scope to. See the windowed overload below for the version
     * used by the normal question-answering flow.
     */
    static JsonObject collectCriticalPath(
            ITmfTrace trace,
            int tid) {
        return collectCriticalPath(trace, tid, null, null);
    }

    /**
     * Same as {@link #collectCriticalPath(ITmfTrace, int)}, but scoped to a
     * specific time window instead of the worker's entire recorded lifetime,
     * when {@code windowStartNs}/{@code windowEndNs} are non-null.
     *
     * On a long-lived worker (minutes to hours -- the common case on real
     * traces, unlike short synthetic ones), {@link OSCriticalPathModule}
     * otherwise always walks the worker's *entire* history even when only
     * one short interval is relevant, per critical_path_improvements.md.
     * That document also verified, directly against the Trace Compass
     * source, that the underlying algorithm
     * ({@code ICriticalPathAlgorithm#computeCriticalPath}) already accepts a
     * bounded start/end vertex -- {@link AbstractCriticalPathModule} (in
     * this same workspace's Trace Compass source checkout) was extended
     * with {@code PARAM_WINDOW_START}/{@code PARAM_WINDOW_END} parameters to
     * expose that, rather than requiring a subclass here.
     *
     * @param windowStartNs
     *            nanosecond timestamp to start the search from, or
     *            {@code null} to use the worker's actual first vertex
     *            (unbounded start, the original behavior)
     * @param windowEndNs
     *            nanosecond timestamp to stop the search at (exclusive), or
     *            {@code null} to run to the worker's natural end (unbounded
     *            end, the original behavior)
     */
    static JsonObject collectCriticalPath(
            ITmfTrace trace,
            int tid,
            @Nullable Long windowStartNs,
            @Nullable Long windowEndNs) {

        JsonObject result = new JsonObject();

        OsExecutionGraph executionGraphModule =
                TmfTraceUtils.getAnalysisModuleOfClass(
                        trace,
                        OsExecutionGraph.class,
                        OsExecutionGraph.ANALYSIS_ID);

        if (executionGraphModule == null) {
            result.addProperty(
                    "available",
                    false);

            result.addProperty(
                    "reason",
                    "No OS execution graph analysis module was found for " +
                    "this trace.");

            return result;
        }

        executionGraphModule.schedule();
        executionGraphModule.waitForCompletion();

        ITmfGraph graph = executionGraphModule.getTmfGraph();

        if (graph == null) {
            result.addProperty(
                    "available",
                    false);

            result.addProperty(
                    "reason",
                    "The execution graph could not be built for this " +
                    "trace. It requires sched_switch and sched_wakeup " +
                    "events.");

            return result;
        }

        OsWorker worker = findOsWorker(graph, tid);

        if (worker == null) {
            result.addProperty(
                    "available",
                    false);

            result.addProperty(
                    "reason",
                    "TID " + tid +
                    " was not found as a worker in the execution graph. " +
                    describeAvailableWorkers(graph, tid));

            return result;
        }

        /*
         * Diagnostic: check whether this exact worker instance already has
         * a head vertex on the *original* execution graph, before handing
         * it to OSCriticalPathModule. AbstractCriticalPathModule#execute
         * Analysis() re-fetches graphModule.getTmfGraph() internally and
         * calls graph.getHead(worker) on that -- if that call returns null
         * there, executeAnalysis() still returns true (an empty critical
         * path graph is a "successful" trivial result in that code path),
         * which is one possible explanation for a should-be-populated
         * result coming back as the generic "no critical path graph"
         * message below. Checking it here, on the same graph/worker pair
         * findOsWorker() already resolved, tells us whether that null
         * originates from the worker genuinely having no vertex data at
         * all (true both here and inside the module), as opposed to some
         * instance/identity mismatch specific to the module's internal
         * re-fetch.
         */
        ITmfVertex directHead = graph.getHead(worker);

        System.err.println("[CRITPATH-DEBUG][caller] worker=" + worker +
                " identityHash=" + System.identityHashCode(worker) +
                " graphIdentityHash=" + System.identityHashCode(graph) +
                " directHead=" + directHead);

        OSCriticalPathModule criticalPathModule =
                new OSCriticalPathModule(executionGraphModule, worker);

        /*
         * Constructing with (graph, worker) above already sets PARAM_WORKER
         * with fScheduleOnParameterChange=false, so setting these two
         * additional parameters here does not trigger an unwanted
         * schedule() -- see AbstractCriticalPathModule's constructor.
         */
        if (windowStartNs != null) {
            criticalPathModule.setParameter(
                    AbstractCriticalPathModule.PARAM_WINDOW_START,
                    windowStartNs);
        }

        if (windowEndNs != null) {
            criticalPathModule.setParameter(
                    AbstractCriticalPathModule.PARAM_WINDOW_END,
                    windowEndNs);
        }

        /*
         * Unlike executionGraphModule (obtained via
         * TmfTraceUtils.getAnalysisModuleOfClass(), which returns a module
         * already bound to the trace through Trace Compass's normal
         * analysis-module registry), this module is hand-constructed and
         * has no trace of its own yet. TmfAbstractAnalysisModule#schedule()
         * silently no-ops (returns an error IStatus without ever calling
         * executeAnalysis()) when getTrace() == null, which is exactly
         * what was happening here -- every prior "no critical path graph
         * was produced" result was this, not a real graph/data limitation.
         */
        try {
            criticalPathModule.setTrace(trace);
        } catch (TmfAnalysisException exception) {
            result.addProperty(
                    "available",
                    false);

            result.addProperty(
                    "reason",
                    "Could not bind the critical path module to the " +
                    "trace: " + exception.getMessage());

            return result;
        }

        try {
            criticalPathModule.schedule();

            if (!criticalPathModule.waitForCompletion()) {
                result.addProperty(
                        "available",
                        false);

                result.addProperty(
                        "reason",
                        "Critical path computation did not complete " +
                        "successfully for this thread.");

                return result;
            }

            ITmfGraph criticalPathGraph =
                    criticalPathModule.getCriticalPathGraph();

            if (criticalPathGraph == null) {
                result.addProperty(
                        "available",
                        false);

                result.addProperty(
                        "reason",
                        "No critical path graph was produced for this " +
                        "thread (it may never have run, or have no " +
                        "recorded dependencies). Diagnostic: this worker " +
                        (directHead == null ?
                                "also has no head vertex on the original " +
                                "execution graph (graph.getHead(worker) " +
                                "== null there too) -- the worker is " +
                                "registered but has no vertex data at " +
                                "all, not a critical-path-module-specific " +
                                "issue." :
                                "DOES have a head vertex on the original " +
                                "execution graph (at timestamp " +
                                directHead.getTimestamp() +
                                ") -- the data exists, so this looks like " +
                                "an issue specific to how " +
                                "OSCriticalPathModule re-resolves the " +
                                "worker/graph internally, not missing " +
                                "trace data.") +
                        "");

                return result;
            }

            ITmfVertex head = criticalPathGraph.getHead(worker);
            ITmfVertex tail = criticalPathGraph.getTail(worker);

            if (head == null || tail == null) {
                result.addProperty(
                        "available",
                        false);

                result.addProperty(
                        "reason",
                        "The critical path graph has no vertices for " +
                        "this thread.");

                return result;
            }

            long spanNs = tail.getTimestamp() - head.getTimestamp();

            JsonArray participants = new JsonArray();
            int otherWorkerCount = 0;

            for (IGraphWorker participant : criticalPathGraph.getWorkers()) {
                if (!(participant instanceof OsWorker)) {
                    continue;
                }

                OsWorker osParticipant = (OsWorker) participant;
                boolean isRequestedWorker =
                        osParticipant.getHostThread().getTid() == tid &&
                        osParticipant.getHostId().equals(
                                worker.getHostId());

                if (!isRequestedWorker) {
                    otherWorkerCount++;
                }

                JsonObject participantJson = new JsonObject();

                participantJson.addProperty(
                        "tid",
                        osParticipant.getHostThread().getTid());

                participantJson.addProperty(
                        "name",
                        osParticipant.getName());

                participantJson.addProperty(
                        "host",
                        osParticipant.getHostId());

                participantJson.addProperty(
                        "is_requested_thread",
                        isRequestedWorker);

                participants.add(participantJson);
            }

            result.add(
                    "chain",
                    describeCriticalPathChain(
                            criticalPathGraph,
                            worker,
                            tid));

            result.addProperty("available", true);
            result.addProperty("span_ns", spanNs);
            result.addProperty("span_ms", spanNs / 1_000_000.0);
            result.addProperty(
                    "participant_count",
                    participants.size());
            result.addProperty(
                    "other_thread_count",
                    otherWorkerCount);
            result.add("participants", participants);
            result.addProperty(
                    "windowed",
                    windowStartNs != null || windowEndNs != null);

            if (windowStartNs != null) {
                result.addProperty("window_start_ns", windowStartNs);
            }

            if (windowEndNs != null) {
                result.addProperty("window_end_ns", windowEndNs);
            }

            result.addProperty(
                    "note",
                    "participants lists every thread/process the " +
                    "execution graph's critical-path algorithm found to " +
                    "be causally part of this thread's total duration -- " +
                    "not just a single wake-up, but the full dependency " +
                    "chain. other_thread_count > 0 means at least one " +
                    "other thread's execution is on the critical path, " +
                    "i.e. this thread's duration is not explained by its " +
                    "own behavior alone. When \"windowed\" is true, the " +
                    "search was scoped to [window_start_ns, window_end_ns) " +
                    "instead of this worker's entire recorded lifetime -- " +
                    "see critical_path_improvements.md.");

            return result;
        } finally {
            retireTemporaryCriticalPath(trace, criticalPathModule);
            restoreCriticalPathBinding(trace);
        }
    }

    /**
     * Finds the execution-graph worker matching a TID.
     *
     * A trace can contain multiple {@link OsWorker} records for the same
     * TID over its lifetime (e.g. after exec or TID reuse). This used to
     * return the first match found, on the assumption that was
     * "sufficient for the sampled lookups here." Testing against
     * noferesti-elk-trace TID 20990 disproved that: the first-matching
     * instance turned out to be a 1.3ms-lived fork/exec-boundary
     * artifact, not the ~120-second instance the thread's real recorded
     * activity (per TMLL's known_active_duration_ms) shows it should
     * have -- so every "heavy" TID tried against this trace in this
     * investigation was very likely being resolved to the wrong
     * instance. This now returns the matching instance with the largest
     * head-to-tail span instead, which is far more likely to be the one
     * a question about this TID's actual behavior is asking about. When
     * only one instance matches (the common case), this returns exactly
     * what the old first-match logic would have.
     */
    static OsWorker findOsWorker(
            ITmfGraph graph,
            int tid) {

        OsWorker bestCandidate = null;
        long bestSpanNs = -1;

        for (IGraphWorker candidate : graph.getWorkers()) {
            if (!(candidate instanceof OsWorker)) {
                continue;
            }

            OsWorker osCandidate = (OsWorker) candidate;

            if (osCandidate.getHostThread().getTid() != tid) {
                continue;
            }

            ITmfVertex candidateHead = graph.getHead(osCandidate);
            ITmfVertex candidateTail = graph.getTail(osCandidate);

            long candidateSpanNs =
                    (candidateHead != null && candidateTail != null) ?
                            candidateTail.getTimestamp() -
                                    candidateHead.getTimestamp() :
                            0;

            if (bestCandidate == null || candidateSpanNs > bestSpanNs) {
                bestCandidate = osCandidate;
                bestSpanNs = candidateSpanNs;
            }
        }

        return bestCandidate;
    }

    /**
     * Builds a diagnostic description of the execution graph's actual
     * worker set, for when {@link #findOsWorker} fails to find a match.
     *
     * This mirrors the "closest available TIDs" pattern already used on
     * the Python/TMLL side (matching_thread_entry_ids in
     * tmll_control_flow_probe_syscall_v1.py) so a lookup failure here is
     * similarly self-diagnosing instead of an opaque "not found". This
     * trace is a combined multi-host experiment (client/db/httpd), and the
     * execution-graph analysis is known to sometimes only build workers
     * from a subset of the constituent traces; reporting which hosts and
     * TIDs the graph actually has lets that be confirmed directly from the
     * assistant's own output instead of guessed at.
     */
    static String describeAvailableWorkers(
            ITmfGraph graph,
            int tid) {

        Set<Integer> tidsSeen = new TreeSet<>();
        Set<String> hostsSeen = new TreeSet<>();
        int totalWorkers = 0;

        for (IGraphWorker candidate : graph.getWorkers()) {
            if (candidate instanceof OsWorker) {
                OsWorker osCandidate = (OsWorker) candidate;

                totalWorkers++;
                tidsSeen.add(osCandidate.getHostThread().getTid());
                hostsSeen.add(osCandidate.getHostId());
            }
        }

        List<Integer> nearestTids = tidsSeen.stream()
                .sorted(Comparator.comparingInt(
                        candidateTid -> Math.abs(candidateTid - tid)))
                .limit(15)
                .collect(Collectors.toList());

        return "The execution graph has " + totalWorkers +
                " worker(s) across " + hostsSeen.size() +
                " host(s) (" + String.join(", ", hostsSeen) + "). " +
                "Closest available TIDs: " + nearestTids + ".";
    }

    /**
     * Converts Trace Compass ProcessStatus values into clearer names
     * for the language model.
     */
    static String controlFlowStateName(
            ProcessStatus status) {

        switch (status) {
        case RUN:
            return "RUNNING_USER_MODE";

        case RUN_SYTEMCALL:
            /*
             * RUN_SYTEMCALL is the spelling used by the
             * Trace Compass ProcessStatus enum.
             */
            return "RUNNING_SYSTEM_CALL";

        case WAIT_CPU:
            return "RUNNABLE_WAITING_FOR_CPU";

        case WAIT_BLOCKED:
            return "BLOCKED";

        case INTERRUPTED:
            return "INTERRUPTED";

        case WAIT_FORK:
            return "WAITING_FOR_FORK";

        case WAIT_UNKNOWN:
            return "WAITING_UNKNOWN";

        case NOT_ALIVE:
            return "NOT_ALIVE";

        case EXIT:
            return "EXITED";

        case ZOMBIE:
            return "ZOMBIE";

        case UNKNOWN:
        default:
            return "UNKNOWN";
        }
    }

    /**
     * Calculates the duration of an interval whose endpoints are
     * both inclusive.
     */
    static long inclusiveDuration(
            long start,
            long endInclusive) {

        if (endInclusive < start) {
            return 0;
        }

        long difference =
                endInclusive - start;

        if (difference == Long.MAX_VALUE) {
            return Long.MAX_VALUE;
        }

        return difference + 1;
    }

    /**
     * Asks the local Python/TMLL service for the thread's late cycles (the
     * late-cycle window finder) -- see periodic_thread_delay_design.md.
     *
     * @param tid
     *            thread ID requested by the user
     * @param expectedPeriodNs
     *            expected activation period in nanoseconds, or
     *            {@code null} to auto-infer it from the median observed
     *            period
     * @return JSON returned by the TMLL service
     * @throws Exception
     *             if the service cannot be reached or returns an error
     */
    String callTmllPeriodicJitter(
            int tid,
            @Nullable Long expectedPeriodNs) throws Exception {

        JsonObject body = new JsonObject();

        body.addProperty(
                "trace_path",
                requireActiveTracePath());

        body.addProperty(
                "tid",
                tid);

        if (expectedPeriodNs != null) {
            body.addProperty(
                    "expected_period_ns",
                    expectedPeriodNs);
        }

        /*
         * The service defaults to "100us" when this is omitted -- far too
         * coarse for a sub-millisecond-period thread. Confirmed directly
         * (periodic_thread_delay_design.md, Finding 3/testing notes): at
         * 100us resolution a real 800-cycle, ~1ms-period thread's
         * RUNNING-state intervals get badly aliased (activation counts and
         * gap boundaries come out wrong, not just less precise), which is
         * exactly what produced a bogus 123ms/inconsistent-percentage
         * result here instead of the validated, clean 30.5ms/98.4% one.
         * "1us" is what that validation actually used.
         */
        body.addProperty(
                "resolution",
                "1us");

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        TMLL_PERIODIC_JITTER_URL))
                        .timeout(TMLL_TIMEOUT)
                        .header(
                                "Content-Type",
                                "application/json")
                        .POST(
                                HttpRequest.BodyPublishers
                                        .ofString(
                                                body.toString()))
                        .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 ||
                response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "TMLL periodic jitter analysis failed: HTTP " +
                    response.statusCode() +
                    "\n" +
                    response.body());
        }

        return response.body();
    }

    /**
     * Extracts an optional expected-period clause ("every 1ms"/"every
     * 500us") from a free-form question, in nanoseconds.
     *
     * @return the expected period in nanoseconds, or {@code null} if the
     *         question does not state one (in which case
     *         {@code detect_periodic_jitter_anomalies()} auto-infers it
     *         from the median observed period instead)
     */
    static @Nullable Long extractExpectedPeriodNs(
            String userMessage) {

        Matcher matcher =
                EXPECTED_PERIOD_PATTERN.matcher(userMessage);

        if (!matcher.find()) {
            return null;
        }

        long value = Long.parseLong(matcher.group(1));
        String unit = matcher.group(2).toLowerCase(Locale.ROOT);

        if (unit.startsWith("us") || unit.startsWith("micro")) {
            return value * 1_000L;
        }

        return value * 1_000_000L;
    }

    static final class TimeWindow {
        final long startNs;
        final long endNs;
        final String interpretation;

        TimeWindow(long startNs, long endNs, String interpretation) {
            this.startNs = startNs;
            this.endNs = endNs;
            this.interpretation = interpretation;
        }
    }

    /**
     * Finds a time window in the question. Tried in order: absolute
     * nanosecond timestamps, clock times as Trace Compass displays them (in
     * its display time zone), then offsets from the trace start with units
     * ("between 1.2 and 1.5 ms"; with "between"/"from", a missing unit means
     * seconds). The window is clamped to the trace; if it does not overlap
     * it, start ends up after end.
     */
    static @Nullable TimeWindow parseTimeWindow(
            String question,
            long traceStart,
            long traceEnd) {

        Long first = null;
        Long second = null;
        String interpretation = null;

        Matcher matcher = ABSOLUTE_NS_WINDOW_PATTERN.matcher(question);

        if (matcher.find()) {
            first = Long.parseLong(matcher.group(1));
            second = Long.parseLong(matcher.group(2));
            interpretation = "absolute timestamps in nanoseconds";
        }

        if (first == null) {
            matcher = CLOCK_WINDOW_PATTERN.matcher(question);

            if (matcher.find()) {
                first = clockTimeToNs(matcher.group(1), traceStart, traceEnd);
                second = clockTimeToNs(matcher.group(2), traceStart, traceEnd);
                interpretation =
                        "clock times in Trace Compass's display time zone (" +
                        TmfTimePreferences.getTimeZone().getID() + ")";
            }
        }

        if (first == null) {
            matcher = RELATIVE_WINDOW_WITH_KEYWORD_PATTERN.matcher(question);

            if (!matcher.find()) {
                matcher = RELATIVE_WINDOW_PATTERN.matcher(question);

                if (!matcher.find()) {
                    return null;
                }
            }

            String unit1 = matcher.group(2);
            String unit2 = matcher.group(4);
            String unitA = unit1 != null ? unit1 : unit2;
            String unitB = unit2 != null ? unit2 : unit1;

            first = traceStart + toNanos(matcher.group(1), unitA);
            second = traceStart + toNanos(matcher.group(3), unitB);
            interpretation =
                    "offsets from the start of the trace (" +
                    matcher.group(1) + " " + (unitA == null ? "s" : unitA) +
                    " to " + matcher.group(3) + " " +
                    (unitB == null ? "s" : unitB) + ")";
        }

        if (first == null || second == null) {
            return null;
        }

        long start = Math.max(Math.min(first, second), traceStart);
        long end = Math.min(Math.max(first, second), traceEnd);
        return new TimeWindow(start, end, interpretation);
    }

    static long toNanos(String value, @Nullable String unit) {
        String u = unit == null ? "s" : unit.toLowerCase(Locale.ROOT);
        long scale =
                u.startsWith("n") ? 1L
                : u.startsWith("us") || u.startsWith("µ") ||
                        u.startsWith("micro") ? 1_000L
                : u.startsWith("ms") || u.startsWith("milli") ? 1_000_000L
                : 1_000_000_000L;

        return new java.math.BigDecimal(value)
                .multiply(java.math.BigDecimal.valueOf(scale))
                .longValue();
    }

    /**
     * Converts "HH:MM:SS[.fraction]" to a timestamp on the trace's date in
     * Trace Compass's display time zone, moving it by a day if that lands it
     * more than 12 hours outside the trace (a trace spanning midnight).
     */
    static @Nullable Long clockTimeToNs(
            String text,
            long traceStart,
            long traceEnd) {

        String[] parts = text.trim().split("[.,]", 2);
        String[] hms = parts[0].split(":");

        if (hms.length != 3) {
            return null;
        }

        String fraction =
                parts.length > 1 ? parts[1].replace(" ", "") : "";

        if (fraction.length() > 9) {
            fraction = fraction.substring(0, 9);
        }

        long fractionNs =
                fraction.isEmpty()
                        ? 0
                        : Long.parseLong(
                                (fraction + "000000000").substring(0, 9));

        java.time.ZoneId zone =
                TmfTimePreferences.getTimeZone().toZoneId();
        java.time.LocalDate date =
                java.time.Instant
                        .ofEpochSecond(0, traceStart)
                        .atZone(zone)
                        .toLocalDate();
        long seconds =
                java.time.LocalDateTime
                        .of(date,
                                java.time.LocalTime.of(
                                        Integer.parseInt(hms[0]),
                                        Integer.parseInt(hms[1]),
                                        Integer.parseInt(hms[2])))
                        .atZone(zone)
                        .toEpochSecond();
        long ns = seconds * 1_000_000_000L + fractionNs;
        long halfDay = 12L * 3600 * 1_000_000_000L;

        if (ns < traceStart - halfDay) {
            ns += 2 * halfDay;
        } else if (ns > traceEnd + halfDay) {
            ns -= 2 * halfDay;
        }

        return ns;
    }

    /**
     * One deterministic sentence per blocked gap, so the LLM phrases an
     * already-read chain instead of reconstructing it from raw segments.
     */
    static String summarizeBlockedGap(
            int tid,
            JsonObject criticalPath) {

        if (!criticalPath.has("available") ||
                !criticalPath.get("available").getAsBoolean() ||
                !criticalPath.has("chain")) {
            return "No critical path is available for this gap" +
                    (criticalPath.has("reason")
                            ? ": " + criticalPath.get("reason").getAsString()
                            : ".");
        }

        JsonObject chain = criticalPath.getAsJsonObject("chain");

        /* Consecutive segments of one thread become one run. */
        List<String> runs = new ArrayList<>();
        int runTid = Integer.MIN_VALUE;
        String runName = "";
        Map<String, Double> runStates = new LinkedHashMap<>();

        for (JsonElement element : chain.getAsJsonArray("segments")) {
            JsonObject segment = element.getAsJsonObject();
            int segmentTid = segment.get("tid").getAsInt();

            if (segmentTid != runTid && !runStates.isEmpty()) {
                runs.add(formatRun(runTid, runName, runStates));
                runStates = new LinkedHashMap<>();
            }

            runTid = segmentTid;
            runName = segment.get("name").getAsString();
            runStates.merge(
                    segment.get("state").getAsString(),
                    segment.get("duration_ms").getAsDouble(),
                    Double::sum);
        }

        if (!runStates.isEmpty()) {
            runs.add(formatRun(runTid, runName, runStates));
        }

        StringBuilder summary = new StringBuilder(
                "Critical path of TID " + tid +
                " over this gap, in time order: " +
                String.join(" -> ", runs) + ".");

        if (chain.get("direct_waker").isJsonObject()) {
            JsonObject waker = chain.getAsJsonObject("direct_waker");
            summary.append(" Direct waker (last other thread before TID ")
                    .append(tid)
                    .append(" resumed): TID ")
                    .append(waker.get("tid").getAsInt())
                    .append(" (")
                    .append(waker.get("name").getAsString())
                    .append(").");
        }

        if (chain.get("root_activity").isJsonObject()) {
            JsonObject root = chain.getAsJsonObject("root_activity");
            summary.append(String.format(
                    Locale.ROOT,
                    " Longest activity the wait depended on: TID %d (%s) " +
                    "in state %s for %.3f ms.",
                    root.get("tid").getAsInt(),
                    root.get("name").getAsString(),
                    root.get("state").getAsString(),
                    root.get("duration_ms").getAsDouble()));
        }

        if (chain.has("warning")) {
            summary.append(" WARNING: ")
                    .append(chain.get("warning").getAsString());
        }

        return summary.toString();
    }

    static String formatRun(
            int tid,
            String name,
            Map<String, Double> stateMs) {

        List<String> parts = new ArrayList<>();

        for (Map.Entry<String, Double> entry : stateMs.entrySet()) {
            parts.add(String.format(
                    Locale.ROOT,
                    "%s %.3f ms",
                    entry.getKey(),
                    entry.getValue()));
        }

        return "TID " + tid + " (" + name + ") " + String.join(", ", parts);
    }

    /**
     * Requests sampled thread-state analysis from the local Python/TMLL
     * service.
     *
     * @param tid
     *            thread ID requested by the user
     * @return JSON returned by the TMLL service
     * @throws Exception
     *             if the service cannot be reached or returns an error
     */
    String callTmllThreadAnalysis(
            int tid) throws Exception {

        JsonObject body = new JsonObject();

        body.addProperty(
                "trace_path",
                requireActiveTracePath());

        body.addProperty(
                "tid",
                tid);

        body.addProperty(
                "resolution",
                "100us");

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        TMLL_THREAD_ANALYSIS_URL))
                        .timeout(TMLL_TIMEOUT)
                        .header(
                                "Content-Type",
                                "application/json")
                        .POST(
                                HttpRequest.BodyPublishers
                                        .ofString(
                                                body.toString()))
                        .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 ||
                response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "TMLL analysis failed: HTTP " +
                    response.statusCode() +
                    "\n" +
                    response.body());
        }

        return response.body();
    }

    /** One time window an answer is about. */
    /**
     * Some state-system attributes' intervals over a time range, loaded in
     * one sweep of the history (query2D) and searched in memory. Querying
     * the on-disk history one point at a time inside a loop took minutes to
     * hours on a 30-minute system-wide trace.
     */
    static final class History {
        private final Map<Integer, List<ITmfStateInterval>> fByQuark = new HashMap<>();

        static History load(ITmfStateSystem ss, Collection<Integer> quarks, long start, long end) {
            History history = new History();
            List<Integer> valid = new ArrayList<>();
            for (Integer quark : quarks) {
                if (quark != null && quark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                    valid.add(quark);
                    history.fByQuark.put(quark, new ArrayList<>());
                }
            }
            if (ss == null || valid.isEmpty()) {
                return history;
            }
            long from = Math.max(start, ss.getStartTime());
            long to = Math.min(end, ss.getCurrentEndTime());
            if (to < from) {
                return history;
            }
            try {
                for (ITmfStateInterval interval : ss.query2D(valid, from, to)) {
                    List<ITmfStateInterval> list = history.fByQuark.get(interval.getAttribute());
                    if (list != null) {
                        list.add(interval);
                    }
                }
            } catch (StateSystemDisposedException exception) {
                return history;
            }
            history.fByQuark.values().forEach(list -> list.sort((a, b) -> Long.compare(a.getStartTime(), b.getStartTime())));
            return history;
        }

        List<ITmfStateInterval> intervals(int quark) {
            return fByQuark.getOrDefault(quark, List.of());
        }

        /** Adds (or replaces) one attribute's intervals, loaded separately. */
        void put(int quark, List<ITmfStateInterval> intervals) {
            fByQuark.put(quark, new ArrayList<>(intervals));
        }

        /** The intervals of {@code quark} overlapping [start, end], in time order. */
        List<ITmfStateInterval> intervals(int quark, long start, long end) {
            List<ITmfStateInterval> list = intervals(quark);
            List<ITmfStateInterval> result = new ArrayList<>();
            int low = 0;
            int high = list.size();
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (list.get(mid).getEndTime() < start) {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            for (int i = low; i < list.size() && list.get(i).getStartTime() <= end; i++) {
                result.add(list.get(i));
            }
            return result;
        }

        /** The value of {@code quark} at {@code time}, or null. */
        Object valueAt(int quark, long time) {
            List<ITmfStateInterval> list = intervals(quark);
            int low = 0;
            int high = list.size() - 1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                ITmfStateInterval interval = list.get(mid);
                if (interval.getEndTime() < time) {
                    low = mid + 1;
                } else if (interval.getStartTime() > time) {
                    high = mid - 1;
                } else {
                    return interval.getValue();
                }
            }
            return null;
        }
    }

    static final class ExplainWindow {
        final String about;
        final String source;
        final long start;
        final long end;
        /** Extra facts about how the window was chosen (e.g. a late cycle's period). */
        final JsonObject details;

        ExplainWindow(String about, String source, long start, long end, JsonObject details) {
            this.about = about;
            this.source = source;
            this.start = start;
            this.end = end;
            this.details = details;
        }
    }

    /**
     * The unified architecture's explanation stage (unified_architecture_design.pdf,
     * phase 3). For each window: split the thread's time by state using the
     * exact Trace Compass state system, then explain each state that holds a
     * meaningful share of it with that state's single explainer:
     * <ul>
     * <li>blocked: the system call it blocked in, and the critical path of
     * the longest blocked interval (direct waker, root activity);</li>
     * <li>waiting for a CPU: which threads held the CPU the thread was queued
     * on, read from the CPU's current-thread history;</li>
     * <li>running: exact user/system time and the decoded system-call
     * activity, compared with a normal cycle when the window is a late
     * cycle.</li>
     * </ul>
     * Every result is a finding:
     * <pre>
     * { id, about, state, claim, window, share, evidence {analysis, data},
     *   confidence, caveats }
     * </pre>
     */
    static final class UnifiedExplainer {

        /** A state is explained when it holds at least this share of the window's alive time. */
        private static final double EXPLAIN_SHARE = 0.10;
        /** How many of the longest blocked intervals get their system call reported. */
        private static final int SYSCALL_INTERVALS = 5;

        private final ITmfTrace fTrace;
        private final int fTid;
        private final boolean fDescribe;
        private final KernelAnalysisModule fKernel;
        private final ITmfStateSystem fSs;
        private final long fTraceStart;
        private final JsonArray fFindings = new JsonArray();
        private JsonObject fWholeActivity;
        private Decomposition fWholeDecomposition;

        private UnifiedExplainer(ITmfTrace trace, int tid, boolean describe,
                KernelAnalysisModule kernel, ITmfStateSystem ss) {
            fTrace = trace;
            fTid = tid;
            fDescribe = describe;
            fKernel = kernel;
            fSs = ss;
            fTraceStart = trace.getStartTime().toNanos();
        }

        /**
         * @param windows
         *            the windows the question is about; the whole-trace window
         *            only gets explainers when no more specific window exists
         * @param describe
         *            the question asks what the thread does, so the running
         *            explainer's activity account runs regardless of share
         * @param lateCycleScan
         *            the late-cycle detector's summary, or null if it did not run
         */
        static JsonArray explain(ITmfTrace trace, int tid, List<ExplainWindow> windows,
                boolean describe, JsonObject lateCycleScan) {
            return explain(trace, tid, windows, describe, lateCycleScan, "");
        }

        /**
         * @param question
         *            decides the optional detail findings: its busiest CPU
         *            window (running.cpu_peak), its longest system calls
         *            (syscalls.longest), its wake-up scheduling delays
         *            (scheduling.latency)
         */
        static JsonArray explain(ITmfTrace trace, int tid, List<ExplainWindow> windows,
                boolean describe, JsonObject lateCycleScan, String question) {
            return explain(trace, tid, windows, describe, lateCycleScan, question, Set.of());
        }

        /**
         * @param details
         *            detail findings to add whatever the question's words: any
         *            of "cpu_peak", "syscalls", "sched_latency" (the thread
         *            finder's symptom asks for them)
         */
        static JsonArray explain(ITmfTrace trace, int tid, List<ExplainWindow> windows,
                boolean describe, JsonObject lateCycleScan, String question, Set<String> details) {
            KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                    trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
            if (kernel == null) {
                return new JsonArray();
            }
            kernel.schedule();
            kernel.waitForCompletion();
            ITmfStateSystem ss = kernel.getStateSystem();
            if (ss == null) {
                return new JsonArray();
            }
            UnifiedExplainer explainer = new UnifiedExplainer(trace, tid, describe, kernel, ss);
            explainer.fCpuPeak = CPU_PEAK_WORDS.matcher(question).find() || details.contains("cpu_peak");
            explainer.fSyscallDetail = SYSCALL_WORDS.matcher(question).find() || details.contains("syscalls");
            explainer.fSchedLatency = SCHED_LATENCY_WORDS.matcher(question).find() || details.contains("sched_latency");
            explainer.run(windows, lateCycleScan);
            return explainer.fFindings;
        }

        /**
         * Only the detail findings asked for, over one window, without the
         * per-state explainers (no event scans, no critical paths): the
         * thread search's level 2 (thread_finder_design.md, section 4).
         *
         * @param kinds
         *            any of "cpu_peak" (running.cpu_peak), "syscalls"
         *            (syscalls.longest), "sched_latency" (scheduling.latency)
         */
        static JsonArray details(ITmfTrace trace, int tid, ExplainWindow w, Set<String> kinds) {
            KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                    trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
            ITmfStateSystem ss = kernel == null ? null : kernel.getStateSystem();
            if (ss == null) {
                return new JsonArray();
            }
            UnifiedExplainer explainer = new UnifiedExplainer(trace, tid, false, kernel, ss);
            JsonObject win = explainer.window(w.source, w.start, w.end);
            Decomposition d = explainer.decompose(w.start, w.end);
            explainer.addDecomposition(w, win, d);
            if (kinds.contains("cpu_peak")) {
                explainer.addCpuPeak(w, win, d);
            }
            if (kinds.contains("syscalls")) {
                explainer.addLongestSyscalls(w, win);
            }
            if (kinds.contains("sched_latency")) {
                explainer.addSchedulingLatency(w, win);
            }
            return explainer.fFindings;
        }

        private void run(List<ExplainWindow> windows, JsonObject lateCycleScan) {
            if (lateCycleScan != null) {
                add("window.late_cycle_scan", "late_cycles", null, str(lateCycleScan, "claim"),
                        window("whole_trace", fTraceStart, fTrace.getEndTime().toNanos()), null,
                        "tmll.periodic_jitter", lateCycleScan, "high", new JsonArray());
            }
            boolean specific = windows.stream().anyMatch(w -> !"whole_trace".equals(w.source));
            for (ExplainWindow w : windows) {
                JsonObject win = window(w.source, w.start, w.end);
                if (w.details != null && w.details.has("interpreted_as")) {
                    win.add("interpreted_as", w.details.get("interpreted_as"));
                }
                if ("late_cycle".equals(w.source)) {
                    addLateCycle(w, win);
                }
                Decomposition d = decompose(w.start, w.end);
                if ("whole_trace".equals(w.source)) {
                    fWholeDecomposition = d;
                }
                addDecomposition(w, win, d);
                if ("whole_trace".equals(w.source) && specific) {
                    // Counts of waits to run are about the whole run ("at least 50 times in the trace"),
                    // not only the late cycles explained one by one.
                    if (fSchedLatency) {
                        addSchedulingLatency(w, win);
                    }
                    continue;
                }
                addCpuPlacement(w, win, d);
                if (fCpuPeak) {
                    addCpuPeak(w, win, d);
                }
                if (fSyscallDetail) {
                    addLongestSyscalls(w, win);
                }
                if (fSchedLatency) {
                    addSchedulingLatency(w, win);
                }
                if (d.share("BLOCKED") >= EXPLAIN_SHARE) {
                    explainBlocked(w, win, d);
                }
                /* A small share can still be a real delay: 20 ms of waits, or preemptions by a real-time thread. */
                if (d.share("RUNNABLE_WAITING_FOR_CPU") >= EXPLAIN_SHARE
                        || d.ns("RUNNABLE_WAITING_FOR_CPU") >= 20_000_000L) {
                    explainWaiting(w, win, d);
                }
                if (d.shareRunning() >= EXPLAIN_SHARE || fDescribe) {
                    explainRunning(w, win, d);
                }
            }
            try {
                addCycleTrend();
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addThreadExtras();
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
        }

        /**
         * From the trace's all-process pass (cached): interrupt time on the CPUs this thread runs on, its
         * moves between CPUs, and how late its timers fired (when the trace records timer starts).
         */
        private void addThreadExtras() {
            long traceEnd = fTrace.getEndTime().toNanos();
            JsonObject summary = ThreadActivitySummarizer.summarizeProcesses(fTrace, null, null);
            Integer pid = ProcessExplainer.pidMap(fKernel, fTraceStart, traceEnd).get(fTid);
            JsonObject process = pid == null ? null : obj(obj(summary, "processes"), String.valueOf(pid));
            JsonObject win = window("whole_trace", fTraceStart, traceEnd);
            // The CPUs carrying at least 5% of its running time.
            int threadQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid));
            int rqQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "Current_cpu_rq");
            Map<Integer, Long> byCpu = new HashMap<>();
            long total = 0;
            if (rqQuark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                for (ITmfStateInterval interval : history().intervals(threadQuark)) {
                    String state = controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                    if (state.startsWith("RUNNING")) {
                        Object cpu = history().valueAt(rqQuark, interval.getStartTime());
                        if (cpu instanceof Integer) {
                            long length = interval.getEndTime() - interval.getStartTime() + 1;
                            byCpu.merge((Integer) cpu, length, Long::sum);
                            total += length;
                        }
                    }
                }
            }
            List<Integer> cpus = new ArrayList<>();
            for (Map.Entry<Integer, Long> entry : byCpu.entrySet()) {
                if (entry.getValue() * 20 >= total) {
                    cpus.add(entry.getKey());
                }
            }
            JsonObject interrupts = obj(summary, "interrupts_by_cpu");
            if (interrupts != null && !cpus.isEmpty()) {
                ProcessExplainer.addInterruptFinding(fFindings, interrupts, cpus, fTraceStart, traceEnd, fTraceStart,
                        "thread " + fTid, win, "thread " + fTid + " (" + threadName(fTid) + ")");
            }
            if (process == null) {
                return;
            }
            // On the CPU nearly all the time in its own code, with almost no system calls.
            Decomposition whole = fWholeDecomposition != null ? fWholeDecomposition : decompose(fTraceStart, traceEnd);
            long calls = 0;
            JsonObject threadCalls = obj(obj(process, "syscalls_by_thread"), String.valueOf(fTid));
            if (threadCalls != null) {
                for (Map.Entry<String, JsonElement> call : threadCalls.entrySet()) {
                    calls += call.getValue().getAsLong();
                }
            }
            double aliveSeconds = Math.max(1e-3, whole.alive / 1e9);
            if (whole.alive > 0 && whole.running() >= 0.8 * whole.alive
                    && whole.ns("RUNNING_USER_MODE") >= 0.95 * whole.running() && calls / aliveSeconds < 10) {
                JsonObject data = new JsonObject();
                data.addProperty("running_percent", whole.running() * 100.0 / whole.alive);
                data.addProperty("user_mode_percent_of_running", whole.ns("RUNNING_USER_MODE") * 100.0 / Math.max(1, whole.running()));
                data.addProperty("system_calls", calls);
                data.addProperty("system_calls_per_second", calls / aliveSeconds);
                add("running.spin_or_compute", "thread " + fTid, "running", String.format(Locale.ROOT,
                        "TID %d (%s) is on the CPU %.1f%% of its life, almost all in its own code, with %d system calls (%.1f per "
                                + "second): it never waits. A busy-wait (a loop checking a flag until another thread sets it) "
                                + "looks like this, and so does nonstop computation; the trace cannot tell them apart by itself.",
                        fTid, threadName(fTid), whole.running() * 100.0 / whole.alive, calls, calls / aliveSeconds),
                        win, null, "tracecompass.state_system+java.thread_activity", data, "high", new JsonArray());
            }
            JsonObject migrations = obj(process, "migrations");
            for (JsonElement element : arr(migrations, "threads")) {
                JsonObject row = element.getAsJsonObject();
                if (row.get("tid").getAsInt() == fTid) {
                    add("thread.migrations", "thread " + fTid, null, String.format(Locale.ROOT,
                            "Over the whole trace, TID %d (%s) moved between CPUs %d times, %.1f per second (%s; %s).", fTid,
                            threadName(fTid), num(row, "migrations", 0L), dbl(row, "per_second", 0), str(row, "level"),
                            str(migrations, "scale")), win, null, "java.thread_activity", row, "high", new JsonArray());
                }
            }
            for (JsonElement element : arr(process, "timer_lateness")) {
                JsonObject row = element.getAsJsonObject();
                if (row.get("tid").getAsInt() == fTid) {
                    add("timing.timer_lateness", "thread " + fTid, null, String.format(Locale.ROOT,
                            "Its %d timers fired a median %.3f ms after the time it asked for (p99 %.3f ms, max %.3f ms; %.0f%% at "
                                    + "least 1 ms late); its timer slack averaged %.3f ms. Level: %s.%s", num(row, "timers", 0L),
                            dbl(row, "median_late_ms", 0), dbl(row, "p99_late_ms", 0), dbl(row, "max_late_ms", 0),
                            dbl(row, "percent_late_1ms_or_more", 0), dbl(row, "mean_timer_slack_ms", 0),
                            str(row, "level"), row.has("slack_note") ? " Note: " + str(row, "slack_note") + "." : ""),
                            win, null, "java.thread_activity", row, "high", new JsonArray());
                }
            }
            JsonArray callTime = arr(obj(process, "syscall_time_by_thread"), String.valueOf(fTid));
            if (callTime.size() > 0 && whole.alive > 0) {
                JsonObject row = ProcessExplainer.callTimeRow(fTid, threadName(fTid), callTime, whole.alive);
                add("syscalls.time_by_kind", "thread " + fTid, null, "Over the whole trace, " + str(row, "text"), win,
                        null, "java.thread_activity", row, "high", ProcessExplainer.callTimeCaveats());
            }
            boolean periodic = false;
            for (JsonElement element : fFindings) {
                periodic |= "timing.cycle_trend".equals(str(element.getAsJsonObject(), "id"));
            }
            if (periodic && !bool(summary, "timer_start_events_recorded")) {
                JsonObject data = new JsonObject();
                data.addProperty("timer_start_events_recorded", false);
                add("timing.timer_lateness", "thread " + fTid, null, "This trace does not record when timers were asked to "
                        + "fire (timer_hrtimer_start), so how late a sleep ended against the time requested cannot be measured; "
                        + "cycle lengths can (timing.cycle_trend).", win, null, "java.thread_activity", data, "high",
                        new JsonArray());
            }
        }

        // ---------------------------------------------------------------
        // Cycles over time: trend, step change, spread (whole trace)
        // ---------------------------------------------------------------

        /** Only the cycle trend finding (for the process path). */
        JsonArray cycleTrendOnly() {
            addCycleTrend();
            return fFindings;
        }

        /** Calls that end a thread's wait for its next cycle. */
        private static final Set<String> CYCLE_CALLS = Set.of("clock_nanosleep", "nanosleep", "epoll_wait",
                "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "select", "pselect6", "futex", "read", "recvfrom",
                "recvmsg", "accept", "accept4");

        /**
         * A thread that repeatedly waits in the same call (a periodic sampler in clock_nanosleep, a
         * worker in futex): its cycles, from the end of one such call to the end of the next, and the
         * time it is awake between two calls. For each series over the whole trace: the median and
         * spread, the first and last tenths, a straight-line trend and the best single step, with one
         * label: a step change (when and from what to what), a gradual change, varying throughout,
         * steady with isolated outliers, or steady.
         */
        private void addCycleTrend() {
            int callQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "System_call");
            int threadQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid));
            if (callQuark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return;
            }
            long traceEnd = fTrace.getEndTime().toNanos();
            Map<String, Long> callTime = new HashMap<>();
            Map<String, Integer> callCount = new HashMap<>();
            for (ITmfStateInterval interval : history().intervals(callQuark)) {
                if (interval.getValue() instanceof String) {
                    String call = stripSyscall((String) interval.getValue());
                    callTime.merge(call, interval.getEndTime() - interval.getStartTime() + 1, Long::sum);
                    callCount.merge(call, 1, Integer::sum);
                }
            }
            String cycleCall = callTime.entrySet().stream()
                    .filter(entry -> CYCLE_CALLS.contains(entry.getKey()) && callCount.get(entry.getKey()) >= 30)
                    .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
            if (cycleCall == null) {
                return;
            }
            List<long[]> calls = new ArrayList<>();
            for (ITmfStateInterval interval : history().intervals(callQuark)) {
                if (interval.getValue() instanceof String && cycleCall.equals(stripSyscall((String) interval.getValue()))) {
                    calls.add(new long[] {interval.getStartTime(), interval.getEndTime() + 1});
                }
            }
            if (calls.size() < 30) {
                return;
            }
            // Running time between calls, by a sweep over the thread's states.
            List<long[]> running = new ArrayList<>();
            for (ITmfStateInterval interval : history().intervals(threadQuark)) {
                String state = controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                if (state.startsWith("RUNNING")) {
                    running.add(new long[] {interval.getStartTime(), interval.getEndTime() + 1});
                }
            }
            int n = calls.size() - 1;
            double[] times = new double[n];
            double[] cycle = new double[n];
            double[] awake = new double[n];
            double[] work = new double[n];
            int r = 0;
            for (int i = 0; i < n; i++) {
                long from = calls.get(i)[1];
                long to = calls.get(i + 1)[1];
                times[i] = (from - fTraceStart) / 1e9;
                cycle[i] = (to - from) / 1e6;
                awake[i] = Math.max(0, calls.get(i + 1)[0] - from) / 1e6;
                while (r < running.size() && running.get(r)[1] <= from) {
                    r++;
                }
                long ran = 0;
                for (int k = r; k < running.size() && running.get(k)[0] < to; k++) {
                    ran += Math.max(0, Math.min(to, running.get(k)[1]) - Math.max(from, running.get(k)[0]));
                }
                work[i] = ran / 1e6;
            }
            JsonObject cycleJson = seriesTrend(times, cycle, "cycle length");
            JsonObject workJson = seriesTrend(times, work, "CPU work per cycle");
            JsonObject awakeJson = seriesTrend(times, awake, "time awake between waits");
            if ("gradual increase".equals(str(workJson, "label")) && "step change".equals(str(cycleJson, "label"))
                    && dbl(cycleJson, "after_step_mean", 0) > dbl(cycleJson, "before_step_mean", 0)) {
                cycleJson.addProperty("label", "gradual increase");
                cycleJson.addProperty("text", String.format(Locale.ROOT, "a gradual increase, in steps of whole periods: "
                        + "from %.3f ms in the first tenth of the trace to %.3f ms in the last tenth (%.2f times), stepping up "
                        + "at about %.3f s, when its gradually growing CPU work outgrew the period",
                        dbl(cycleJson, "first_tenth_mean", 0), dbl(cycleJson, "last_tenth_mean", 0),
                        dbl(cycleJson, "last_tenth_mean", 0) / Math.max(1e-9, dbl(cycleJson, "first_tenth_mean", 0)),
                        dbl(cycleJson, "step_at_s", 0)));
            }
            JsonObject data = new JsonObject();
            data.addProperty("cycle_call", cycleCall);
            data.addProperty("cycles", n);
            data.addProperty("definition", "a cycle runs from the end of one " + cycleCall + " call to the end of the next; "
                    + "its CPU work is the thread's running time in it");
            data.add("cycle_length_ms", cycleJson);
            data.add("cpu_work_per_cycle_ms", workJson);
            data.add("awake_between_waits_ms", awakeJson);
            JsonArray caveats = new JsonArray();
            caveats.add("Labels: a step change needs the two-level fit to explain at least 60% of the variation, clearly "
                    + "better than a straight line, with levels at least 1.5 times apart; a gradual change needs a straight "
                    + "line to explain at least half of it and the last tenth to be 1.5 times the first (or less than two "
                    + "thirds); varying throughout means the 5th-95th percentile spread is at least 15% of the median (and 0.1 ms) in at "
                    + "least 7 of 10 stretches of the trace; isolated outliers are under 2% of the cycles.");
            caveats.add("The requested sleep length is not in the trace, so lateness against a requested period is not "
                    + "measured; cycle lengths and their changes are.");
            caveats.add("A periodic thread whose work outgrows its period skips to the next tick, so its cycle length rises "
                    + "in steps (2 ms, then 4 ms) even when the slowdown is gradual: a gradual increase in CPU work per "
                    + "cycle is a program getting steadily slower, whatever the steps of the cycle length.");
            add("timing.cycle_trend", "thread " + fTid, null, String.format(Locale.ROOT,
                    "Over the whole trace (%d cycles of %s, ending in %s): cycle length %s; CPU work per cycle %s.", n,
                    threadName(fTid), cycleCall, str(cycleJson, "text"), str(workJson, "text")),
                    window("whole_trace", fTraceStart, traceEnd), null, "tracecompass.state_system", data, "high", caveats);
        }

        private static String stripSyscall(String value) {
            return value.startsWith("syscall_entry_") ? value.substring("syscall_entry_".length()) : value;
        }

        private static double percentile(double[] sorted, double q) {
            if (sorted.length == 0) {
                return 0;
            }
            int index = (int) Math.min(sorted.length - 1, Math.max(0, Math.round(q * (sorted.length - 1))));
            return sorted[index];
        }

        private static double meanOf(double[] values, int from, int to) {
            double sum = 0;
            for (int i = from; i < to; i++) {
                sum += values[i];
            }
            return to > from ? sum / (to - from) : 0;
        }

        /** Trend, step and spread of one series over time, with a label (see addCycleTrend). */
        static JsonObject seriesTrend(double[] times, double[] values, String what) {
            int n = values.length;
            double[] sorted = values.clone();
            java.util.Arrays.sort(sorted);
            double median = percentile(sorted, 0.5);
            double p5 = percentile(sorted, 0.05);
            double p95 = percentile(sorted, 0.95);
            double p99 = percentile(sorted, 0.99);
            double max = sorted[n - 1];
            int tenth = Math.max(1, n / 10);
            double first = meanOf(values, 0, tenth);
            double lastTenth = meanOf(values, n - tenth, n);
            double mean = meanOf(values, 0, n);
            double sst = 0;
            for (double value : values) {
                sst += (value - mean) * (value - mean);
            }
            // Straight line.
            double tMean = meanOf(times, 0, n);
            double sxy = 0;
            double sxx = 0;
            for (int i = 0; i < n; i++) {
                sxy += (times[i] - tMean) * (values[i] - mean);
                sxx += (times[i] - tMean) * (times[i] - tMean);
            }
            double slope = sxx == 0 ? 0 : sxy / sxx;
            double rLine = sst == 0 || sxx == 0 ? 0 : (sxy * sxy) / (sxx * sst);
            // Best single step (two levels), by prefix sums.
            double[] prefix = new double[n + 1];
            double[] prefix2 = new double[n + 1];
            for (int i = 0; i < n; i++) {
                prefix[i + 1] = prefix[i] + values[i];
                prefix2[i + 1] = prefix2[i] + values[i] * values[i];
            }
            int bestK = -1;
            double bestSse = Double.MAX_VALUE;
            for (int k = Math.max(1, n / 20); k <= n - Math.max(1, n / 20); k++) {
                double left = prefix[k];
                double right = prefix[n] - prefix[k];
                double sse = prefix2[k] - left * left / k + (prefix2[n] - prefix2[k]) - right * right / (n - k);
                if (sse < bestSse) {
                    bestSse = sse;
                    bestK = k;
                }
            }
            double rStep = sst == 0 || bestK < 0 ? 0 : 1 - bestSse / sst;
            double before = bestK < 0 ? 0 : prefix[bestK] / bestK;
            double after = bestK < 0 ? 0 : (prefix[n] - prefix[bestK]) / (n - bestK);
            double stepRatio = Math.max(before, after) / Math.max(1e-9, Math.min(before, after));
            // Spread per tenth of the trace.
            int stretchesWithSpread = 0;
            double spread = median <= 0 ? 0 : (p95 - p5) / median;
            for (int b = 0; b < 10; b++) {
                int from = b * n / 10;
                int to = Math.max(from + 1, (b + 1) * n / 10);
                double[] part = java.util.Arrays.copyOfRange(values, from, Math.min(n, to));
                java.util.Arrays.sort(part);
                if (median > 0 && (percentile(part, 0.95) - percentile(part, 0.05)) / median >= 0.15) {
                    stretchesWithSpread++;
                }
            }
            int outliers = 0;
            for (double value : values) {
                if (value > 1.5 * median && value - median >= 0.1) {
                    outliers++;
                }
            }
            String label;
            String text;
            double lastRatio = Math.max(lastTenth, first) / Math.max(1e-9, Math.min(lastTenth, first));
            if (rStep >= 0.6 && stepRatio >= 1.5 && rStep >= rLine + 0.15) {
                label = "step change";
                text = String.format(Locale.ROOT, "a step change at %.3f s: from %.3f ms to %.3f ms (%.2f times) and stays there",
                        times[bestK], before, after, after / Math.max(1e-9, before));
            } else if (rLine >= 0.5 && lastRatio >= 1.5) {
                label = lastTenth > first ? "gradual increase" : "gradual decrease";
                text = String.format(Locale.ROOT, "a gradual %s: from %.3f ms on average in the first tenth of the trace to "
                        + "%.3f ms in the last tenth (%.2f times; straight-line fit explains %.0f%%)",
                        lastTenth > first ? "increase" : "decrease", first, lastTenth, lastTenth / Math.max(1e-9, first), rLine * 100);
            } else if (spread >= 0.15 && p95 - p5 >= 0.1 && stretchesWithSpread >= 7) {
                label = "varies throughout";
                text = String.format(Locale.ROOT, "varies throughout the run: median %.3f ms, 5th-95th percentile %.3f to %.3f ms "
                        + "(spread %.3f ms, %.0f%% of the median), in %d of 10 stretches of the trace", median, p5, p95, p95 - p5,
                        spread * 100, stretchesWithSpread);
            } else if (outliers > 0 && outliers * 50 < n) {
                label = "steady, isolated outliers";
                text = String.format(Locale.ROOT, "steady: median %.3f ms, 5th-95th percentile %.3f to %.3f ms; only %d of %d "
                        + "(%.2f%%) over 1.5 times the median, the largest %.3f ms", median, p5, p95, outliers, n,
                        outliers * 100.0 / n, max);
            } else {
                label = "steady";
                text = String.format(Locale.ROOT, "steady: median %.3f ms, 5th-95th percentile %.3f to %.3f ms, max %.3f ms",
                        median, p5, p95, max);
            }
            text += String.format(Locale.ROOT, " (first tenth %.3f ms, last tenth %.3f ms: %.2f times)", first, lastTenth,
                    lastTenth / Math.max(1e-9, first));
            JsonObject json = new JsonObject();
            json.addProperty("what", what);
            json.addProperty("label", label);
            json.addProperty("text", text);
            json.addProperty("median", median);
            json.addProperty("p5", p5);
            json.addProperty("p95", p95);
            json.addProperty("p99", p99);
            json.addProperty("max", max);
            json.addProperty("first_tenth_mean", first);
            json.addProperty("last_tenth_mean", lastTenth);
            json.addProperty("line_slope_per_s", slope);
            json.addProperty("line_fit_r2", rLine);
            json.addProperty("step_fit_r2", rStep);
            if (bestK >= 0) {
                json.addProperty("step_at_s", times[bestK]);
                json.addProperty("before_step_mean", before);
                json.addProperty("after_step_mean", after);
            }
            json.addProperty("outliers_over_1_5x_median", outliers);
            json.addProperty("stretches_with_spread_of_10", stretchesWithSpread);
            return json;
        }

        // ---------------------------------------------------------------
        // Decomposition
        // ---------------------------------------------------------------

        private static final class Decomposition {
            final Map<String, Long> ns = new LinkedHashMap<>();
            final Map<String, List<long[]>> intervals = new HashMap<>();
            long total;
            long alive;

            long ns(String state) {
                return ns.getOrDefault(state, 0L);
            }

            long running() {
                return ns.entrySet().stream().filter(e -> e.getKey().startsWith("RUNNING"))
                        .mapToLong(Map.Entry::getValue).sum();
            }

            double share(String state) {
                return alive == 0 ? 0 : ns(state) / (double) alive;
            }

            double shareRunning() {
                return alive == 0 ? 0 : running() / (double) alive;
            }

            List<long[]> intervals(String state) {
                return intervals.getOrDefault(state, new ArrayList<>());
            }
        }

        private History fHistory;
        private boolean fCpuPeak;
        private boolean fSyscallDetail;
        private boolean fSchedLatency;

        /**
         * The thread's longest system calls in the window (from its
         * System_call history: an interval with a value is the time inside
         * one call), with when they happened, and how its calls are
         * distributed overall.
         */
        /** System calls that never return: Trace Compass ends them when the thread ends. */
        static final Set<String> NEVER_RETURNS = Set.of("exit", "exit_group");

        private void addLongestSyscalls(ExplainWindow w, JsonObject win) {
            int quark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "System_call");
            if (quark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return;
            }
            List<ITmfStateInterval> calls = new ArrayList<>();
            for (ITmfStateInterval interval : history().intervals(quark, w.start, w.end)) {
                if (interval.getValue() instanceof String) {
                    calls.add(interval);
                }
            }
            if (calls.isEmpty()) {
                return;
            }
            List<Long> lengths = new ArrayList<>();
            calls.forEach(call -> lengths.add(inclusiveDuration(call.getStartTime(), call.getEndTime())));
            List<ITmfStateInterval> longest = new ArrayList<>(calls);
            longest.sort((a, b) -> Long.compare(b.getEndTime() - b.getStartTime(), a.getEndTime() - a.getStartTime()));
            JsonArray list = new JsonArray();
            List<String> parts = new ArrayList<>();
            for (ITmfStateInterval call : longest.subList(0, Math.min(5, longest.size()))) {
                long length = inclusiveDuration(call.getStartTime(), call.getEndTime());
                JsonObject item = new JsonObject();
                item.addProperty("system_call", (String) call.getValue());
                item.addProperty("start_ns", call.getStartTime());
                item.addProperty("end_ns", call.getEndTime());
                item.addProperty("start_offset_ms", (call.getStartTime() - fTraceStart) / 1_000_000.0);
                item.addProperty("duration_ms", length / 1_000_000.0);
                list.add(item);
                parts.add(String.format(Locale.ROOT, "%s %.3f ms at %,.3f ms", call.getValue(), length / 1_000_000.0,
                        (call.getStartTime() - fTraceStart) / 1_000_000.0));
            }
            List<Long> sorted = new ArrayList<>(lengths);
            sorted.sort(Long::compare);
            JsonObject data = new JsonObject();
            data.addProperty("call_count", calls.size());
            data.addProperty("median_ms", sorted.get(sorted.size() / 2) / 1_000_000.0);
            data.addProperty("p99_ms", sorted.get(Math.min(sorted.size() - 1, (int) Math.ceil(0.99 * sorted.size()) - 1)) / 1_000_000.0);
            data.add("longest", list);
            /* exit and exit_group never return: their "duration" is the time until the thread ended. */
            ITmfStateInterval completed = null;
            for (ITmfStateInterval call : longest) {
                if (!NEVER_RETURNS.contains(String.valueOf(call.getValue()))) {
                    completed = call;
                    break;
                }
            }
            if (completed != null && completed != longest.get(0)) {
                JsonObject item = new JsonObject();
                item.addProperty("system_call", (String) completed.getValue());
                item.addProperty("start_ns", completed.getStartTime());
                item.addProperty("end_ns", completed.getEndTime());
                item.addProperty("start_offset_ms", (completed.getStartTime() - fTraceStart) / 1_000_000.0);
                item.addProperty("duration_ms", inclusiveDuration(completed.getStartTime(), completed.getEndTime()) / 1_000_000.0);
                data.add("longest_completed", item);
            }
            JsonArray caveats = new JsonArray();
            caveats.add("A call's duration includes any time the thread was blocked or waiting for a CPU inside it.");
            if (completed != longest.get(0)) {
                caveats.add("exit and exit_group never return: their duration is the time until the thread ended, not a "
                        + "slow call. longest_completed is the longest call that returned.");
            }
            add("syscalls.longest", w.about, null, String.format(Locale.ROOT,
                    "%,d system calls here (median %.3f ms, p99 %.3f ms); the longest: %s.", calls.size(),
                    sorted.get(sorted.size() / 2) / 1_000_000.0,
                    sorted.get(Math.min(sorted.size() - 1, (int) Math.ceil(0.99 * sorted.size()) - 1)) / 1_000_000.0,
                    String.join("; ", parts)),
                    win, null, "tracecompass.state_system", data, "high", caveats);
        }

        /**
         * How long the thread waits to run after being woken: each
         * ready-to-run (RUNNABLE_WAITING_FOR_CPU) stretch that directly
         * follows a blocked one, with count, median, p99 and the worst one;
         * waits after being preempted are counted separately.
         */
        private void addSchedulingLatency(ExplainWindow w, JsonObject win) {
            int quark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid));
            String previous = null;
            List<long[]> wakeups = new ArrayList<>();
            long preemptedNs = 0;
            int preempted = 0;
            /* How often a wait to run (after a wake-up or a preemption) lasted 1 ms or more, or 10 ms or more. */
            int over1ms = 0;
            int over10ms = 0;
            long longestPreemptedNs = 0;
            for (ITmfStateInterval interval : history().intervals(quark, w.start, w.end)) {
                String state = controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                if ("RUNNABLE_WAITING_FOR_CPU".equals(state)) {
                    long s0 = Math.max(interval.getStartTime(), w.start);
                    long e0 = Math.min(interval.getEndTime(), w.end);
                    long length = inclusiveDuration(s0, e0);
                    if ("BLOCKED".equals(previous)) {
                        wakeups.add(new long[] {s0, e0});
                    } else if (previous != null && previous.startsWith("RUNNING")) {
                        preempted++;
                        preemptedNs += length;
                        longestPreemptedNs = Math.max(longestPreemptedNs, length);
                    }
                    if (previous != null && ("BLOCKED".equals(previous) || previous.startsWith("RUNNING"))) {
                        over1ms += length >= 1_000_000L ? 1 : 0;
                        over10ms += length >= 10_000_000L ? 1 : 0;
                    }
                }
                previous = state;
            }
            if (wakeups.isEmpty()) {
                return;
            }
            List<Long> lengths = new ArrayList<>();
            long[] worst = wakeups.get(0);
            long total = 0;
            for (long[] wakeup : wakeups) {
                long length = inclusiveDuration(wakeup[0], wakeup[1]);
                lengths.add(length);
                total += length;
                if (length > inclusiveDuration(worst[0], worst[1])) {
                    worst = wakeup;
                }
            }
            lengths.sort(Long::compare);
            long median = lengths.get(lengths.size() / 2);
            long p99 = lengths.get(Math.min(lengths.size() - 1, (int) Math.ceil(0.99 * lengths.size()) - 1));
            JsonObject data = new JsonObject();
            data.addProperty("wakeups", wakeups.size());
            data.addProperty("mean_ms", total / (double) wakeups.size() / 1_000_000.0);
            data.addProperty("median_ms", median / 1_000_000.0);
            data.addProperty("p99_ms", p99 / 1_000_000.0);
            data.addProperty("worst_ms", inclusiveDuration(worst[0], worst[1]) / 1_000_000.0);
            data.addProperty("worst_start_ns", worst[0]);
            data.addProperty("worst_end_ns", worst[1]);
            data.addProperty("worst_start_offset_ms", (worst[0] - fTraceStart) / 1_000_000.0);
            data.addProperty("preempted_waits", preempted);
            data.addProperty("preempted_ms", preemptedNs / 1_000_000.0);
            data.addProperty("preempted_longest_ms", longestPreemptedNs / 1_000_000.0);
            data.addProperty("waits_to_run_1ms_or_more", over1ms);
            data.addProperty("waits_to_run_10ms_or_more", over10ms);
            JsonArray caveats = new JsonArray();
            caveats.add("A wake-up delay is the time from being woken (ready to run) to running; who held the CPU meanwhile "
                    + "is in waiting.cpu_occupancy.");
            caveats.add("A few waits of about a millisecond happen to most threads on a busy machine; how many there are, "
                    + "and how long, says whether the delays are a real problem.");
            add("scheduling.latency", w.about, "waiting_for_cpu", String.format(Locale.ROOT,
                    "After being woken it waited to run %,d times here: median %.3f ms, mean %.3f ms, p99 %.3f ms, worst %.3f ms "
                            + "(at %,.3f ms). It also waited %.3f ms in total after being preempted (%,d times, longest %.3f ms). "
                            + "Counting both, %,d of its waits to run lasted 1 ms or more, and %,d lasted 10 ms or more.",
                    wakeups.size(), median / 1_000_000.0, total / (double) wakeups.size() / 1_000_000.0, p99 / 1_000_000.0,
                    inclusiveDuration(worst[0], worst[1]) / 1_000_000.0, (worst[0] - fTraceStart) / 1_000_000.0,
                    preemptedNs / 1_000_000.0, preempted, longestPreemptedNs / 1_000_000.0, over1ms, over10ms),
                    win, null, "tracecompass.state_system", data, "high", caveats);
        }

        /**
         * When the thread used the CPU most: the window of a fixed length
         * (about 1/500 of the range, a 1-2-5 value, so it matches what the
         * CPU Usage chart can resolve) holding the most running time, found
         * by sliding it over the exact running intervals; with the next two
         * busiest windows that do not overlap it, and the average.
         */
        private void addCpuPeak(ExplainWindow w, JsonObject win, Decomposition d) {
            List<long[]> running = new ArrayList<>();
            d.intervals.forEach((state, list) -> {
                if (state.startsWith("RUNNING")) {
                    running.addAll(list);
                }
            });
            if (running.isEmpty()) {
                return;
            }
            running.sort((a, b) -> Long.compare(a[0], b[0]));
            int n = running.size();
            long[] prefix = new long[n + 1];
            for (int i = 0; i < n; i++) {
                prefix[i + 1] = prefix[i] + inclusiveDuration(running.get(i)[0], running.get(i)[1]);
            }
            long length = niceWindow(Math.max(1, (w.end - w.start) / 500));
            // The busiest window starts where some running interval starts.
            List<long[]> candidates = new ArrayList<>(); // {start, running ns}
            int j = 0;
            for (int i = 0; i < n; i++) {
                long start = running.get(i)[0];
                long end = start + length;
                if (j < i) {
                    j = i;
                }
                while (j + 1 < n && running.get(j + 1)[0] < end) {
                    j++;
                }
                long total = prefix[j + 1] - prefix[i];
                long overflow = running.get(j)[1] + 1 - end;
                if (overflow > 0) {
                    total -= Math.min(overflow, inclusiveDuration(running.get(j)[0], running.get(j)[1]));
                }
                candidates.add(new long[] {start, total});
            }
            candidates.sort((a, b) -> Long.compare(b[1], a[1]));
            List<long[]> peaks = new ArrayList<>();
            for (long[] candidate : candidates) {
                boolean overlaps = false;
                for (long[] peak : peaks) {
                    if (candidate[0] < peak[0] + length && peak[0] < candidate[0] + length) {
                        overlaps = true;
                        break;
                    }
                }
                if (!overlaps) {
                    peaks.add(candidate);
                }
                if (peaks.size() == 3) {
                    break;
                }
            }
            long[] top = peaks.get(0);
            double averagePercent = d.running() * 100.0 / Math.max(1, d.alive);
            JsonArray list = new JsonArray();
            List<String> others = new ArrayList<>();
            for (long[] peak : peaks) {
                JsonObject item = new JsonObject();
                item.addProperty("start_ns", peak[0]);
                item.addProperty("end_ns", peak[0] + length);
                item.addProperty("start_offset_ms", (peak[0] - fTraceStart) / 1_000_000.0);
                item.addProperty("end_offset_ms", (peak[0] + length - fTraceStart) / 1_000_000.0);
                item.addProperty("running_ms", peak[1] / 1_000_000.0);
                item.addProperty("percent", peak[1] * 100.0 / length);
                list.add(item);
                if (peak != top) {
                    others.add(String.format(Locale.ROOT, "%,.3f–%,.3f ms (%.1f%%)", (peak[0] - fTraceStart) / 1_000_000.0,
                            (peak[0] + length - fTraceStart) / 1_000_000.0, peak[1] * 100.0 / length));
                }
            }
            JsonObject data = new JsonObject();
            data.addProperty("window_ms", length / 1_000_000.0);
            data.addProperty("peak_start_ns", top[0]);
            data.addProperty("peak_end_ns", top[0] + length);
            data.addProperty("peak_start_offset_ms", (top[0] - fTraceStart) / 1_000_000.0);
            data.addProperty("peak_end_offset_ms", (top[0] + length - fTraceStart) / 1_000_000.0);
            data.addProperty("peak_running_ms", top[1] / 1_000_000.0);
            data.addProperty("peak_percent", top[1] * 100.0 / length);
            data.addProperty("average_percent", averagePercent);
            data.add("busiest_windows", list);
            JsonArray caveats = new JsonArray();
            caveats.add(String.format(Locale.ROOT, "Measured over windows of %s ms (about 1/500 of the range, what the CPU Usage chart "
                    + "can show); a shorter window gives a higher, narrower peak.", trimMs(length)));
            add("running.cpu_peak", w.about, "running", String.format(Locale.ROOT,
                    "Its CPU usage was highest at %,.3f–%,.3f ms: %.3f ms on the CPU in that %s ms window (%.1f%%), against "
                            + "%.1f%% on average here.%s",
                    (top[0] - fTraceStart) / 1_000_000.0, (top[0] + length - fTraceStart) / 1_000_000.0, top[1] / 1_000_000.0,
                    trimMs(length), top[1] * 100.0 / length, averagePercent,
                    others.isEmpty() ? "" : " Next busiest: " + String.join(", ", others) + "."),
                    win, null, "tracecompass.state_system", data, "high", caveats);
        }

        /** The 1-2-5 duration (ns) closest above {@code ns}, at least 1 microsecond. */
        private static long niceWindow(long ns) {
            long scale = 1_000;
            while (true) {
                for (long step : new long[] {1, 2, 5}) {
                    if (step * scale >= ns) {
                        return step * scale;
                    }
                }
                scale *= 10;
            }
        }

        private static String trimMs(long ns) {
            double ms = ns / 1_000_000.0;
            return ms == Math.rint(ms) ? String.format(Locale.ROOT, "%d", (long) ms) : String.format(Locale.ROOT, "%.3f", ms);
        }

        /** The thread's state, system call and run queue over the whole trace, loaded once. */
        private History history() {
            if (fHistory == null) {
                fHistory = History.load(fSs, List.of(
                        fSs.optQuarkAbsolute("Threads", String.valueOf(fTid)),
                        fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "System_call"),
                        fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "Current_cpu_rq")),
                        fTraceStart, fTrace.getEndTime().toNanos());
            }
            return fHistory;
        }

        private Decomposition decompose(long start, long end) {
            Decomposition d = new Decomposition();
            int threadQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid));
            Iterator<ITmfStateInterval> it = history().intervals(threadQuark, start, end).iterator();
            while (it.hasNext()) {
                ITmfStateInterval interval = it.next();
                long s = Math.max(interval.getStartTime(), start);
                long e = Math.min(interval.getEndTime(), end);
                if (e < s) {
                    continue;
                }
                long duration = inclusiveDuration(s, e);
                String state = controlFlowStateName(
                        ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                d.ns.merge(state, duration, Long::sum);
                d.intervals.computeIfAbsent(state, k -> new ArrayList<>()).add(new long[] {s, e});
                d.total += duration;
                if (!Set.of("NOT_ALIVE", "EXITED", "ZOMBIE", "UNKNOWN").contains(state)) {
                    d.alive += duration;
                }
            }
            return d;
        }

        private void addDecomposition(ExplainWindow w, JsonObject win, Decomposition d) {
            JsonObject states = new JsonObject();
            List<Map.Entry<String, Long>> sorted = new ArrayList<>(d.ns.entrySet());
            sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, Long> entry : sorted) {
                double percent = d.total == 0 ? 0 : entry.getValue() * 100.0 / d.total;
                JsonObject state = new JsonObject();
                state.addProperty("duration_ms", entry.getValue() / 1_000_000.0);
                state.addProperty("percent", percent);
                states.add(entry.getKey(), state);
                if (percent >= 0.05) {
                    parts.add(String.format(Locale.ROOT, "%.1f%% %s (%.3f ms)", percent, entry.getKey(),
                            entry.getValue() / 1_000_000.0));
                }
            }
            JsonObject data = new JsonObject();
            data.add("states", states);
            data.addProperty("alive_ms", d.alive / 1_000_000.0);
            data.addProperty("running_ms", d.running() / 1_000_000.0);
            String lead = "whole_trace".equals(w.source) ? "Over the whole trace" : "In this window";
            add("decomposition", w.about, null, lead + ", the thread's time was: " + String.join(", ", parts) + ".",
                    win, 1.0, "tracecompass.state_system", data, "high", new JsonArray());
        }

        private void addLateCycle(ExplainWindow w, JsonObject win) {
            JsonObject data = w.details.deepCopy();
            String local = data.has("local_size") ? String.format(Locale.ROOT,
                    " Against the cycles around it (about %.3f ms): %.2fx, %.3f ms late; size %s.",
                    dbl(data, "local_period_ms", 0), dbl(data, "local_delay_factor", 0), dbl(data, "local_delay_ms", 0),
                    str(data, "local_size")) : "";
            add("window.late_cycle", w.about, str(data, "gap_kind"),
                    String.format(Locale.ROOT,
                            "A cycle came %.3f ms after the previous one instead of about %.3f ms (%.1fx).%s",
                            dbl(data, "period_ms", 0), dbl(data, "expected_period_ms", 0),
                            dbl(data, "delay_factor", 0), local),
                    win, null, "tmll.periodic_jitter", data, "high", new JsonArray());
        }

        // ---------------------------------------------------------------
        // Where the running time happened: CPU time per CPU, migrations
        // ---------------------------------------------------------------

        /**
         * Which CPUs the thread ran on. sched_switch sets the incoming
         * thread's Current_cpu_rq to the CPU it was switched onto, so during
         * every running interval that attribute is the CPU it ran on.
         */
        private void addCpuPlacement(ExplainWindow w, JsonObject win, Decomposition d) {
            int quark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "Current_cpu_rq");
            List<long[]> running = new ArrayList<>();
            d.intervals.forEach((state, list) -> {
                if (state.startsWith("RUNNING")) {
                    running.addAll(list);
                }
            });
            if (quark == ITmfStateSystem.INVALID_ATTRIBUTE || running.isEmpty()) {
                return;
            }
            running.sort((a, b) -> Long.compare(a[0], b[0]));
            Map<Integer, Long> byCpu = new java.util.TreeMap<>();
            Integer previous = null;
            Integer first = null;
            int migrations = 0;
            long known = 0;
            long unknown = 0;
            {
                for (long[] interval : running) {
                    long length = inclusiveDuration(interval[0], interval[1]);
                    Object value = history().valueAt(quark, Math.max(interval[0], fSs.getStartTime()));
                    if (!(value instanceof Integer)) {
                        unknown += length;
                        continue;
                    }
                    int cpu = (Integer) value;
                    byCpu.merge(cpu, length, Long::sum);
                    known += length;
                    if (first == null) {
                        first = cpu;
                    }
                    if (previous != null && previous != cpu) {
                        migrations++;
                    }
                    previous = cpu;
                }
            }
            if (byCpu.isEmpty()) {
                return;
            }
            long total = known;
            JsonArray cpus = new JsonArray();
            List<String> parts = new ArrayList<>();
            byCpu.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .forEach(entry -> {
                        JsonObject item = new JsonObject();
                        item.addProperty("cpu", entry.getKey());
                        item.addProperty("running_ms", entry.getValue() / 1_000_000.0);
                        item.addProperty("percent_of_running", entry.getValue() * 100.0 / total);
                        cpus.add(item);
                        parts.add(String.format(Locale.ROOT, "CPU %d %.3f ms (%.1f%%)", entry.getKey(),
                                entry.getValue() / 1_000_000.0, entry.getValue() * 100.0 / total));
                    });
            JsonObject data = new JsonObject();
            data.add("cpus", cpus);
            data.addProperty("cpu_count_used", byCpu.size());
            data.addProperty("migrations", migrations);
            data.addProperty("first_cpu", first);
            data.addProperty("last_cpu", previous);
            data.addProperty("running_ms", total / 1_000_000.0);
            data.addProperty("unattributed_ms", unknown / 1_000_000.0);
            JsonArray caveats = new JsonArray();
            caveats.add("This is where the thread actually ran, not the CPUs it was allowed to run on (its affinity mask is not recorded).");
            String claim = byCpu.size() == 1
                    ? String.format(Locale.ROOT, "It ran only on CPU %d here (%.3f ms on the CPU).",
                            first, total / 1_000_000.0)
                    : String.format(Locale.ROOT,
                            "It ran on %d CPUs here: %s; it moved between CPUs %d times.",
                            byCpu.size(), String.join(", ", parts), migrations);
            add("running.cpu_placement", w.about, "running", claim, win, d.shareRunning(),
                    "tracecompass.state_system", data, "high", caveats);
        }

        // ---------------------------------------------------------------
        // Blocked: blocking system call + critical path of the longest wait
        // ---------------------------------------------------------------

        private void explainBlocked(ExplainWindow w, JsonObject win, Decomposition d) {
            List<long[]> blocked = new ArrayList<>(d.intervals("BLOCKED"));
            blocked.sort((a, b) -> Long.compare(b[1] - b[0], a[1] - a[0]));

            JsonArray intervals = new JsonArray();
            Map<String, Integer> bySyscall = new LinkedHashMap<>();
            for (long[] interval : blocked.subList(0, Math.min(SYSCALL_INTERVALS, blocked.size()))) {
                String syscall = syscallAt(interval[0]);
                JsonObject item = new JsonObject();
                item.addProperty("start_ns", interval[0]);
                item.addProperty("end_ns", interval[1]);
                item.addProperty("start_offset_ms", (interval[0] - fTraceStart) / 1_000_000.0);
                item.addProperty("duration_ms", inclusiveDuration(interval[0], interval[1]) / 1_000_000.0);
                item.addProperty("syscall", syscall);
                intervals.add(item);
                bySyscall.merge(syscall == null ? "no system call" : syscall, 1, Integer::sum);
            }
            if (intervals.size() == 0) {
                return;
            }

            // Every wait, grouped by what ended it; a typical wait of the main group is the example.
            long[] example = addWakers(w, win, d);
            JsonArray outlierCaveats = new JsonArray();
            /* A wait still going on when the trace ends was never woken: not a one-off startup wait. */
            boolean unfinished = StuckWaits.reachesEnd(fSs, blocked.get(0)[1]);
            if (unfinished) {
                intervals.get(0).getAsJsonObject().addProperty("unfinished", true);
                outlierCaveats.add("The longest wait had not ended when the trace ended: the thread was never woken from "
                        + "it, so no wake-up or wait chain exists for it, and blocked.wakers (waits that ended) does not "
                        + "include it. It is not a one-off startup wait.");
            } else if (fTypicalWaitNs > 0 && blocked.get(0)[1] - blocked.get(0)[0] > 3 * fTypicalWaitNs) {
                outlierCaveats.add(String.format(Locale.ROOT,
                        "The longest waits are far longer than this thread's typical wait (median %.3f ms) and are "
                                + "likely one-off (e.g. program startup); blocked.wakers gives the recurring pattern.",
                        fTypicalWaitNs / 1_000_000.0));
            }

            JsonObject longest = intervals.get(0).getAsJsonObject();
            List<String> parts = new ArrayList<>();
            bySyscall.forEach((name, count) -> parts.add(name + " (" + count + " of " + intervals.size() + ")"));
            JsonObject data = new JsonObject();
            data.add("intervals", intervals);
            data.add("longest_syscall", longest.get("syscall"));
            add("blocked.syscalls", w.about, "blocked",
                    String.format(Locale.ROOT,
                            "Blocked for %.3f ms (%.1f%% of its alive time here); the %d longest waits (longest %.3f ms) were inside: %s.",
                            d.ns("BLOCKED") / 1_000_000.0, d.share("BLOCKED") * 100, intervals.size(),
                            dbl(longest, "duration_ms", 0), String.join(", ", parts)),
                    win, d.share("BLOCKED"), "tracecompass.state_system", data, "high", outlierCaveats);

            long[] top = example != null ? example : blocked.get(0);
            // +2: the window end is exclusive and the wake-up vertex sits just past the
            // interval's inclusive end (see extractLongestBlockedIntervalEndNs).
            JsonObject criticalPath = collectCriticalPath(fTrace, fTid, top[0], top[1] + 2);
            JsonObject wakeCause = correlateBlockedIntervalCause(criticalPath);
            JsonObject chain = obj(criticalPath, "chain");
            JsonObject chainData = new JsonObject();
            chainData.addProperty("available", bool(criticalPath, "available"));
            chainData.addProperty("interval_start_ns", top[0]);
            chainData.addProperty("interval_end_ns", top[1]);
            chainData.addProperty("interval_ms", inclusiveDuration(top[0], top[1]) / 1_000_000.0);
            chainData.addProperty("interval_start_offset_ms", (top[0] - fTraceStart) / 1_000_000.0);
            chainData.addProperty("which_wait", example != null
                    ? "a typical wait of the group in blocked.wakers that is not waiting for new work"
                    : "the longest wait");
            chainData.add("verdict", wakeCause.get("verdict"));
            chainData.add("likely_cause_tid", wakeCause.get("likely_cause_tid"));
            chainData.add("likely_cause_name", wakeCause.get("likely_cause_name"));
            JsonArray caveats = new JsonArray();
            if (chain != null) {
                chainData.add("root_activity", chain.get("root_activity"));
                chainData.add("idle_task_percent_of_path", chain.get("idle_task_percent_of_path"));
                chainData.add("segments", chain.get("segments"));
                if (chain.has("warning")) {
                    caveats.add(chain.get("warning"));
                }
            }
            if (!bool(criticalPath, "available")) {
                chainData.add("reason", criticalPath.get("reason"));
            }
            add("blocked.wake_chain", w.about, "blocked",
                    bool(criticalPath, "available")
                            ? summarizeBlockedGap(fTid, criticalPath) + " " + str(wakeCause, "basis")
                            : "Critical path not available for the longest wait: " + str(criticalPath, "reason"),
                    win, inclusiveDuration(top[0], top[1]) / (double) Math.max(1, d.alive),
                    "tracecompass.critical_path", chainData, str(wakeCause, "confidence"), caveats);
        }

        /** Median length of this thread's waits in the last addWakers call (0 if none). */
        private long fTypicalWaitNs;

        /**
         * All of the thread's waits in the window, grouped by what ended them
         * (which thread, or a timer, disk, network): count, total, median,
         * and the system call they were in. Waits ended by the process's main
         * thread are marked: for a worker, they are usually waits for new
         * work (idle time), not delay. Returns a typical wait (closest to the
         * median) of the largest group that is not that, as the example for
         * the critical path; null if the graph is unavailable.
         */
        private long[] addWakers(ExplainWindow w, JsonObject win, Decomposition d) {
            fTypicalWaitNs = 0;
            ITmfGraph graph = ProcessExplainer.executionGraph(fTrace);
            if (graph == null) {
                return null;
            }
            List<ProcessExplainer.WaitInterval> waits = ProcessExplainer.waitsOf(graph, fTid, w.start, w.end);
            if (waits.isEmpty()) {
                return null;
            }
            Integer pid = ProcessExplainer.pidOfThread(fKernel, fTid, w.start, w.end);
            String mainCause = pid != null && pid != fTid ? "tid:" + pid : null;

            Map<String, List<ProcessExplainer.WaitInterval>> groups = new LinkedHashMap<>();
            List<Long> all = new ArrayList<>();
            for (ProcessExplainer.WaitInterval wait : waits) {
                groups.computeIfAbsent(wait.cause, k -> new ArrayList<>()).add(wait);
                all.add(wait.end - wait.start);
            }
            fTypicalWaitNs = median(all);
            List<Map.Entry<String, List<ProcessExplainer.WaitInterval>>> ordered = new ArrayList<>(groups.entrySet());
            ordered.sort((a, b) -> Long.compare(total(b.getValue()), total(a.getValue())));

            JsonArray rows = new JsonArray();
            List<String> parts = new ArrayList<>();
            String focus = null;
            for (Map.Entry<String, List<ProcessExplainer.WaitInterval>> entry : ordered) {
                String cause = entry.getKey();
                List<ProcessExplainer.WaitInterval> group = entry.getValue();
                List<Long> lengths = new ArrayList<>();
                Map<String, Integer> calls = new HashMap<>();
                for (ProcessExplainer.WaitInterval wait : group) {
                    lengths.add(wait.end - wait.start);
                    String call = syscallAt(wait.start);
                    calls.merge(call == null ? "no system call" : call, 1, Integer::sum);
                }
                String call = calls.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
                boolean byMain = cause.equals(mainCause);
                if (focus == null && !byMain) {
                    focus = cause;
                }
                if (rows.size() < 8) {
                    JsonObject row = new JsonObject();
                    row.addProperty("woken_by", describeWaker(cause));
                    row.addProperty("cause", cause);
                    if (cause.startsWith("tid:")) {
                        row.addProperty("woken_by_tid", Integer.parseInt(cause.substring(4)));
                    }
                    row.addProperty("woken_by_process_main_thread", byMain);
                    row.addProperty("waits", group.size());
                    row.addProperty("total_ms", total(group) / 1_000_000.0);
                    row.addProperty("median_ms", median(lengths) / 1_000_000.0);
                    row.addProperty("system_call", call);
                    rows.add(row);
                    parts.add(String.format(Locale.ROOT, "%s: %,d waits, %.3f ms in total, typically %.3f ms, in %s%s",
                            describeWaker(cause), group.size(), total(group) / 1_000_000.0, median(lengths) / 1_000_000.0,
                            call, byMain ? " (its process's main thread; for a worker usually waiting for new work)" : ""));
                }
            }
            JsonObject data = new JsonObject();
            data.addProperty("waits", waits.size());
            data.addProperty("median_wait_ms", fTypicalWaitNs / 1_000_000.0);
            data.add("by_waker", rows);
            if (focus != null) {
                data.addProperty("main_cause_excluding_new_work", describeWaker(focus));
            }
            JsonArray caveats = new JsonArray();
            caveats.add("The waker is the thread that ended the wait (released the lock, posted the data); "
                    + "what that thread was itself waiting on is in thread.process_role or the critical path.");
            add("blocked.wakers", w.about, "blocked", String.format(Locale.ROOT,
                    "Across its %,d waits here, what ended them: %s.", waits.size(), String.join("; ", parts)),
                    win, d.share("BLOCKED"), "tracecompass.execution_graph+state_system", data, "high", caveats);

            if (focus == null) {
                return null;
            }
            List<ProcessExplainer.WaitInterval> group = groups.get(focus);
            List<Long> lengths = new ArrayList<>();
            group.forEach(wait -> lengths.add(wait.end - wait.start));
            long typical = median(lengths);
            ProcessExplainer.WaitInterval best = group.get(0);
            for (ProcessExplainer.WaitInterval wait : group) {
                if (Math.abs((wait.end - wait.start) - typical) < Math.abs((best.end - best.start) - typical)) {
                    best = wait;
                }
            }
            return new long[] {best.start, best.end};
        }

        private String describeWaker(String cause) {
            if (cause.startsWith("tid:")) {
                int tid = Integer.parseInt(cause.substring(4));
                return "TID " + tid + " (" + threadName(tid) + ")";
            }
            switch (cause) {
            case "TIMER":
                return "a timer (sleep or timeout)";
            case "NETWORK":
                return "the network";
            case "BLOCK_DEVICE":
                return "disk I/O";
            case "IDLE_TASK":
                return "a wake-up attributed to the idle task";
            default:
                return "an interrupt or unattributed wake-up";
            }
        }

        private static long total(List<ProcessExplainer.WaitInterval> waits) {
            long sum = 0;
            for (ProcessExplainer.WaitInterval wait : waits) {
                sum += wait.end - wait.start;
            }
            return sum;
        }

        private static long median(List<Long> values) {
            if (values.isEmpty()) {
                return 0;
            }
            List<Long> sorted = new ArrayList<>(values);
            sorted.sort(Long::compare);
            return sorted.get(sorted.size() / 2);
        }

        private String syscallAt(long ts) {
            int quark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "System_call");
            if (quark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return null;
            }
            Object value = history().valueAt(quark, Math.max(ts, fSs.getStartTime()));
            return value instanceof String ? (String) value : null;
        }

        // ---------------------------------------------------------------
        // Waiting for a CPU: who held the CPU the thread was queued on
        // ---------------------------------------------------------------

        private void explainWaiting(ExplainWindow w, JsonObject win, Decomposition d) {
            int rqQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid), "Current_cpu_rq");
            if (rqQuark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return;
            }
            Map<Integer, Long> occupancy = new HashMap<>();
            Map<Integer, Long> waitingByCpu = new LinkedHashMap<>();
            Map<Integer, History> cpuHistories = new HashMap<>();
            long waiting = 0;
            long unknown = 0;
            {
                for (long[] interval : d.intervals("RUNNABLE_WAITING_FOR_CPU")) {
                    Object rq = history().valueAt(rqQuark, interval[0]);
                    if (!(rq instanceof Integer)) {
                        continue;
                    }
                    int cpu = (Integer) rq;
                    long length = inclusiveDuration(interval[0], interval[1]);
                    waiting += length;
                    waitingByCpu.merge(cpu, length, Long::sum);
                    int cpuQuark = fSs.optQuarkAbsolute("CPUs", String.valueOf(cpu), "Current_thread");
                    if (cpuQuark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                        unknown += length;
                        continue;
                    }
                    History holders = cpuHistories.computeIfAbsent(cpu,
                            key -> History.load(fSs, List.of(cpuQuark), w.start, w.end));
                    for (ITmfStateInterval held : holders.intervals(cpuQuark, interval[0], interval[1])) {
                        long t = Math.max(held.getStartTime(), interval[0]);
                        long e = Math.min(held.getEndTime(), interval[1]);
                        if (e < t) {
                            continue;
                        }
                        Object tid = held.getValue();
                        if (tid instanceof Integer) {
                            occupancy.merge((Integer) tid, inclusiveDuration(t, e), Long::sum);
                        } else {
                            unknown += inclusiveDuration(t, e);
                        }
                    }
                }
            }
            if (waiting == 0) {
                return;
            }
            occupancy.remove(fTid);
            List<Map.Entry<Integer, Long>> holders = new ArrayList<>(occupancy.entrySet());
            holders.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
            Map<Integer, Integer> pids = ProcessExplainer.pidMap(fKernel, w.start, w.end);
            Integer ownPid = pids.get(fTid);
            long middle = w.start + (w.end - w.start) / 2;
            JsonArray occupants = new JsonArray();
            List<String> holderText = new ArrayList<>();
            for (Map.Entry<Integer, Long> holder : holders.subList(0, Math.min(5, holders.size()))) {
                int tid = holder.getKey();
                Integer pid = pids.get(tid);
                String priority = tid == 0 ? "idle" : ProcessExplainer.priorityText(priorityOf(tid, middle));
                JsonObject item = new JsonObject();
                item.addProperty("tid", tid);
                item.addProperty("name", threadName(tid));
                if (pid != null) {
                    item.addProperty("pid", pid);
                    item.addProperty("process", threadName(pid));
                }
                item.addProperty("same_process", pid != null && pid.equals(ownPid));
                item.addProperty("priority", priority);
                item.addProperty("held_ms", holder.getValue() / 1_000_000.0);
                item.addProperty("percent_of_waiting", holder.getValue() * 100.0 / waiting);
                occupants.add(item);
                if (holderText.size() < 3 && tid != 0) {
                    holderText.add(String.format(Locale.ROOT, "TID %d (%s, %s, %s) %.1f%%", tid, threadName(tid),
                            pid != null && pid.equals(ownPid) ? "same process" : "process " + pid + " " + threadName(pid == null ? tid : pid),
                            priority, holder.getValue() * 100.0 / waiting));
                }
            }
            JsonArray cpus = new JsonArray();
            waitingByCpu.keySet().forEach(cpus::add);
            // Preempted while running, or queued after a wake-up.
            int preemptions = 0;
            int queued = 0;
            long longest = 0;
            String previous = null;
            int threadQuark = fSs.optQuarkAbsolute("Threads", String.valueOf(fTid));
            for (ITmfStateInterval interval : history().intervals(threadQuark, w.start, w.end)) {
                String state = controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                if ("RUNNABLE_WAITING_FOR_CPU".equals(state)) {
                    longest = Math.max(longest, interval.getEndTime() - interval.getStartTime() + 1);
                    if (previous != null && previous.startsWith("RUNNING")) {
                        preemptions++;
                    } else {
                        queued++;
                    }
                }
                previous = state;
            }

            JsonObject data = new JsonObject();
            data.addProperty("waiting_ms", waiting / 1_000_000.0);
            data.add("cpus", cpus);
            data.addProperty("own_priority", ProcessExplainer.priorityText(priorityOf(fTid, middle)));
            data.add("occupants", occupants);
            data.addProperty("preemptions", preemptions);
            data.addProperty("queued_after_wake_up", queued);
            data.addProperty("longest_wait_ms", longest / 1_000_000.0);
            data.addProperty("unattributed_percent", unknown * 100.0 / waiting);
            data.addProperty("holders_text", String.format(Locale.ROOT, "It (%s) was preempted while running %d times and "
                    + "queued after a wake-up %d times; its longest wait for a CPU was %.3f ms. The CPU was held by %s.",
                    ProcessExplainer.priorityText(priorityOf(fTid, middle)), preemptions, queued, longest / 1_000_000.0,
                    holderText.isEmpty() ? "no other thread" : String.join(", ", holderText)));
            String claim;
            String confidence;
            if (holders.isEmpty() || holders.get(0).getKey() == 0) {
                data.addProperty("verdict", "cpu_idle_or_interrupt");
                claim = String.format(Locale.ROOT,
                        "Ready to run for %.3f ms, but no other thread held the CPU for most of it (idle or interrupt handling).",
                        waiting / 1_000_000.0);
                confidence = "low";
            } else {
                Map.Entry<Integer, Long> top = holders.get(0);
                double percent = top.getValue() * 100.0 / waiting;
                data.addProperty("holder_tid", top.getKey());
                data.addProperty("holder_name", threadName(top.getKey()));
                data.addProperty("holder_percent", percent);
                data.addProperty("verdict", percent >= 50 ? "single_dominant_occupant" : "multiple_contending_occupants");
                claim = String.format(Locale.ROOT,
                        "Ready to run for %.3f ms (%.1f%% of its alive time here) while queued on CPU %s; TID %d (%s) held that CPU for %.1f%% of the waiting time.",
                        waiting / 1_000_000.0, d.share("RUNNABLE_WAITING_FOR_CPU") * 100,
                        waitingByCpu.keySet().stream().map(String::valueOf).collect(Collectors.joining(", ")),
                        top.getKey(), threadName(top.getKey()), percent);
                confidence = percent >= 50 ? "high" : "medium";
            }
            claim += " " + str(data, "holders_text");
            add("waiting.cpu_occupancy", w.about, "waiting_for_cpu", claim, win,
                    d.share("RUNNABLE_WAITING_FOR_CPU"), "tracecompass.state_system", data, confidence,
                    new JsonArray());
        }

        private int priorityOf(int tid, long time) {
            try {
                return KernelThreadInformationProvider.getThreadPriority(fKernel, tid, time);
            } catch (RuntimeException exception) {
                return Integer.MIN_VALUE;
            }
        }

        private String threadName(int tid) {
            if (tid == 0) {
                return "idle (swapper)";
            }
            String name = KernelThreadInformationProvider.getExecutableName(fKernel, tid);
            return name == null ? "unknown" : name;
        }

        // ---------------------------------------------------------------
        // Running: exact CPU time + decoded activity (+ normal-cycle baseline)
        // ---------------------------------------------------------------

        private void explainRunning(ExplainWindow w, JsonObject win, Decomposition d) {
            boolean whole = "whole_trace".equals(w.source);
            JsonObject activity = whole
                    ? wholeActivity()
                    : ThreadActivitySummarizer.summarize(fTrace, fTid, w.start, w.end);

            JsonObject counts = obj(activity, "syscall_counts");
            JsonObject data = new JsonObject();
            data.addProperty("on_cpu_ms", d.running() / 1_000_000.0);
            data.addProperty("user_mode_ms", d.ns("RUNNING_USER_MODE") / 1_000_000.0);
            data.addProperty("system_call_ms", d.ns("RUNNING_SYSTEM_CALL") / 1_000_000.0);
            data.add("syscall_count", activity.get("syscall_count"));
            data.add("syscall_counts", counts);

            List<String> calls = new ArrayList<>();
            JsonObject baseline = lateCycleBaseline(w, d, counts);
            if (baseline != null) {
                data.add("normal_cycle", baseline);
            }
            JsonArray top = arr(activity, "top_syscalls");
            for (JsonElement element : top) {
                JsonObject call = element.getAsJsonObject();
                String name = str(call, "syscall");
                String normal = "";
                if (baseline != null) {
                    JsonObject perCycle = obj(baseline, "syscalls_per_cycle");
                    normal = String.format(Locale.ROOT, ", normally %.1f per cycle", dbl(perCycle, name, 0));
                }
                calls.add(String.format(Locale.ROOT, "%s x%d (%.3f ms%s)", name, num(call, "calls", 0L),
                        dbl(call, "total_ms", 0), normal));
                if (calls.size() == 5) {
                    break;
                }
            }
            String claim = String.format(Locale.ROOT,
                    "On the CPU for %.3f ms here (%.3f ms in its own code, %.3f ms in system calls)%s; it made %s system calls%s.",
                    d.running() / 1_000_000.0, d.ns("RUNNING_USER_MODE") / 1_000_000.0,
                    d.ns("RUNNING_SYSTEM_CALL") / 1_000_000.0,
                    baseline != null ? String.format(Locale.ROOT, ", against about %.3f ms in a normal cycle",
                            dbl(baseline, "on_cpu_ms", 0)) : "",
                    str(activity, "syscall_count"),
                    calls.isEmpty() ? "" : ": " + String.join(", ", calls));
            if (!fDescribe && "late_cycle".equals(w.source)) {
                // Which files and other targets those calls used (fd -> name), so a burst of reads is not anonymous.
                JsonArray targets = new JsonArray();
                List<String> described = new ArrayList<>();
                for (String group : new String[] {"files", "sockets_pipes_devices_other"}) {
                    for (JsonElement element : arr(activity, group)) {
                        targets.add(element);
                        described.add(describeTarget(element.getAsJsonObject()));
                    }
                }
                if (targets.size() > 0) {
                    data.add("targets", targets);
                    claim += " Used here: " + String.join(" ", described);
                }
            }
            add("running.work", w.about, "running", claim, win, d.shareRunning(),
                    "tracecompass.state_system+java.thread_activity", data, "high", new JsonArray());

            if (fDescribe || !"late_cycle".equals(w.source)) {
                addActivity(w, win, activity);
            }
        }

        /** Average normal cycle, for comparing a late cycle's work against it. */
        private JsonObject lateCycleBaseline(ExplainWindow w, Decomposition d, JsonObject counts) {
            if (!"late_cycle".equals(w.source) || w.details == null || fWholeDecomposition == null) {
                return null;
            }
            long cycles = num(w.details, "activation_count", 0L) - 1 - num(w.details, "late_cycle_count", 1L);
            if (cycles <= 0) {
                return null;
            }
            JsonObject whole = obj(wholeActivity(), "syscall_counts");
            JsonObject perCycle = new JsonObject();
            if (whole != null) {
                for (Map.Entry<String, JsonElement> entry : whole.entrySet()) {
                    long inWindow = counts != null && counts.has(entry.getKey()) ? counts.get(entry.getKey()).getAsLong() : 0;
                    perCycle.addProperty(entry.getKey(), (entry.getValue().getAsLong() - inWindow) / (double) cycles);
                }
            }
            JsonObject baseline = new JsonObject();
            baseline.addProperty("cycles", cycles);
            baseline.addProperty("on_cpu_ms", (fWholeDecomposition.running() - d.running()) / 1_000_000.0 / cycles);
            baseline.add("syscalls_per_cycle", perCycle);
            return baseline;
        }

        private JsonObject wholeActivity() {
            if (fWholeActivity == null) {
                fWholeActivity = ThreadActivitySummarizer.summarize(fTrace, fTid, null, null);
            }
            return fWholeActivity;
        }

        private void addActivity(ExplainWindow w, JsonObject win, JsonObject activity) {
            if (!bool(activity, "available")) {
                return;
            }
            JsonObject summary = new JsonObject();
            for (String key : new String[] {"syscall_count", "program_executed", "syscalls_by_category",
                    "top_syscalls", "rates", "syscall_latency", "file_relations", "created_threads_or_processes",
                    "executable", "pid"}) {
                if (activity.has(key)) {
                    summary.add(key, activity.get(key));
                }
            }
            add("running.activity", w.about, "running", str(activity, "summary")
                    + ProcessExplainer.activitySizes(activity), win,
                    null, "java.thread_activity", summary, "high", ProcessExplainer.activityCaveats());

            String[][] groups = {
                    {"files", "file"},
                    {"standard_streams", "standard_stream"},
                    {"runtime_loader_files", "runtime_loader"},
                    {"sockets_pipes_devices_other", "other"},
                    {"thread_names", "thread_name"}};
            for (String[] group : groups) {
                for (JsonElement element : arr(activity, group[0])) {
                    JsonObject target = element.getAsJsonObject().deepCopy();
                    target.addProperty("group", group[1]);
                    JsonArray caveats = new JsonArray();
                    if ("socket".equals(str(target, "kind"))) {
                        caveats.add("The trace records no socket addresses, so this socket is not linked to the other end's thread or host.");
                    }
                    add("running.target", w.about, "running", describeTarget(target), win,
                            null, "java.thread_activity", target, "high", caveats);
                }
            }

            JsonArray timeline = arr(activity, "timeline");
            if (timeline.size() > 0) {
                List<String> steps = new ArrayList<>();
                for (JsonElement element : timeline) {
                    JsonObject step = element.getAsJsonObject();
                    steps.add(str(step, "operation") + (step.has("target") ? " " + str(step, "target") : ""));
                }
                JsonObject data = new JsonObject();
                data.add("steps", timeline);
                data.add("steps_omitted", activity.get("timeline_steps_omitted"));
                add("running.timeline", w.about, "running",
                        "In order: " + String.join("; ", steps.subList(0, Math.min(12, steps.size())))
                                + (steps.size() > 12 ? "; ..." : "") + ".",
                        win, null, "java.thread_activity", data, "high", new JsonArray());
            }

            if (activity.has("exit_status")) {
                JsonObject data = new JsonObject();
                data.add("exit_status", activity.get("exit_status"));
                data.add("exit_kind", activity.get("exit_kind"));
                data.add("exited_at_offset_ms", activity.get("exited_at_offset_ms"));
                JsonArray caveats = new JsonArray();
                if (!"whole_trace".equals(w.source)) {
                    caveats.add("States after the exit (e.g. WAITING_UNKNOWN, NOT_ALIVE) are the thread being torn down, not activity.");
                }
                add("lifecycle.exit", w.about, null,
                        String.format(Locale.ROOT, "At %.3f ms the thread %s, with status %s.",
                                dbl(activity, "exited_at_offset_ms", 0), str(activity, "exit_kind"),
                                str(activity, "exit_status")),
                        win, null, "java.thread_activity", data, "high", caveats);
            }
        }

        private static String describeTarget(JsonObject target) {
            if ("thread_name".equals(str(target, "group"))) {
                return "Named thread " + str(target, "named_tid") + " (wrote its /proc comm file, as pthread_setname_np does).";
            }
            List<String> parts = new ArrayList<>();
            if (num(target, "opens", 0L) > 0) {
                parts.add("opened " + (target.has("open_mode") ? str(target, "open_mode") : ""));
            }
            if (num(target, "writes", 0L) > 0) {
                parts.add(String.format(Locale.ROOT, "wrote %,d bytes in %d write(s)",
                        num(target, "bytes_written", 0L), num(target, "writes", 0L)));
            }
            if (num(target, "reads", 0L) > 0) {
                parts.add(String.format(Locale.ROOT, "read %,d bytes in %d read(s)",
                        num(target, "bytes_read", 0L), num(target, "reads", 0L)));
            }
            if (num(target, "syncs_to_disk", 0L) > 0) {
                parts.add(String.format(Locale.ROOT, "flushed to disk %d time(s) (%.3f ms)",
                        num(target, "syncs_to_disk", 0L), dbl(target, "sync_ms", 0)));
            }
            if (num(target, "closes", 0L) > 0) {
                parts.add("closed");
            }
            for (JsonElement element : arr(target, "also_used_by_threads_of_same_process")) {
                JsonObject peer = element.getAsJsonObject();
                parts.add(String.format(Locale.ROOT, "also used by TID %s%s (read %,d bytes, wrote %,d bytes)",
                        str(peer, "tid"), peer.has("name") ? " " + str(peer, "name") : "",
                        num(peer, "bytes_read", 0L), num(peer, "bytes_written", 0L)));
            }
            return str(target, "name") + " (" + str(target, "kind") + "): " + String.join("; ", parts) + ".";
        }

        // ---------------------------------------------------------------
        // Finding shape and JSON helpers
        // ---------------------------------------------------------------

        private void add(String id, String about, String state, String claim, JsonObject win, Double share,
                String analysis, JsonObject data, String confidence, JsonArray caveats) {
            JsonObject finding = new JsonObject();
            finding.addProperty("id", id);
            finding.addProperty("about", about);
            finding.addProperty("state", state);
            finding.addProperty("claim", claim);
            finding.add("window", win);
            if (share != null) {
                finding.addProperty("share", share);
            }
            JsonObject evidence = new JsonObject();
            evidence.addProperty("analysis", analysis);
            evidence.add("data", data);
            finding.add("evidence", evidence);
            finding.addProperty("confidence", confidence);
            finding.add("caveats", caveats);
            fFindings.add(finding);
        }

        private JsonObject window(String source, long startNs, long endNs) {
            JsonObject win = new JsonObject();
            win.addProperty("source", source);
            win.addProperty("start_ns", startNs);
            win.addProperty("end_ns", endNs);
            win.addProperty("start_offset_ms", (startNs - fTraceStart) / 1_000_000.0);
            win.addProperty("end_offset_ms", (endNs - fTraceStart) / 1_000_000.0);
            return win;
        }

        static JsonObject obj(JsonObject parent, String key) {
            return parent != null && parent.has(key) && parent.get(key).isJsonObject()
                    ? parent.getAsJsonObject(key) : null;
        }

        static JsonArray arr(JsonObject parent, String key) {
            return parent != null && parent.has(key) && parent.get(key).isJsonArray()
                    ? parent.getAsJsonArray(key) : new JsonArray();
        }

        static boolean bool(JsonObject parent, String key) {
            return parent != null && parent.has(key) && parent.get(key).isJsonPrimitive()
                    && parent.get(key).getAsBoolean();
        }

        static long num(JsonObject parent, String key, long fallback) {
            return parent != null && parent.has(key) && parent.get(key).isJsonPrimitive()
                    ? parent.get(key).getAsLong() : fallback;
        }

        static double dbl(JsonObject parent, String key, double fallback) {
            return parent != null && parent.has(key) && parent.get(key).isJsonPrimitive()
                    ? parent.get(key).getAsDouble() : fallback;
        }

        static String str(JsonObject parent, String key) {
            return parent != null && parent.has(key) && !parent.get(key).isJsonNull()
                    ? parent.get(key).getAsString() : null;
        }
    }

    /**
     * Explains a question about the whole trace rather than one thread ("what
     * does this trace record?"): what kinds of events it holds, which
     * processes ran and used the CPU, which of them are the workload (started
     * during the trace) rather than background or the tracer itself, and what
     * each workload process did. One pass over the events
     * ({@link ThreadActivitySummarizer#summarizeProcesses}) plus the kernel
     * state system for CPU time.
     */
    static final class TraceExplainer {

        /** Workload processes that get their own activity finding. */
        private static final int MAX_WORKLOAD = 5;
        private static final int MAX_TIMELINE = 40;
        private static final int MAX_PROCESSES = 25;

        /** Event-name prefix -> what kind of activity it records. */
        private static final String[][] EVENT_CATEGORIES = {
                {"syscall_", "system calls"},
                {"sched_", "scheduling (context switches, wake-ups, process creation and exit)"},
                {"timer_", "timers"},
                {"hrtimer_", "timers"},
                {"irq_", "interrupts"},
                {"x86_irq_vectors_", "interrupts"},
                {"lttng_statedump_", "state dump (processes and open files at trace start)"},
                {"block_", "block (disk) I/O"},
                {"net_", "network packets"},
                {"netif_", "network packets"},
                {"napi_", "network packets"},
                {"skb_", "network packets"},
                {"kmem_", "memory"},
                {"mm_", "memory"},
                {"x86_exceptions_page_fault", "memory"},
                {"page_fault", "memory"},
                {"power_", "power and CPU frequency"},
                {"workqueue_", "kernel workqueues"},
                {"rcu_", "RCU"},
                {"signal_", "signals"},
                {"writeback_", "page cache writeback"},
                {"module_", "kernel modules"}};

        /** Kinds of activity an analysis may need; reported when absent. */
        private static final String[] NOTABLE = {
                "system calls", "scheduling (context switches, wake-ups, process creation and exit)",
                "timers", "interrupts", "block (disk) I/O", "network packets", "memory",
                "user-space (UST) events"};

        private final ITmfTrace fTrace;
        private final ExplainWindow fWindow;
        private final JsonObject fWin;
        private final long fTraceStart;
        private final JsonArray fFindings = new JsonArray();
        private ITmfStateSystem fSs;
        private boolean fEventPeak;

        private TraceExplainer(ITmfTrace trace, ExplainWindow window, JsonObject win) {
            fTrace = trace;
            fWindow = window;
            fWin = win;
            fTraceStart = trace.getStartTime().toNanos();
        }

        static JsonArray explain(ITmfTrace trace, ExplainWindow window) {
            return explain(trace, window, "");
        }

        /** @param question asks when the system was busiest: add trace.event_peak */
        static JsonArray explain(ITmfTrace trace, ExplainWindow window, String question) {
            JsonObject win = new JsonObject();
            win.addProperty("source", window.source);
            win.addProperty("start_ns", window.start);
            win.addProperty("end_ns", window.end);
            long traceStart = trace.getStartTime().toNanos();
            win.addProperty("start_offset_ms", (window.start - traceStart) / 1_000_000.0);
            win.addProperty("end_offset_ms", (window.end - traceStart) / 1_000_000.0);
            if (window.details != null && window.details.has("interpreted_as")) {
                win.add("interpreted_as", window.details.get("interpreted_as"));
            }
            TraceExplainer explainer = new TraceExplainer(trace, window, win);
            explainer.fEventPeak = EVENT_PEAK_WORDS.matcher(question).find();
            explainer.run();
            return explainer.fFindings;
        }

        private void run() {
            KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                    fTrace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
            ITmfStateSystem ss = null;
            if (kernel != null) {
                kernel.schedule();
                kernel.waitForCompletion();
                ss = kernel.getStateSystem();
            }
            fSs = ss;
            boolean windowed = !"whole_trace".equals(fWindow.source);
            JsonObject summary = ThreadActivitySummarizer.summarizeProcesses(fTrace,
                    windowed ? fWindow.start : null, windowed ? fWindow.end : null);
            if (!UnifiedExplainer.bool(summary, "available")) {
                add("trace.unavailable", null, "The trace's events could not be read for this question: "
                        + UnifiedExplainer.str(summary, "reason"), "java.trace_events", summary, "n/a", new JsonArray());
                return;
            }

            int cpuCount = addRecorded(summary, ss);
            if (fEventPeak) {
                addEventPeak(summary);
            }
            Map<Integer, Long> cpuByPid = new HashMap<>();
            long busyNs = cpuUsage(ss, kernel, cpuByPid);
            addProcesses(summary, kernel, cpuByPid, busyNs, cpuCount);
        }

        // ---------------------------------------------------------------
        // What the trace recorded
        // ---------------------------------------------------------------

        private int addRecorded(JsonObject summary, ITmfStateSystem ss) {
            Map<String, long[]> categories = new LinkedHashMap<>();
            Map<String, List<String>> names = new HashMap<>();
            Set<String> syscalls = new java.util.TreeSet<>();
            for (Map.Entry<String, JsonElement> entry : UnifiedExplainer.obj(summary, "event_counts").entrySet()) {
                String name = entry.getKey();
                String category = categoryOf(name);
                categories.computeIfAbsent(category, k -> new long[1])[0] += entry.getValue().getAsLong();
                if (name.startsWith("syscall_entry_")) {
                    syscalls.add(name.substring("syscall_entry_".length()));
                } else if (!name.startsWith("syscall_exit_")) {
                    names.computeIfAbsent(category, k -> new ArrayList<>()).add(name);
                }
            }
            int cpuCount = 0;
            if (ss != null) {
                int cpus = ss.optQuarkAbsolute("CPUs");
                if (cpus != ITmfStateSystem.INVALID_ATTRIBUTE) {
                    cpuCount = ss.getSubAttributes(cpus, false).size();
                }
            }

            JsonArray recorded = new JsonArray();
            List<String> parts = new ArrayList<>();
            categories.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue()[0], a.getValue()[0]))
                    .forEach(entry -> {
                        JsonObject item = new JsonObject();
                        item.addProperty("category", entry.getKey());
                        item.addProperty("events", entry.getValue()[0]);
                        if ("system calls".equals(entry.getKey())) {
                            item.addProperty("distinct_system_calls", syscalls.size());
                        } else {
                            JsonArray eventNames = new JsonArray();
                            names.getOrDefault(entry.getKey(), List.of()).stream().sorted()
                                    .limit(15).forEach(eventNames::add);
                            item.add("event_names", eventNames);
                        }
                        recorded.add(item);
                        parts.add(String.format(Locale.ROOT, "%s (%,d events%s)", entry.getKey(),
                                entry.getValue()[0], "system calls".equals(entry.getKey())
                                        ? ", " + syscalls.size() + " different calls" : ""));
                    });
            JsonArray missing = new JsonArray();
            for (String notable : NOTABLE) {
                if (!categories.containsKey(notable)) {
                    missing.add(notable);
                }
            }

            JsonObject data = new JsonObject();
            data.addProperty("trace_name", fTrace.getName());
            data.addProperty("host", fTrace.getHostId());
            data.addProperty("cpu_count", cpuCount);
            data.addProperty("duration_ms", (fWindow.end - fWindow.start) / 1_000_000.0);
            data.addProperty("event_count", UnifiedExplainer.num(summary, "event_count", 0L));
            data.addProperty("event_type_count", UnifiedExplainer.obj(summary, "event_counts").size());
            data.add("recorded", recorded);
            data.add("not_recorded", missing);

            JsonArray caveats = new JsonArray();
            if (!categories.containsKey("timers") || !categories.containsKey("interrupts")) {
                caveats.add("No timer or interrupt events: the critical path cannot recognize timer wake-ups and attributes them to the idle task.");
            }
            if (!categories.containsKey("system calls")) {
                caveats.add("No system call events: what processes did with files, pipes and sockets cannot be decoded.");
            }
            if (!categories.containsKey("state dump (processes and open files at trace start)")) {
                caveats.add("No state dump: files opened before tracing started cannot be named.");
            }

            List<String> missingText = new ArrayList<>();
            missing.forEach(element -> missingText.add(element.getAsString()));
            add("trace.recorded", null, String.format(Locale.ROOT,
                    "%s is a Linux kernel trace of host %s%s, %.3f ms long, holding %,d events of %d types: %s.%s",
                    fTrace.getName(), fTrace.getHostId(),
                    cpuCount > 0 ? " (" + cpuCount + " CPUs)" : "",
                    (fWindow.end - fWindow.start) / 1_000_000.0,
                    UnifiedExplainer.num(summary, "event_count", 0L),
                    UnifiedExplainer.obj(summary, "event_counts").size(), String.join("; ", parts),
                    missingText.isEmpty() ? "" : " It did not record: " + String.join(", ", missingText) + "."),
                    "java.trace_events", data, "high", caveats);
            return cpuCount;
        }

        /** The busiest stretch of the trace by event rate (one of 500 equal bins), against the average. */
        private void addEventPeak(JsonObject summary) {
            JsonArray bins = UnifiedExplainer.arr(summary, "event_bins");
            long binNs = UnifiedExplainer.num(summary, "event_bin_ns", 0L);
            long binsStart = UnifiedExplainer.num(summary, "event_bins_start_ns", fWindow.start);
            if (bins.size() == 0 || binNs <= 0) {
                return;
            }
            int best = 0;
            long total = 0;
            for (int i = 0; i < bins.size(); i++) {
                total += bins.get(i).getAsLong();
                if (bins.get(i).getAsLong() > bins.get(best).getAsLong()) {
                    best = i;
                }
            }
            long peak = bins.get(best).getAsLong();
            long start = binsStart + best * binNs;
            double average = total / (double) bins.size();
            JsonObject data = new JsonObject();
            data.addProperty("bin_ms", binNs / 1_000_000.0);
            data.addProperty("peak_start_ns", start);
            data.addProperty("peak_end_ns", start + binNs);
            data.addProperty("peak_start_offset_ms", (start - fTraceStart) / 1_000_000.0);
            data.addProperty("peak_end_offset_ms", (start + binNs - fTraceStart) / 1_000_000.0);
            data.addProperty("peak_events", peak);
            data.addProperty("average_events_per_bin", average);
            data.addProperty("peak_events_per_second", peak * 1e9 / binNs);
            /*
             * The first 1% of a trace is almost always busiest: LTTng writes its
             * state dump and programs start up. Then also give, and show, the
             * busiest stretch after start-up.
             */
            int startBins = Math.max(1, bins.size() / 100);
            String afterStart = "";
            JsonArray caveats = new JsonArray();
            if (best < startBins && bins.size() > startBins) {
                int after = startBins;
                for (int i = startBins; i < bins.size(); i++) {
                    if (bins.get(i).getAsLong() > bins.get(after).getAsLong()) {
                        after = i;
                    }
                }
                long afterEvents = bins.get(after).getAsLong();
                long afterStartNs = binsStart + after * binNs;
                data.addProperty("peak_is_trace_start", true);
                data.addProperty("after_start_peak_start_ns", afterStartNs);
                data.addProperty("after_start_peak_end_ns", afterStartNs + binNs);
                data.addProperty("after_start_peak_start_offset_ms", (afterStartNs - fTraceStart) / 1_000_000.0);
                data.addProperty("after_start_peak_events", afterEvents);
                caveats.add("The busiest stretch is the start of the trace, where LTTng writes its state dump (a list of every "
                        + "process and open file) and programs start up; it says little about the workload itself.");
                afterStart = String.format(Locale.ROOT,
                        " That is the start of the trace (LTTng's state dump, programs starting up). After start-up the busiest "
                                + "stretch was %,.3f–%,.3f ms: %,d events (%.1fx the average).",
                        (afterStartNs - fTraceStart) / 1_000_000.0, (afterStartNs + binNs - fTraceStart) / 1_000_000.0,
                        afterEvents, average == 0 ? 0 : afterEvents / average);
            }
            add("trace.event_peak", null, String.format(Locale.ROOT,
                    "The trace was busiest at %,.3f–%,.3f ms: %,d events in that %.3f ms (%,.0f events/s), %.1fx the average of "
                            + "%,.0f events per %.3f ms.%s",
                    (start - fTraceStart) / 1_000_000.0, (start + binNs - fTraceStart) / 1_000_000.0, peak,
                    binNs / 1_000_000.0, peak * 1e9 / binNs, average == 0 ? 0 : peak / average, average, binNs / 1_000_000.0,
                    afterStart),
                    "java.trace_events", data, "high", caveats);
        }

        private static String categoryOf(String eventName) {
            if (eventName.contains(":")) {
                return "user-space (UST) events";
            }
            for (String[] category : EVENT_CATEGORIES) {
                if (eventName.startsWith(category[0])) {
                    return category[1];
                }
            }
            return "other kernel events";
        }

        // ---------------------------------------------------------------
        // CPU time per process
        // ---------------------------------------------------------------

        /** Fills CPU time per PID from each CPU's current-thread history; returns total busy time. */
        private long cpuUsage(ITmfStateSystem ss, KernelAnalysisModule kernel, Map<Integer, Long> byPid) {
            if (ss == null || kernel == null) {
                return 0;
            }
            int cpus = ss.optQuarkAbsolute("CPUs");
            if (cpus == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return 0;
            }
            long busy = 0;
            long start = Math.max(fWindow.start, ss.getStartTime());
            long end = Math.min(fWindow.end, ss.getCurrentEndTime());
            List<Integer> quarks = new ArrayList<>();
            for (int cpu : ss.getSubAttributes(cpus, false)) {
                int quark = ss.optQuarkRelative(cpu, "Current_thread");
                if (quark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                    quarks.add(quark);
                }
            }
            /*
             * One sweep through the history for every CPU at once (query2D),
             * not one lookup per interval: a 30-minute system-wide trace has
             * about ten million context switches, and per-interval lookups
             * took over an hour there.
             */
            Map<Integer, Long> byTid = new HashMap<>();
            try {
                for (ITmfStateInterval interval : ss.query2D(quarks, start, end)) {
                    Object value = interval.getValue();
                    if (!(value instanceof Integer) || (Integer) value <= 0) {
                        continue;
                    }
                    long s0 = Math.max(interval.getStartTime(), start);
                    long e0 = Math.min(interval.getEndTime(), end);
                    if (e0 < s0) {
                        continue;
                    }
                    long length = inclusiveDuration(s0, e0);
                    busy += length;
                    byTid.merge((Integer) value, length, Long::sum);
                }
            } catch (StateSystemDisposedException exception) {
                return 0;
            }
            for (Map.Entry<Integer, Long> entry : byTid.entrySet()) {
                Integer pid = ProcessExplainer.pidOfThread(kernel, entry.getKey(), fWindow.start, fWindow.end);
                byPid.merge(pid == null ? entry.getKey() : pid, entry.getValue(), Long::sum);
            }
            return busy;
        }

        // ---------------------------------------------------------------
        // Processes: workload, launcher, tracer, background
        // ---------------------------------------------------------------

        private void addProcesses(JsonObject summary, KernelAnalysisModule kernel,
                Map<Integer, Long> cpuByPid, long busyNs, int cpuCount) {
            JsonObject processes = UnifiedExplainer.obj(summary, "processes");
            Set<Integer> pids = new java.util.TreeSet<>(cpuByPid.keySet());
            processes.keySet().forEach(pid -> pids.add(Integer.valueOf(pid)));

            List<JsonObject> rows = new ArrayList<>();
            for (int pid : pids) {
                JsonObject activity = processes.has(String.valueOf(pid))
                        ? processes.getAsJsonObject(String.valueOf(pid)) : new JsonObject();
                long syscalls = UnifiedExplainer.num(activity, "syscall_count", 0L);
                long cpuNs = cpuByPid.getOrDefault(pid, 0L);
                boolean created = activity.has("created_at_offset_ms");
                if (syscalls == 0 && cpuNs == 0 && !created) {
                    continue;
                }
                String name = kernel == null ? null
                        : KernelThreadInformationProvider.getExecutableName(kernel, pid, fWindow.end);
                JsonObject row = new JsonObject();
                row.addProperty("pid", pid);
                row.addProperty("name", name != null ? name
                        : activity.has("executable") ? UnifiedExplainer.str(activity, "executable") : "unknown");
                row.addProperty("cpu_ms", cpuNs / 1_000_000.0);
                row.addProperty("cpu_percent_of_busy", busyNs == 0 ? 0 : cpuNs * 100.0 / busyNs);
                row.addProperty("syscall_count", syscalls);
                row.addProperty("thread_count", UnifiedExplainer.arr(activity, "threads").size());
                for (String key : new String[] {"created_at_offset_ms", "parent_pid", "program_executed",
                        "program_executed_at_offset_ms", "exit_status", "exited_at_offset_ms"}) {
                    if (activity.has(key)) {
                        row.add(key, activity.get(key));
                    }
                }
                row.add("activity", activity);
                rows.add(row);
            }

            // Roles: the tracer's own tools; processes started during the trace
            // (the workload); their parents (launchers); everything else.
            // Started during the trace is not enough on a desktop machine: status bars and
            // monitors start short helpers (nvidia-smi, sensors, awk) every few seconds.
            // A workload process also does meaningful work or lives a meaningful time.
            double windowMs = (fWindow.end - fWindow.start) / 1_000_000.0;
            Set<Integer> workloadPids = new java.util.LinkedHashSet<>();
            for (JsonObject row : rows) {
                if (isTracer(row)) {
                    row.addProperty("role", "tracer");
                } else if (row.has("created_at_offset_ms")) {
                    double created = row.get("created_at_offset_ms").getAsDouble();
                    double ended = row.has("exited_at_offset_ms") ? row.get("exited_at_offset_ms").getAsDouble()
                            : (fWindow.end - fTraceStart) / 1_000_000.0;
                    boolean busy = row.get("cpu_percent_of_busy").getAsDouble() >= 1.0;
                    boolean longLived = ended - created >= 0.10 * windowMs;
                    if (busy || longLived) {
                        row.addProperty("role", "workload");
                        workloadPids.add(row.get("pid").getAsInt());
                    } else {
                        row.addProperty("role", "background");
                        row.addProperty("short_lived", true);
                    }
                }
            }
            if (workloadPids.isEmpty()) {
                // Nothing started during the trace: the busiest non-tracer process is the workload.
                rows.stream().filter(row -> !row.has("role"))
                        .max((a, b) -> Double.compare(a.get("cpu_ms").getAsDouble(), b.get("cpu_ms").getAsDouble()))
                        .ifPresent(row -> {
                            row.addProperty("role", "workload");
                            workloadPids.add(row.get("pid").getAsInt());
                        });
            }
            for (JsonObject row : rows) {
                if (!row.has("role")) {
                    boolean launcher = rows.stream().anyMatch(other -> other.has("parent_pid")
                            && workloadPids.contains(other.get("pid").getAsInt())
                            && other.get("parent_pid").getAsInt() == row.get("pid").getAsInt());
                    row.addProperty("role", launcher ? "launcher" : "background");
                }
            }
            rows.sort((a, b) -> {
                int byRole = Integer.compare(roleRank(a), roleRank(b));
                return byRole != 0 ? byRole
                        : Double.compare(b.get("cpu_ms").getAsDouble(), a.get("cpu_ms").getAsDouble());
            });

            addCpu(rows, busyNs, cpuCount);
            addProcessList(rows);
            addWorkload(rows);
            addTimeline(rows);
            addBackground(rows, busyNs);
        }

        private static boolean isTracer(JsonObject row) {
            String name = UnifiedExplainer.str(row, "name");
            String program = UnifiedExplainer.str(row, "program_executed");
            return (name != null && (name.startsWith("lttng") || name.startsWith("babeltrace")))
                    || (program != null && (program.endsWith("/lttng") || program.contains("/lttng-")));
        }

        private static int roleRank(JsonObject row) {
            switch (UnifiedExplainer.str(row, "role")) {
            case "workload":
                return 0;
            case "launcher":
                return 1;
            case "background":
                return 2;
            default:
                return 3;
            }
        }

        private void addCpu(List<JsonObject> rows, long busyNs, int cpuCount) {
            long capacity = (long) Math.max(1, cpuCount) * Math.max(1, fWindow.end - fWindow.start);
            JsonArray top = new JsonArray();
            List<String> parts = new ArrayList<>();
            rows.stream().filter(row -> row.get("cpu_ms").getAsDouble() > 0)
                    .sorted((a, b) -> Double.compare(b.get("cpu_ms").getAsDouble(), a.get("cpu_ms").getAsDouble()))
                    .limit(5)
                    .forEach(row -> {
                        JsonObject item = new JsonObject();
                        for (String key : new String[] {"pid", "name", "role", "cpu_ms", "cpu_percent_of_busy"}) {
                            item.add(key, row.get(key));
                        }
                        top.add(item);
                        parts.add(String.format(Locale.ROOT, "%s (PID %d, %s) %.3f ms (%.1f%%)",
                                UnifiedExplainer.str(row, "name"), row.get("pid").getAsInt(),
                                UnifiedExplainer.str(row, "role"), row.get("cpu_ms").getAsDouble(),
                                row.get("cpu_percent_of_busy").getAsDouble()));
                    });
            JsonObject data = new JsonObject();
            data.addProperty("busy_ms", busyNs / 1_000_000.0);
            data.addProperty("cpu_count", cpuCount);
            data.addProperty("busy_percent_of_capacity", busyNs * 100.0 / capacity);
            data.add("top_processes", top);
            add("trace.cpu_usage", null, String.format(Locale.ROOT,
                    "The CPUs were busy for %.3f ms in total (%.1f%% of the %d CPUs' time); most CPU time went to: %s.",
                    busyNs / 1_000_000.0, busyNs * 100.0 / capacity, cpuCount,
                    parts.isEmpty() ? "no process" : String.join(", ", parts)),
                    "tracecompass.state_system", data, "high", new JsonArray());
        }

        private void addProcessList(List<JsonObject> rows) {
            JsonArray list = new JsonArray();
            Map<String, Integer> byRole = new LinkedHashMap<>();
            for (JsonObject row : rows) {
                byRole.merge(UnifiedExplainer.str(row, "role"), 1, Integer::sum);
                if (list.size() < MAX_PROCESSES) {
                    JsonObject item = row.deepCopy();
                    item.remove("activity");
                    list.add(item);
                }
            }
            JsonObject data = new JsonObject();
            data.addProperty("active_process_count", rows.size());
            data.add("processes", list);
            data.addProperty("processes_omitted", Math.max(0, rows.size() - MAX_PROCESSES));
            JsonArray caveats = new JsonArray();
            caveats.add("Roles are inferred: 'workload' = started during the trace and either using at least 1% of the CPU "
                    + "time or living at least 10% of the window (or, if none did, the busiest process); short-lived helpers "
                    + "started during the trace count as background; "
                    + "'launcher' = its parent; 'tracer' = LTTng's own tools; 'background' = everything else.");
            List<String> counts = new ArrayList<>();
            byRole.forEach((role, count) -> counts.add(count + " " + role));
            add("trace.processes", null, String.format(Locale.ROOT,
                    "%d processes were active (ran on a CPU or made system calls): %s.",
                    rows.size(), String.join(", ", counts)),
                    "tracecompass.state_system+java.thread_activity", data, "medium", caveats);
        }

        private void addWorkload(List<JsonObject> rows) {
            rows.stream().filter(row -> "workload".equals(UnifiedExplainer.str(row, "role")))
                    .limit(MAX_WORKLOAD)
                    .forEach(row -> {
                        JsonObject activity = UnifiedExplainer.obj(row, "activity");
                        JsonObject data = new JsonObject();
                        for (String key : new String[] {"pid", "name", "thread_count", "cpu_ms",
                                "cpu_percent_of_busy", "created_at_offset_ms", "parent_pid", "program_executed",
                                "exit_status", "exited_at_offset_ms"}) {
                            if (row.has(key)) {
                                data.add(key, row.get(key));
                            }
                        }
                        if (activity != null) {
                            for (String key : new String[] {"threads", "syscall_count", "files", "standard_streams",
                                    "sockets_pipes_devices_other", "thread_names", "created_threads_or_processes",
                                    "exit_kind", "syscalls_by_category", "top_syscalls"}) {
                                if (activity.has(key)) {
                                    data.add(key, activity.get(key));
                                }
                            }
                            data.addProperty("runtime_loader_file_count",
                                    UnifiedExplainer.arr(activity, "runtime_loader_files").size());
                        }
                        String threadText = threadNames(row, activity, data);
                        JsonArray caveats = new JsonArray();
                        for (JsonElement element : UnifiedExplainer.arr(activity, "sockets_pipes_devices_other")) {
                            if ("socket".equals(UnifiedExplainer.str(element.getAsJsonObject(), "kind"))) {
                                caveats.add("The trace records no socket addresses, so sockets are not linked to the other end.");
                                break;
                            }
                        }
                        String claim = (threadText.isEmpty() ? "" : threadText + " ")
                                + (activity != null && activity.has("summary")
                                        ? UnifiedExplainer.str(activity, "summary")
                                        : String.format(Locale.ROOT, "%s (PID %d) used %.3f ms of CPU time.",
                                                UnifiedExplainer.str(row, "name"), row.get("pid").getAsInt(),
                                                row.get("cpu_ms").getAsDouble()));
                        add("trace.workload_process", "process " + row.get("pid").getAsInt(), claim,
                                "java.thread_activity", data, "high", caveats);
                    });
        }

        /**
         * The process's threads with the names the kernel recorded for them
         * (their last name in the window: a thread renamed by the program,
         * e.g. "worker-0", shows that name). Adds them to {@code data} and
         * returns a sentence for the claim.
         */
        private String threadNames(JsonObject row, JsonObject activity, JsonObject data) {
            JsonArray tids = UnifiedExplainer.arr(activity, "threads");
            if (fSs == null || tids.size() == 0) {
                return "";
            }
            int pid = row.get("pid").getAsInt();
            Map<Integer, Integer> quarkTid = new LinkedHashMap<>();
            for (JsonElement element : tids) {
                int tid = element.getAsInt();
                quarkTid.put(fSs.optQuarkAbsolute("Threads", String.valueOf(tid), "Exec_name"), tid);
            }
            History history = History.load(fSs, quarkTid.keySet(), fWindow.start, fWindow.end);
            JsonArray list = new JsonArray();
            List<String> parts = new ArrayList<>();
            for (Map.Entry<Integer, Integer> entry : quarkTid.entrySet()) {
                String name = null;
                for (ITmfStateInterval interval : history.intervals(entry.getKey())) {
                    if (interval.getValue() instanceof String) {
                        name = (String) interval.getValue();
                    }
                }
                int tid = entry.getValue();
                JsonObject item = new JsonObject();
                item.addProperty("tid", tid);
                item.addProperty("name", name);
                item.addProperty("main_thread", tid == pid);
                list.add(item);
                if (parts.size() < 20) {
                    parts.add(tid + " " + (name == null ? "(unnamed)" : name) + (tid == pid ? " (main thread)" : ""));
                }
            }
            data.add("thread_list", list);
            return String.format(Locale.ROOT, "%s (PID %d) has %d thread(s), named in the trace: %s%s.",
                    UnifiedExplainer.str(row, "name"), pid, list.size(), String.join(", ", parts),
                    list.size() > 20 ? ", and " + (list.size() - 20) + " more" : "");
        }

        private void addTimeline(List<JsonObject> rows) {
            List<JsonObject> steps = new ArrayList<>();
            for (JsonObject row : rows) {
                if ("background".equals(UnifiedExplainer.str(row, "role"))) {
                    continue;
                }
                String who = UnifiedExplainer.str(row, "name") + " (PID " + row.get("pid").getAsInt() + ")";
                if (row.has("created_at_offset_ms")) {
                    steps.add(step(row.get("created_at_offset_ms").getAsDouble(), who, "created"
                            + (row.has("parent_pid") ? " by PID " + row.get("parent_pid").getAsInt() : "")));
                }
                if (row.has("program_executed")) {
                    steps.add(step(row.get("program_executed_at_offset_ms").getAsDouble(), who,
                            "ran " + UnifiedExplainer.str(row, "program_executed")));
                }
                JsonObject activity = UnifiedExplainer.obj(row, "activity");
                if ("workload".equals(UnifiedExplainer.str(row, "role")) && activity != null) {
                    for (JsonElement element : UnifiedExplainer.arr(activity, "timeline")) {
                        JsonObject step = element.getAsJsonObject();
                        String operation = UnifiedExplainer.str(step, "operation");
                        if (operation.startsWith("create thread") || operation.startsWith("rename")
                                || operation.startsWith("delete")) {
                            steps.add(step(step.get("offset_ms").getAsDouble(), who, operation
                                    + (step.has("target") ? " " + UnifiedExplainer.str(step, "target") : "")));
                        }
                    }
                }
                if (row.has("exited_at_offset_ms")) {
                    steps.add(step(row.get("exited_at_offset_ms").getAsDouble(), who,
                            "ended with status " + UnifiedExplainer.str(row, "exit_status")));
                }
            }
            if (steps.isEmpty()) {
                return;
            }
            steps.sort((a, b) -> Double.compare(a.get("offset_ms").getAsDouble(), b.get("offset_ms").getAsDouble()));
            JsonArray ordered = new JsonArray();
            List<String> text = new ArrayList<>();
            for (JsonObject step : steps.subList(0, Math.min(MAX_TIMELINE, steps.size()))) {
                ordered.add(step);
                text.add(String.format(Locale.ROOT, "%.3f ms %s %s", step.get("offset_ms").getAsDouble(),
                        UnifiedExplainer.str(step, "process"), UnifiedExplainer.str(step, "event")));
            }
            JsonObject data = new JsonObject();
            data.add("steps", ordered);
            data.addProperty("steps_omitted", Math.max(0, steps.size() - MAX_TIMELINE));
            add("trace.timeline", null, "In order: " + String.join("; ", text) + ".",
                    "java.thread_activity", data, "high", new JsonArray());
        }

        private static JsonObject step(double offsetMs, String process, String event) {
            JsonObject step = new JsonObject();
            step.addProperty("offset_ms", offsetMs);
            step.addProperty("process", process);
            step.addProperty("event", event);
            return step;
        }

        private void addBackground(List<JsonObject> rows, long busyNs) {
            for (String role : new String[] {"background", "tracer"}) {
                List<JsonObject> group = new ArrayList<>();
                rows.stream().filter(row -> role.equals(UnifiedExplainer.str(row, "role"))).forEach(group::add);
                if (group.isEmpty()) {
                    continue;
                }
                double cpuMs = group.stream().mapToDouble(row -> row.get("cpu_ms").getAsDouble()).sum();
                long syscalls = group.stream().mapToLong(row -> row.get("syscall_count").getAsLong()).sum();
                JsonArray names = new JsonArray();
                Set<String> seen = new java.util.LinkedHashSet<>();
                group.stream()
                        .sorted((a, b) -> Double.compare(b.get("cpu_ms").getAsDouble(), a.get("cpu_ms").getAsDouble()))
                        .forEach(row -> seen.add(UnifiedExplainer.str(row, "name")));
                seen.stream().limit(10).forEach(names::add);
                JsonObject data = new JsonObject();
                data.addProperty("process_count", group.size());
                data.addProperty("cpu_ms", cpuMs);
                data.addProperty("cpu_percent_of_busy", busyNs == 0 ? 0 : cpuMs * 1_000_000.0 * 100.0 / busyNs);
                data.addProperty("syscall_count", syscalls);
                data.add("names", names);
                JsonArray caveats = new JsonArray();
                if ("tracer".equals(role)) {
                    caveats.add("This is LTTng's own work (starting, stopping and writing the trace), not the traced program.");
                }
                List<String> nameText = new ArrayList<>();
                names.forEach(name -> nameText.add(name.getAsString()));
                add("trace." + role, null, String.format(Locale.ROOT,
                        "%s: %d process(es) (%s) used %.3f ms of CPU time (%.1f%% of busy time) and made %,d system calls.",
                        "tracer".equals(role) ? "The tracer's own tools" : "Other (background) activity",
                        group.size(), String.join(", ", nameText), cpuMs,
                        busyNs == 0 ? 0 : cpuMs * 1_000_000.0 * 100.0 / busyNs, syscalls),
                        "tracecompass.state_system+java.thread_activity", data, "high", caveats);
            }
        }

        private void add(String id, String about, String claim, String analysis, JsonObject data,
                String confidence, JsonArray caveats) {
            JsonObject finding = finding(id, about != null ? about : fWindow.about, null, claim, fWin,
                    analysis, data, confidence, caveats);
            fFindings.add(finding);
        }
    }

    /**
     * Explains a question about one process and its threads ("which thread
     * is the bottleneck of batch_server?"): how each thread's time splits,
     * who woke each thread after each of its waits (from the execution
     * graph's wake-up edges, one pass per thread rather than a critical path
     * per thread), which thread the others spent most of their waiting on,
     * and one example critical-path chain through that thread.
     */
    static final class ProcessExplainer {

        /** Wait types: a horizontal edge of one of these is the thread waiting for something. */
        private static final Set<String> WAIT_EDGES = Set.of(
                "BLOCKED", "TIMER", "NETWORK", "BLOCK_DEVICE", "IPI", "USER_INPUT", "INTERRUPTED");
        private static final int MAX_EDGES = 20;

        /** Waiting by one thread on one cause: total, count, and its longest single wait. */
        /** One wait of one thread: when, and what ended it ("tid:N" or a wait type). */
        static final class WaitInterval {
            final long start;
            final long end;
            final String cause;

            WaitInterval(long start, long end, String cause) {
                this.start = start;
                this.end = end;
                this.cause = cause;
            }
        }

        private static final class Wait {
            long ns;
            int count;
            long longestStart;
            long longestEnd = -1;

            void add(long start, long end) {
                ns += end - start;
                count++;
                if (end - start > longestEnd - longestStart) {
                    longestStart = start;
                    longestEnd = end;
                }
            }
        }

        private final ITmfTrace fTrace;
        private final int fPid;
        private final ExplainWindow fWindow;
        private final JsonObject fWin;
        private final boolean fDescribe;
        private final KernelAnalysisModule fKernel;
        private final JsonArray fFindings = new JsonArray();
        private final String fAbout;
        /** Filled with the bottleneck and the main thread's waits on it, for TMLL; may be null. */
        private JsonObject fSide;

        private ProcessExplainer(ITmfTrace trace, int pid, ExplainWindow window, JsonObject win,
                boolean describe, KernelAnalysisModule kernel) {
            fTrace = trace;
            fPid = pid;
            fWindow = window;
            fWin = win;
            fDescribe = describe;
            fKernel = kernel;
            fAbout = "process " + pid;
        }

        static JsonArray explain(ITmfTrace trace, int pid, ExplainWindow window, boolean describe, JsonObject side) {
            KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                    trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
            if (kernel == null) {
                return new JsonArray();
            }
            kernel.schedule();
            kernel.waitForCompletion();
            JsonObject win = new JsonObject();
            long traceStart = trace.getStartTime().toNanos();
            win.addProperty("source", window.source);
            win.addProperty("start_ns", window.start);
            win.addProperty("end_ns", window.end);
            win.addProperty("start_offset_ms", (window.start - traceStart) / 1_000_000.0);
            win.addProperty("end_offset_ms", (window.end - traceStart) / 1_000_000.0);
            if (window.details != null && window.details.has("interpreted_as")) {
                win.add("interpreted_as", window.details.get("interpreted_as"));
            }
            ProcessExplainer explainer = new ProcessExplainer(trace, pid, window, win, describe, kernel);
            explainer.fSide = side;
            explainer.run();
            return explainer.fFindings;
        }

        /**
         * The PID a thread belonged to at any time in [start, end]. Asking at
         * one instant is not enough: a thread's attributes only exist between
         * its creation and its sched_process_free, so a thread created after
         * the start and freed before the end has no PID at either.
         */
        static Integer pidOfThread(KernelAnalysisModule kernel, int tid, long start, long end) {
            return pidMap(kernel, start, end).get(tid);
        }

        /** Recent TID -> PID maps, by state system and window. */
        private static final Map<String, Map<Integer, Integer>> PID_MAPS = java.util.Collections.synchronizedMap(
                new LinkedHashMap<String, Map<Integer, Integer>>(8, 0.75f, true) {
                    private static final long serialVersionUID = 1L;

                });

        /**
         * Every thread's PID during [start, end], from one sweep over all the
         * Threads/<tid>/PID attributes (thousands of threads on a long
         * desktop trace; one query per thread took minutes).
         */
        static Map<Integer, Integer> pidMap(KernelAnalysisModule kernel, long start, long end) {
            ITmfStateSystem ss = kernel.getStateSystem();
            if (ss == null) {
                return Map.of();
            }
            String key = System.identityHashCode(ss) + "|" + start + "|" + end;
            Map<Integer, Integer> cached = PID_MAPS.get(key);
            if (cached != null) {
                return cached;
            }
            Map<Integer, Integer> tidOfQuark = new HashMap<>();
            /* As in KernelThreadInformationProvider.getProcessId: no PID attribute means the thread is the process. */
            Map<Integer, Integer> map = new HashMap<>();
            int threads = ss.optQuarkAbsolute("Threads");
            if (threads != ITmfStateSystem.INVALID_ATTRIBUTE) {
                for (int threadQuark : ss.getSubAttributes(threads, false)) {
                    int tid;
                    try {
                        tid = Integer.parseInt(ss.getAttributeName(threadQuark));
                    } catch (NumberFormatException exception) {
                        continue;
                    }
                    int pidQuark = ss.optQuarkRelative(threadQuark, "PID");
                    if (pidQuark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                        tidOfQuark.put(pidQuark, tid);
                    } else {
                        map.put(tid, tid);
                    }
                }
            }
            History history = History.load(ss, tidOfQuark.keySet(), start, end);
            for (Map.Entry<Integer, Integer> entry : tidOfQuark.entrySet()) {
                for (ITmfStateInterval interval : history.intervals(entry.getKey())) {
                    if (interval.getValue() instanceof Integer) {
                        map.putIfAbsent(entry.getValue(), (Integer) interval.getValue());
                        break;
                    }
                }
            }
            synchronized (PID_MAPS) {
                if (PID_MAPS.size() >= 8) {
                    PID_MAPS.remove(PID_MAPS.keySet().iterator().next());
                }
                PID_MAPS.put(key, map);
            }
            return map;
        }

        /** The threads of {@code pid}, from the kernel analysis. */
        static List<Integer> threadsOf(KernelAnalysisModule kernel, int pid, long start, long end) {
            List<Integer> threads = new ArrayList<>();
            for (Map.Entry<Integer, Integer> entry : pidMap(kernel, start, end).entrySet()) {
                if (entry.getValue() == pid) {
                    threads.add(entry.getKey());
                }
            }
            if (!threads.contains(pid)) {
                threads.add(pid);
            }
            threads.sort(Integer::compare);
            return threads;
        }

        private String name(int tid) {
            if (tid == 0) {
                return "idle (swapper)";
            }
            String name = KernelThreadInformationProvider.getExecutableName(fKernel, tid, fWindow.end);
            return name == null ? "unknown" : name;
        }

        private void run() {
            String processName = name(fPid);
            List<Integer> tids = threadsOf(fKernel, fPid, fWindow.start, fWindow.end);

            // 1. Each thread's time split.
            Map<Integer, Map<String, Long>> split = new LinkedHashMap<>();
            Map<Integer, Long> alive = new HashMap<>();
            Map<Integer, List<long[]>> status = new HashMap<>();
            for (int tid : tids) {
                Map<String, Long> states = new LinkedHashMap<>();
                List<long[]> timeline = new ArrayList<>();
                long aliveNs = 0;
                Iterator<ITmfStateInterval> it = processHistory(tids)
                        .intervals(threadQuark(tid), fWindow.start, fWindow.end).iterator();
                while (it.hasNext()) {
                    ITmfStateInterval interval = it.next();
                    long s = Math.max(interval.getStartTime(), fWindow.start);
                    long e = Math.min(interval.getEndTime(), fWindow.end);
                    if (e < s) {
                        continue;
                    }
                    String state = controlFlowStateName(ProcessStatus.getStatusFromStateValue(interval.getStateValue()));
                    long length = inclusiveDuration(s, e);
                    states.merge(state, length, Long::sum);
                    timeline.add(new long[] {s, e + 1, state.startsWith("RUNNING") ? 1
                            : "RUNNABLE_WAITING_FOR_CPU".equals(state) ? 2 : 0});
                    if (!Set.of("NOT_ALIVE", "EXITED", "ZOMBIE", "UNKNOWN").contains(state)) {
                        aliveNs += length;
                        fFirstAlive.merge(tid, s, Math::min);
                        fLastAlive.merge(tid, e + 1, Math::max);
                    }
                    if (state.startsWith("RUNNING")) {
                        fLastRun.merge(tid, e + 1, Math::max);
                    }
                }
                if (aliveNs > 0) {
                    split.put(tid, states);
                    alive.put(tid, aliveNs);
                    status.put(tid, timeline);
                }
            }
            if (split.isEmpty()) {
                fFindings.add(finding("process.threads", fAbout, null, String.format(Locale.ROOT,
                        "Process %d (%s) had no live threads in this window.", fPid, processName),
                        fWin, "tracecompass.state_system", new JsonObject(), "high", new JsonArray()));
                return;
            }
            addThreads(processName, split, alive);

            // 1b. Waits that never ended: the wait graph below only sees waits that a wake-up ended.
            try {
                StuckWaits.add(fFindings, fTrace, fKernel, processHistory(tids), split.keySet(), this::name,
                        new StuckWaits.ExplainWindowView(fWindow.start, fWindow.end, fTrace.getStartTime().toNanos()),
                        fWin, fAbout, fPid, processName);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }

            // 2. Who woke each thread after each wait.
            Map<Integer, List<WaitInterval>> intervals = new HashMap<>();
            Map<Integer, Map<String, Wait>> waits = waitGraph(split.keySet(), intervals);
            if (waits == null) {
                return;
            }
            addWaitGraph(processName, split.keySet(), waits);
            if (!addMainThreadBottleneck(processName, status, intervals, split.keySet())) {
                addBottleneck(processName, split, alive, waits);
            }

            // 3. What the process did: its system calls by kind (count and time), files, and the
            // threads and processes it created. Every process question gets it, not only "what does
            // it do": questions about many small calls, slow calls, memory mapping, starting
            // processes or touching files need these counts (one pass per trace, cached).
            JsonObject activity = null;
            JsonObject allProcesses = null;
            {
                boolean windowed = !"whole_trace".equals(fWindow.source);
                JsonObject summary = ThreadActivitySummarizer.summarizeProcesses(fTrace,
                        windowed ? fWindow.start : null, windowed ? fWindow.end : null);
                fAllSummary = summary;
                allProcesses = UnifiedExplainer.obj(summary, "processes");
                activity = UnifiedExplainer.obj(allProcesses, String.valueOf(fPid));
                if (activity != null && activity.has("summary")) {
                    JsonObject data = new JsonObject();
                    for (String key : new String[] {"threads", "syscall_count", "program_executed", "files",
                            "file_relations", "standard_streams", "sockets_pipes_devices_other", "thread_names",
                            "created_threads_or_processes", "exit_status", "exit_kind", "rates",
                            "syscall_latency", "syscall_results", "futex_addresses", "migrations",
                            "syscalls_by_category", "top_syscalls"}) {
                        if (activity.has(key)) {
                            data.add(key, activity.get(key).deepCopy());
                        }
                    }
                    fFindings.add(finding("process.activity", fAbout, "running",
                            UnifiedExplainer.str(activity, "summary") + activitySizes(activity), fWin,
                            "java.thread_activity", data, "high", activityCaveats()));
                }
            }

            // 4. Sizes and comparisons computed here, so the answer does not have to judge them: which
            // threads are idle, how each group of like threads compares, who takes the CPU from the
            // process's threads, and its start-up, shutdown and child processes.
            try {
                labelThreadActivity(split, alive, intervals, activity);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addPeerComparison(split, alive, status, intervals, activity);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addCpuCompetition(split, alive, status);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addLifecycle(split, status, intervals, activity, allProcesses);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addThreadCycleTrends(split);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addNetwork(split, alive, intervals, activity);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addCallTimeByThread(alive, activity);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addInterrupts(summaryOfAll());
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addWakeFanOut(split, status, intervals);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addBursts(split, status);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
            try {
                addPriorityInversion(status, intervals);
            } catch (RuntimeException exception) {
                exception.printStackTrace();
            }
        }

        private JsonObject fAllSummary;

        private JsonObject summaryOfAll() {
            return fAllSummary;
        }

        /** The CPUs that carry the process's work (from addCpuCompetition). */
        private Set<Integer> fCpusUsed = Set.of();

        // ---------------------------------------------------------------
        // Time inside system calls, per thread, by what the calls wait on
        // ---------------------------------------------------------------

        private static String shareSize(double percent) {
            return percent >= 50 ? "most of its time" : percent >= 20 ? "a large share" : percent >= 5 ? "a noticeable share"
                    : "a small share";
        }

        /**
         * One thread's time inside its system calls, from the summarizer's syscall_time_by_thread row: per
         * kind of call (storage I/O, network, sleeps, locks, ...) the time and share of the thread's alive
         * time, and the total inside request and I/O calls, apart from calls that wait for another
         * thread, an event or a time to come (sleeps, poll and epoll, futex, pipes, child processes,
         * signals). With a text for the claim.
         */
        static JsonObject callTimeRow(int tid, String name, JsonArray kinds, long aliveNs) {
            JsonObject row = new JsonObject();
            row.addProperty("tid", tid);
            row.addProperty("name", name);
            row.addProperty("alive_ms", aliveNs / 1e6);
            double requestMs = 0;
            JsonArray byKind = new JsonArray();
            List<String> requestText = new ArrayList<>();
            List<String> waitingText = new ArrayList<>();
            for (JsonElement element : kinds) {
                JsonObject kind = element.getAsJsonObject().deepCopy();
                double ms = UnifiedExplainer.dbl(kind, "total_ms", 0);
                double percent = ms * 1e8 / Math.max(1, aliveNs);
                kind.addProperty("percent_of_its_time", percent);
                byKind.add(kind);
                boolean waiting = UnifiedExplainer.bool(kind, "waiting");
                if (!waiting) {
                    requestMs += ms;
                }
                if (percent < 0.5) {
                    continue;
                }
                List<String> calls = new ArrayList<>();
                for (JsonElement callElement : UnifiedExplainer.arr(kind, "syscalls")) {
                    JsonObject call = callElement.getAsJsonObject();
                    long count = UnifiedExplainer.num(call, "calls", 0L);
                    double callMs = UnifiedExplainer.dbl(call, "total_ms", 0);
                    if (calls.size() < 3 && callMs * 1e8 / Math.max(1, aliveNs) >= 0.5) {
                        calls.add(String.format(Locale.ROOT, "%s %,d calls, %,.1f ms, mean %.3f ms", UnifiedExplainer.str(call, "syscall"),
                                count, callMs, callMs / Math.max(1, count)));
                    }
                }
                String text = String.format(Locale.ROOT, "%s %.1f%% (%s)", UnifiedExplainer.str(kind, "kind"), percent,
                        String.join("; ", calls));
                (waiting ? waitingText : requestText).add(text);
            }
            double requestPercent = requestMs * 1e8 / Math.max(1, aliveNs);
            row.addProperty("request_and_io_ms", requestMs);
            row.addProperty("request_and_io_percent", requestPercent);
            row.addProperty("request_and_io_size", shareSize(requestPercent));
            row.add("by_kind", byKind);
            row.addProperty("text", String.format(Locale.ROOT,
                    "TID %d (%s) spent %.1f%% of its time (%,.1f ms of %,.1f ms alive) inside request and I/O system calls, "
                            + "%s%s. Time in calls that wait for another thread, an event or a time to come: %s.",
                    tid, name, requestPercent, requestMs, aliveNs / 1e6, shareSize(requestPercent),
                    requestText.isEmpty() ? "" : ": " + String.join("; ", requestText),
                    waitingText.isEmpty() ? "none over 0.5% of its time" : String.join("; ", waitingText)));
            return row;
        }

        static JsonArray callTimeCaveats() {
            JsonArray caveats = new JsonArray();
            caveats.add("Time inside a call runs from its entry to its exit: it includes the time the thread was blocked in "
                    + "it (for a sync, waiting for the disk) and the kernel's own work for it. Reads and writes are classed by "
                    + "their descriptor: on a file storage I/O, on a socket network, on a pipe waiting for the other end.");
            caveats.add("Request and I/O calls are every kind except the waiting ones (sleeps and timers, poll/epoll/select, "
                    + "futex, pipes, waiting for child processes or signals), which are idle time or waits for other threads.");
            caveats.add("This is the share of time spent in those calls, which a per-call latency label (long tail or not) "
                    + "does not tell: calls that are each fast can still take a large share of a thread's time.");
            return caveats;
        }

        /** process.syscall_time_by_thread: each thread's time inside its system calls, by kind of call. */
        private void addCallTimeByThread(Map<Integer, Long> alive, JsonObject activity) {
            JsonObject byThread = UnifiedExplainer.obj(activity, "syscall_time_by_thread");
            if (byThread == null) {
                return;
            }
            List<JsonObject> rows = new ArrayList<>();
            for (Map.Entry<String, JsonElement> entry : byThread.entrySet()) {
                int tid = Integer.parseInt(entry.getKey());
                Long aliveNs = alive.get(tid);
                if (aliveNs == null || aliveNs <= 0 || !entry.getValue().isJsonArray()) {
                    continue;
                }
                rows.add(callTimeRow(tid, name(tid), entry.getValue().getAsJsonArray(), aliveNs));
            }
            if (rows.isEmpty()) {
                return;
            }
            rows.sort((a, b) -> Double.compare(UnifiedExplainer.dbl(b, "request_and_io_percent", 0),
                    UnifiedExplainer.dbl(a, "request_and_io_percent", 0)));
            JsonArray threads = new JsonArray();
            List<String> text = new ArrayList<>();
            for (JsonObject row : rows.subList(0, Math.min(16, rows.size()))) {
                threads.add(row);
                if (text.size() < 4) {
                    text.add(UnifiedExplainer.str(row, "text"));
                }
            }
            JsonObject data = new JsonObject();
            data.add("threads", threads);
            fFindings.add(finding("process.syscall_time_by_thread", fAbout, null,
                    "Time inside system calls per thread, most time in request and I/O calls first. " + String.join(" ", text),
                    fWin, "java.thread_activity", data, "high", callTimeCaveats()));
        }

        // ---------------------------------------------------------------
        // Network: who is on the other end, and connection attempts
        // ---------------------------------------------------------------

        /**
         * Its threads' waits ended by received packets, and where those packets came from: a local process
         * (loopback: the received packet is processed in the sender's context) or a network device
         * (another machine); and its connection attempts (connect, or the poll after a non-blocking
         * connect) and how they ended, which a timeout ends and the wait graph counts as a timer.
         */
        private void addNetwork(Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive,
                Map<Integer, List<WaitInterval>> intervals, JsonObject activity) {
            JsonObject wakes = UnifiedExplainer.obj(activity, "network_wake_ups");
            JsonObject connects = UnifiedExplainer.obj(activity, "connect_attempts");
            Map<Integer, long[]> networkWaits = new LinkedHashMap<>();
            for (int tid : split.keySet()) {
                for (WaitInterval wait : intervals.getOrDefault(tid, List.of())) {
                    if ("NETWORK".equals(wait.cause)) {
                        long[] stat = networkWaits.computeIfAbsent(tid, k -> new long[3]);
                        stat[0]++;
                        stat[1] += wait.end - wait.start;
                        stat[2] = Math.max(stat[2], wait.end - wait.start);
                    }
                }
            }
            if (wakes == null && connects == null && networkWaits.isEmpty()) {
                return;
            }
            JsonObject data = new JsonObject();
            List<String> parts = new ArrayList<>();
            JsonArray threads = new JsonArray();
            List<String> threadText = new ArrayList<>();
            networkWaits.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue()[1], a.getValue()[1])).limit(8)
                    .forEach(entry -> {
                        long[] stat = entry.getValue();
                        JsonObject row = new JsonObject();
                        row.addProperty("tid", entry.getKey());
                        row.addProperty("name", name(entry.getKey()));
                        row.addProperty("waits", stat[0]);
                        row.addProperty("waited_ms", stat[1] / 1e6);
                        row.addProperty("percent_of_its_time", stat[1] * 100.0 / Math.max(1, alive.get(entry.getKey())));
                        row.addProperty("mean_wait_ms", stat[1] / 1e6 / stat[0]);
                        row.addProperty("longest_wait_ms", stat[2] / 1e6);
                        threads.add(row);
                        if (threadText.size() < 4) {
                            threadText.add(String.format(Locale.ROOT, "%s %.1f%% of its time (%d waits, mean %.3f ms)",
                                    name(entry.getKey()), stat[1] * 100.0 / Math.max(1, alive.get(entry.getKey())), stat[0],
                                    stat[1] / 1e6 / stat[0]));
                        }
                    });
            data.add("waits_ended_by_received_packets", threads);
            if (!threadText.isEmpty()) {
                parts.add("waits ended by a received packet: " + String.join("; ", threadText));
            }
            String where = "unknown";
            if (wakes != null) {
                data.add("packet_wake_ups", wakes);
                double local = UnifiedExplainer.dbl(wakes, "local_percent", 0);
                List<String> contextText = new ArrayList<>();
                for (JsonElement element : UnifiedExplainer.arr(wakes, "contexts")) {
                    JsonObject context = element.getAsJsonObject();
                    long contextPid = UnifiedExplainer.num(context, "context_pid", -1L);
                    String who = UnifiedExplainer.num(context, "context_tid", 0L) <= 0 ? "a network device"
                            : contextPid == fPid ? UnifiedExplainer.str(context, "context") + " (its own thread)"
                                    : UnifiedExplainer.str(context, "context") + " (PID " + contextPid + ", " + name((int) contextPid) + ", on this machine)";
                    if (contextText.size() < 3) {
                        contextText.add(String.format(Locale.ROOT, "%s %.0f%%", who,
                                UnifiedExplainer.num(context, "wake_ups", 0L) * 100.0 / Math.max(1, UnifiedExplainer.num(wakes, "wake_ups", 1L))));
                    }
                }
                where = local >= 80 ? "a local process: the other end is on this machine (loopback), not another machine"
                        : local <= 20 ? "a network device: the other end is another machine" : "both local processes and a network device";
                parts.add(String.format(Locale.ROOT, "the packets that woke its threads came from %s (%s)", where,
                        String.join(", ", contextText)));
            }
            data.addProperty("other_end", where);
            if (connects != null) {
                data.add("connect_attempts", connects);
                List<String> outcomeText = new ArrayList<>();
                for (Map.Entry<String, JsonElement> outcome : UnifiedExplainer.obj(connects, "outcomes").entrySet()) {
                    JsonObject o = outcome.getValue().getAsJsonObject();
                    outcomeText.add(String.format(Locale.ROOT, "%d %s (mean wait %.1f ms)", UnifiedExplainer.num(o, "attempts", 0L),
                            outcome.getKey(), UnifiedExplainer.dbl(o, "mean_wait_ms", 0)));
                }
                double windowMs = Math.max(1, (fWindow.end - fWindow.start) / 1e6);
                int threadsConnecting = Math.max(1, UnifiedExplainer.obj(connects, "by_thread").size());
                parts.add(String.format(Locale.ROOT, "it tried to connect to another host %d times (%.1f per second): %s; "
                        + "%.1f ms waiting in all, about %.1f%% of the time of each of the %d connecting thread(s) (%s); a "
                        + "timeout ends these waits, but they are waits on the network", UnifiedExplainer.num(connects, "attempts", 0L),
                        UnifiedExplainer.dbl(connects, "per_second", 0), String.join(", ", outcomeText),
                        UnifiedExplainer.dbl(connects, "waited_ms", 0),
                        UnifiedExplainer.dbl(connects, "waited_ms", 0) * 100.0 / threadsConnecting / windowMs, threadsConnecting,
                        UnifiedExplainer.obj(connects, "by_thread")));
                data.addProperty("connect_wait_percent_per_thread",
                        UnifiedExplainer.dbl(connects, "waited_ms", 0) * 100.0 / threadsConnecting / windowMs);
            }
            JsonArray caveats = new JsonArray();
            caveats.add("The trace records no addresses. A received packet on loopback is processed in the sending thread's "
                    + "context, which names the local process at the other end; a packet from a device arrives in interrupt "
                    + "context (the idle task or whatever thread was running).");
            fFindings.add(finding("process.network", fAbout, "blocked", "Network use of process " + fPid + " (" + name(fPid)
                    + "): " + String.join("; ", parts) + ".", fWin, "java.thread_activity+tracecompass.execution_graph",
                    data, "medium", caveats));
        }

        // ---------------------------------------------------------------
        // Interrupts on the CPUs the process runs on
        // ---------------------------------------------------------------

        private void addInterrupts(JsonObject summary) {
            JsonObject byCpu = UnifiedExplainer.obj(summary, "interrupts_by_cpu");
            if (byCpu == null || fCpusUsed.isEmpty()) {
                return;
            }
            addInterruptFinding(fFindings, byCpu, fCpusUsed, fWindow.start, fWindow.end, fTrace.getStartTime().toNanos(),
                    fAbout, fWin, "process " + fPid + " (" + name(fPid) + ")");
        }

        /** Interrupt time on the given CPUs, overall and in the worst stretch, with a label (heavy from 10%). */
        static void addInterruptFinding(JsonArray findings, JsonObject byCpu, Collection<Integer> cpus, long start, long end,
                long traceStart, String about, JsonObject win, String who) {
            JsonArray rows = new JsonArray();
            List<String> parts = new ArrayList<>();
            double worst = 0;
            for (int cpu : cpus) {
                JsonObject stats = UnifiedExplainer.obj(byCpu, String.valueOf(cpu));
                if (stats == null) {
                    continue;
                }
                JsonArray bins = UnifiedExplainer.arr(stats, "percent_per_twentieth");
                int peak = 0;
                for (int i = 0; i < bins.size(); i++) {
                    if (bins.get(i).getAsDouble() > bins.get(peak).getAsDouble()) {
                        peak = i;
                    }
                }
                double peakPercent = bins.size() == 0 ? 0 : bins.get(peak).getAsDouble();
                int from = peak;
                int to = peak;
                while (from > 0 && bins.get(from - 1).getAsDouble() >= peakPercent / 2) {
                    from--;
                }
                while (to < bins.size() - 1 && bins.get(to + 1).getAsDouble() >= peakPercent / 2) {
                    to++;
                }
                long bin = (end - start) / 20;
                double overall = UnifiedExplainer.dbl(stats, "percent_of_window", 0);
                worst = Math.max(worst, peakPercent);
                JsonObject row = new JsonObject();
                row.addProperty("cpu", cpu);
                row.addProperty("percent_of_window", overall);
                row.addProperty("peak_percent", peakPercent);
                row.addProperty("peak_stretch_start_offset_ms", (start + from * bin - traceStart) / 1e6);
                row.addProperty("peak_stretch_end_offset_ms", (start + (to + 1) * bin - traceStart) / 1e6);
                row.add("by_source_ms", UnifiedExplainer.obj(stats, "by_source_ms"));
                row.addProperty("level", peakPercent >= 10 || overall >= 10 ? "heavy (10% of the CPU or more)"
                        : peakPercent >= 3 ? "moderate" : "low");
                rows.add(row);
                parts.add(String.format(Locale.ROOT, "CPU %d %.1f%% of the time overall, up to %.1f%% from %.0f ms to %.0f ms "
                        + "(%s), mostly %s", cpu, overall, peakPercent, (start + from * bin - traceStart) / 1e6,
                        (start + (to + 1) * bin - traceStart) / 1e6, UnifiedExplainer.str(row, "level"),
                        UnifiedExplainer.obj(stats, "by_source_ms")));
            }
            if (rows.size() == 0) {
                return;
            }
            JsonObject data = new JsonObject();
            data.add("cpus", rows);
            data.addProperty("worst_percent", worst);
            JsonArray caveats = new JsonArray();
            caveats.add("Hard interrupt and softirq time on these CPUs, from irq_handler and irq_softirq events, per twentieth "
                    + "of the window; the handler name tells the device (nvme: disk completions, a network card, a timer). "
                    + "Heavy from 10% of a CPU.");
            findings.add(finding("cpu.interrupts", about, "running", "Interrupt handling on the CPU(s) " + who
                    + " runs on: " + String.join("; ", parts) + ".", win, "java.thread_activity", data, "high", caveats));
        }

        // ---------------------------------------------------------------
        // Wake fan-out: one wake-up releasing many threads (thundering herd)
        // ---------------------------------------------------------------

        private static double runningBetween(List<long[]> timeline, long start, long end) {
            int low = 0;
            int high = timeline.size();
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (timeline.get(mid)[1] <= start) {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            long ran = 0;
            for (int i = low; i < timeline.size() && timeline.get(i)[0] < end; i++) {
                if (timeline.get(i)[2] == 1) {
                    ran += Math.max(0, Math.min(end, timeline.get(i)[1]) - Math.max(start, timeline.get(i)[0]));
                }
            }
            return ran;
        }

        /**
         * For each thread that wakes several others: how many threads one wake-up releases (wake-ups within
         * 50 us of each other count as one), and how many of the woken run under 50 us before waiting again
         * (they found nothing to do). Many released and most going straight back is a thundering herd.
         */
        private void addWakeFanOut(Map<Integer, Map<String, Long>> split, Map<Integer, List<long[]>> status,
                Map<Integer, List<WaitInterval>> intervals) {
            Map<Integer, List<long[]>> wokenBy = new HashMap<>();
            Map<Integer, List<WaitInterval>> byThread = new HashMap<>();
            for (int tid : split.keySet()) {
                List<WaitInterval> waits = new ArrayList<>(intervals.getOrDefault(tid, List.of()));
                waits.sort((a, b) -> Long.compare(a.start, b.start));
                byThread.put(tid, waits);
                for (WaitInterval wait : waits) {
                    if (wait.cause.startsWith("tid:")) {
                        int waker = Integer.parseInt(wait.cause.substring(4));
                        if (waker != tid && split.containsKey(waker)) {
                            wokenBy.computeIfAbsent(waker, k -> new ArrayList<>()).add(new long[] {wait.end, tid});
                        }
                    }
                }
            }
            JsonArray rows = new JsonArray();
            List<String> parts = new ArrayList<>();
            boolean herd = false;
            List<Map.Entry<Integer, List<long[]>>> wakers = new ArrayList<>(wokenBy.entrySet());
            Map<Integer, Double> fanOut = new HashMap<>();
            for (Map.Entry<Integer, List<long[]>> entry : wakers) {
                List<long[]> wakes = entry.getValue();
                wakes.sort((a, b) -> Long.compare(a[0], b[0]));
                int events = 0;
                for (int i = 0; i < wakes.size();) {
                    int j = i;
                    while (j < wakes.size() && wakes.get(j)[0] - wakes.get(i)[0] <= 50_000L) {
                        j++;
                    }
                    events++;
                    i = j;
                }
                fanOut.put(entry.getKey(), wakes.size() / (double) Math.max(1, events));
            }
            wakers.sort((a, b) -> Double.compare(fanOut.get(b.getKey()), fanOut.get(a.getKey())));
            for (Map.Entry<Integer, List<long[]>> entry : wakers.subList(0, Math.min(6, wakers.size()))) {
                List<long[]> wakes = entry.getValue();
                if (wakes.size() < 100 || wakes.stream().map(w -> w[1]).distinct().count() < 3) {
                    continue;
                }
                wakes.sort((a, b) -> Long.compare(a[0], b[0]));
                int events = 0;
                int wideEvents = 0;
                long woken = 0;
                long straightBack = 0;
                for (int i = 0; i < wakes.size();) {
                    int j = i;
                    while (j < wakes.size() && wakes.get(j)[0] - wakes.get(i)[0] <= 50_000L) {
                        j++;
                    }
                    int size = j - i;
                    events++;
                    if (size >= 3) {
                        wideEvents++;
                    }
                    for (int k = i; k < j; k++) {
                        int tid = (int) wakes.get(k)[1];
                        long wakeAt = wakes.get(k)[0];
                        List<WaitInterval> waits = byThread.get(tid);
                        int low = 0;
                        int high = waits.size();
                        while (low < high) {
                            int mid = (low + high) >>> 1;
                            if (waits.get(mid).start < wakeAt) {
                                low = mid + 1;
                            } else {
                                high = mid;
                            }
                        }
                        woken++;
                        if (low < waits.size()) {
                            long next = waits.get(low).start;
                            if (runningBetween(status.getOrDefault(tid, List.of()), wakeAt, next) < 50_000L
                                    && next - wakeAt < 50_000_000L) {
                                straightBack++;
                            }
                        }
                    }
                    i = j;
                }
                double perEvent = woken / (double) Math.max(1, events);
                double backPercent = straightBack * 100.0 / Math.max(1, woken);
                boolean isHerd = perEvent >= 3 && backPercent >= 50;
                herd |= isHerd;
                JsonObject row = new JsonObject();
                row.addProperty("waker_tid", entry.getKey());
                row.addProperty("waker", name(entry.getKey()));
                row.addProperty("wake_events", events);
                row.addProperty("threads_woken_per_event", perEvent);
                row.addProperty("events_waking_3_or_more_percent", wideEvents * 100.0 / Math.max(1, events));
                row.addProperty("woken_that_went_straight_back_to_waiting_percent", backPercent);
                row.addProperty("label", isHerd ? "thundering herd: each wake-up releases many threads and most go straight "
                        + "back to waiting" : perEvent >= 3 ? "wakes several at once, but most of them find work"
                                : "wakes one thread at a time");
                rows.add(row);
                parts.add(String.format(Locale.ROOT, "%s (TID %d): %d wake-ups releasing %.1f threads each on average, %.0f%% "
                        + "of the woken going straight back to waiting (ran under 0.05 ms): %s", name(entry.getKey()),
                        entry.getKey(), events, perEvent, backPercent, UnifiedExplainer.str(row, "label")));
            }
            if (rows.size() == 0) {
                return;
            }
            JsonObject data = new JsonObject();
            data.add("wakers", rows);
            data.addProperty("thundering_herd", herd);
            JsonArray caveats = new JsonArray();
            caveats.add("Wake-ups of other threads by one thread within 50 us count as one release (a broadcast). A woken "
                    + "thread that runs under 0.05 ms before waiting again most likely found nothing to do.");
            fFindings.add(finding("process.wake_fan_out", fAbout, "blocked", "How many threads each wake-up releases in "
                    + name(fPid) + ": " + String.join("; ", parts) + ".", fWin, "tracecompass.execution_graph+state_system",
                    data, "medium", caveats));
        }

        // ---------------------------------------------------------------
        // Bursts: threads alternating between busy and idle over time
        // ---------------------------------------------------------------

        /**
         * Each busy thread's running share per 50 ms of the window: bursty when it alternates between
         * busy stretches (at least half its usual peak) and idle ones (a tenth of it or less), ten times
         * or more. A producer working in bursts makes its queue fill and drain; a steady pipeline is not
         * bursty.
         */
        private void addBursts(Map<Integer, Map<String, Long>> split, Map<Integer, List<long[]>> status) {
            long binNs = 50_000_000L;
            int bins = (int) Math.min(4000, Math.max(1, (fWindow.end - fWindow.start) / binNs));
            if (bins < 20) {
                return;
            }
            long windowNs = fWindow.end - fWindow.start;
            JsonArray rows = new JsonArray();
            List<String> bursty = new ArrayList<>();
            List<String> steady = new ArrayList<>();
            for (int tid : split.keySet()) {
                if (running(split.get(tid)) < windowNs / 50) {
                    continue;
                }
                double[] share = new double[bins];
                for (long[] interval : status.getOrDefault(tid, List.of())) {
                    if (interval[2] != 1) {
                        continue;
                    }
                    for (long s = Math.max(interval[0], fWindow.start); s < Math.min(interval[1], fWindow.end);) {
                        int bin = (int) Math.min(bins - 1, (s - fWindow.start) / binNs);
                        long binEnd = bin == bins - 1 ? fWindow.end : fWindow.start + (bin + 1) * binNs;
                        long e = Math.min(Math.min(interval[1], binEnd), fWindow.end);
                        share[bin] += (e - s) / (double) binNs;
                        s = Math.max(e, s + 1);
                    }
                }
                double[] sorted = share.clone();
                java.util.Arrays.sort(sorted);
                double peak = sorted[Math.min(bins - 1, (int) (bins * 0.95))];
                if (peak <= 0) {
                    continue;
                }
                int high = 0;
                int low = 0;
                int bursts = 0;
                boolean wasLow = false;
                for (double value : share) {
                    if (value >= peak / 2) {
                        high++;
                        if (wasLow) {
                            bursts++;
                        }
                        wasLow = false;
                    } else if (value <= peak / 10) {
                        low++;
                        wasLow = true;
                    }
                }
                boolean isBursty = high * 10 >= bins && low * 10 >= bins * 3 && bursts >= 10;
                JsonObject row = new JsonObject();
                row.addProperty("tid", tid);
                row.addProperty("name", name(tid));
                row.addProperty("busy_stretches_percent", high * 100.0 / bins);
                row.addProperty("idle_stretches_percent", low * 100.0 / bins);
                row.addProperty("bursts", bursts);
                row.addProperty("label", isBursty ? "bursty: alternates between busy and idle" : "steady");
                rows.add(row);
                if (isBursty) {
                    bursty.add(String.format(Locale.ROOT, "%s (%d bursts; busy in %.0f%% of 50 ms stretches, idle in %.0f%%)",
                            name(tid), bursts, high * 100.0 / bins, low * 100.0 / bins));
                } else {
                    steady.add(name(tid));
                }
            }
            if (rows.size() == 0) {
                return;
            }
            JsonObject data = new JsonObject();
            data.add("threads", rows);
            data.addProperty("any_bursty", !bursty.isEmpty());
            JsonArray caveats = new JsonArray();
            caveats.add("Running share per 50 ms of the window, for threads running at least 2% of it. Bursty: at least 10% "
                    + "of the stretches busy (half the usual peak or more), at least 30% idle (a tenth or less), and ten or more "
                    + "returns from idle to busy. A queue between bursty threads fills during a burst and drains between them.");
            fFindings.add(finding("process.activity_over_time", fAbout, "running", "Busy and idle over time in "
                    + name(fPid) + ": " + (bursty.isEmpty() ? "no thread works in bursts; steady: " + String.join(", ", steady)
                            : "in bursts: " + String.join("; ", bursty) + (steady.isEmpty() ? "" : "; steady: " + String.join(", ", steady)))
                    + ".", fWin, "tracecompass.state_system", data, "high", caveats));
        }

        // ---------------------------------------------------------------
        // Priority inversion along the bottleneck chain
        // ---------------------------------------------------------------

        /** A comparable rank: real-time above normal, a higher real-time priority or lower nice higher. */
        private static int rank(int prio) {
            if (prio == Integer.MIN_VALUE || prio == -1) {
                return Integer.MIN_VALUE;
            }
            return prio < 0 ? 1000 + (-prio - 1) : 500 - (prio - 20);
        }

        /**
         * Along the main thread's wait chain: a thread that waits on a lock (futex) released by a
         * lower-priority thread, which in turn waits for a CPU held by a thread whose priority lies
         * between them, is a priority inversion.
         */
        /** The intervals the execution graph marks PREEMPTED for one thread (ready, but another thread has its CPU). */
        private List<long[]> preemptedIntervals(int tid) {
            List<long[]> result = new ArrayList<>();
            ITmfGraph graph = executionGraph(fTrace);
            OsWorker worker = graph == null ? null : findOsWorker(graph, tid);
            if (worker == null) {
                return result;
            }
            Iterator<ITmfVertex> vertices = graph.getNodesOf(worker);
            while (vertices.hasNext()) {
                ITmfVertex vertex = vertices.next();
                ITmfEdge edge = graph.getEdgeFrom(vertex, ITmfGraph.EdgeDirection.OUTGOING_HORIZONTAL_EDGE);
                if (edge != null && "PREEMPTED".equals(String.valueOf(edge.getEdgeContextState().getContextEnum()))) {
                    long s = Math.max(edge.getVertexFrom().getTimestamp(), fWindow.start);
                    long e = Math.min(edge.getVertexTo().getTimestamp(), fWindow.end);
                    if (e > s) {
                        result.add(new long[] {s, e});
                    }
                }
            }
            result.sort((a, b) -> Long.compare(a[0], b[0]));
            return result;
        }

        /**
         * Along the main thread's wait chain: a thread that waits on a lock (futex) released by a
         * lower-priority thread, which is preempted during those waits by a thread whose priority lies
         * between them, is a priority inversion. Preemption comes from the execution graph (PREEMPTED),
         * the holder of the CPU from the CPU's current thread.
         */
        private void addPriorityInversion(Map<Integer, List<long[]>> status, Map<Integer, List<WaitInterval>> intervals) {
            JsonObject bottleneck = findingById("process.bottleneck");
            JsonObject data = bottleneck == null ? null : UnifiedExplainer.obj(UnifiedExplainer.obj(bottleneck, "evidence"), "data");
            JsonArray chain = UnifiedExplainer.arr(data, "chain");
            ITmfStateSystem ss = fKernel.getStateSystem();
            if (chain.size() < 2 || ss == null) {
                return;
            }
            long middle = fWindow.start + (fWindow.end - fWindow.start) / 2;
            for (int i = 0; i + 1 < chain.size(); i++) {
                JsonObject a = chain.get(i).getAsJsonObject();
                JsonObject b = chain.get(i + 1).getAsJsonObject();
                int aTid = a.get("tid").getAsInt();
                int bTid = b.get("tid").getAsInt();
                if (!"futex".equals(UnifiedExplainer.str(a, "system_call"))
                        || UnifiedExplainer.num(a, "woken_by_tid", -1L) != bTid) {
                    continue;
                }
                int aRank = rank(priorityOf(aTid, middle));
                int bRank = rank(priorityOf(bTid, middle));
                if (aRank == Integer.MIN_VALUE || bRank == Integer.MIN_VALUE || aRank <= bRank) {
                    continue;
                }
                // A's waits that B ended, and B's preempted time inside them.
                List<long[]> windows = new ArrayList<>();
                for (WaitInterval wait : intervals.getOrDefault(aTid, List.of())) {
                    if (wait.cause.equals("tid:" + bTid)) {
                        windows.add(new long[] {wait.start, wait.end});
                    }
                }
                windows.sort((x, y) -> Long.compare(x[0], y[0]));
                long within = 0;
                for (long[] window : windows) {
                    within += window[1] - window[0];
                }
                List<long[]> preempted = new ArrayList<>();
                long preemptedNs = 0;
                for (long[] interval : preemptedIntervals(bTid)) {
                    for (long[] clipped : clip(windows, interval[0], interval[1])) {
                        preempted.add(clipped);
                        preemptedNs += clipped[1] - clipped[0];
                    }
                }
                // Who held B's CPU then: B's CPU is the one it runs on most.
                int rqQuark = ss.optQuarkAbsolute("Threads", String.valueOf(bTid), "Current_cpu_rq");
                Map<Integer, Long> cpuUse = new HashMap<>();
                if (rqQuark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                    History rq = History.load(ss, List.of(rqQuark), fWindow.start, fWindow.end);
                    for (long[] interval : status.getOrDefault(bTid, List.of())) {
                        if (interval[2] == 1 && rq.valueAt(rqQuark, interval[0]) instanceof Integer) {
                            cpuUse.merge((Integer) rq.valueAt(rqQuark, interval[0]), interval[1] - interval[0], Long::sum);
                        }
                    }
                }
                Map<Integer, Long> held = new HashMap<>();
                Integer cpu = cpuUse.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
                if (cpu != null) {
                    int cpuQuark = ss.optQuarkAbsolute("CPUs", String.valueOf(cpu), "Current_thread");
                    if (cpuQuark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                        History holders = History.load(ss, List.of(cpuQuark), fWindow.start, fWindow.end);
                        for (long[] interval : preempted) {
                            for (ITmfStateInterval holding : holders.intervals(cpuQuark, interval[0], interval[1])) {
                                long s = Math.max(holding.getStartTime(), interval[0]);
                                long e = Math.min(holding.getEndTime() + 1, interval[1]);
                                if (e > s && holding.getValue() instanceof Integer && (Integer) holding.getValue() != bTid) {
                                    held.merge((Integer) holding.getValue(), e - s, Long::sum);
                                }
                            }
                        }
                    }
                }
                long heldTotal = held.values().stream().mapToLong(Long::longValue).sum();
                String holder = null;
                double heldPercent = 0;
                JsonArray holders = new JsonArray();
                for (Map.Entry<Integer, Long> entry : held.entrySet().stream()
                        .sorted((x, y) -> Long.compare(y.getValue(), x.getValue())).limit(4).collect(Collectors.toList())) {
                    int hTid = entry.getKey();
                    int hRank = rank(priorityOf(hTid, middle));
                    double percent = entry.getValue() * 100.0 / Math.max(1, heldTotal);
                    JsonObject row = new JsonObject();
                    row.addProperty("tid", hTid);
                    row.addProperty("name", name(hTid));
                    row.addProperty("priority", priorityText(priorityOf(hTid, middle)));
                    row.addProperty("percent", percent);
                    holders.add(row);
                    if (hTid != 0 && hRank > bRank && hRank < aRank && percent > heldPercent) {
                        heldPercent = percent;
                        holder = "TID " + hTid + " (" + name(hTid) + ", " + priorityText(priorityOf(hTid, middle)) + ")";
                    }
                }
                double preemptedPercent = preemptedNs * 100.0 / Math.max(1, within);
                JsonObject result = new JsonObject();
                result.addProperty("high_tid", aTid);
                result.addProperty("high", name(aTid) + " (" + priorityText(priorityOf(aTid, middle)) + ")");
                result.addProperty("low_tid", bTid);
                result.addProperty("low", name(bTid) + " (" + priorityText(priorityOf(bTid, middle)) + ")");
                result.addProperty("waits", windows.size());
                result.addProperty("low_preempted_percent_of_those_waits", preemptedPercent);
                result.add("cpu_held_by_while_preempted", holders);
                boolean inversion = holder != null && preemptedPercent >= 20 && heldPercent >= 30;
                if (holder != null) {
                    result.addProperty("medium", holder);
                    result.addProperty("medium_percent_of_preempted_time", heldPercent);
                }
                result.addProperty("priority_inversion", inversion);
                JsonArray caveats = new JsonArray();
                caveats.add("Priorities as the kernel recorded them in sched_switch: real-time (SCHED_FIFO/RR) above normal; a "
                        + "futex wait ended by the other thread is most likely a lock it held. Preempted: ready to run while "
                        + "another thread had its CPU (execution graph).");
                fFindings.add(finding("process.priority_inversion", fAbout, "blocked", inversion
                        ? String.format(Locale.ROOT, "Priority inversion: %s waits on a lock (futex) released by %s (%d waits); "
                                + "during those waits %s is preempted %.0f%% of the time, its CPU held %.0f%% of that time by %s, "
                                + "whose priority lies between them: the high-priority thread is held up by a medium-priority one.",
                                UnifiedExplainer.str(result, "high"), UnifiedExplainer.str(result, "low"), windows.size(),
                                name(bTid), preemptedPercent, heldPercent, holder)
                        : String.format(Locale.ROOT, "%s waits on a lock (futex) released by the lower-priority %s, which is "
                                + "preempted %.0f%% of those waits%s: a high-priority thread waiting on a low-priority one, but no "
                                + "medium-priority thread keeps the low one off the CPU much, so not a priority inversion.",
                                UnifiedExplainer.str(result, "high"), UnifiedExplainer.str(result, "low"), preemptedPercent,
                                holder == null ? "" : String.format(Locale.ROOT, " (%.0f%% of that by %s)", heldPercent, holder)),
                        fWin, "tracecompass.execution_graph+state_system", result, "medium", caveats));
                return;
            }
        }

        /** The cycle trend over the whole trace (timing.cycle_trend) of the process's two busiest threads. */
        private void addThreadCycleTrends(Map<Integer, Map<String, Long>> split) {
            ITmfStateSystem ss = fKernel.getStateSystem();
            if (ss == null) {
                return;
            }
            List<Integer> busiest = new ArrayList<>(split.keySet());
            busiest.sort((a, b) -> Long.compare(running(split.get(b)), running(split.get(a))));
            int added = 0;
            for (int tid : busiest) {
                if (added == 2 || running(split.get(tid)) == 0) {
                    break;
                }
                UnifiedExplainer explainer = new UnifiedExplainer(fTrace, tid, false, fKernel, ss);
                JsonArray trend = explainer.cycleTrendOnly();
                for (JsonElement element : trend) {
                    fFindings.add(element);
                    added++;
                }
            }
        }

        /** First and last alive moment of each thread in the window. */
        private final Map<Integer, Long> fFirstAlive = new HashMap<>();
        private final Map<Integer, Long> fLastAlive = new HashMap<>();
        /** Last running moment of each thread in the window (an exiting thread wakes its joiner then). */
        private final Map<Integer, Long> fLastRun = new HashMap<>();

        /** The rate and latency labels of process.activity, as sentences for its claim. */
        private static String activitySizes(JsonObject activity) {
            List<String> parts = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(activity, "rates")) {
                JsonObject rate = element.getAsJsonObject();
                boolean costly = UnifiedExplainer.str(rate, "scale") != null && UnifiedExplainer.str(rate, "scale").startsWith("costly");
                if ((parts.size() < 6 || costly) && UnifiedExplainer.num(rate, "calls", 0L) > 0) {
                    parts.add(String.format(Locale.ROOT, "%s %.1f per second (%s)", UnifiedExplainer.str(rate, "what"),
                            UnifiedExplainer.dbl(rate, "per_second", 0), UnifiedExplainer.str(rate, "level")));
                }
            }
            StringBuilder text = new StringBuilder();
            if (!parts.isEmpty()) {
                text.append(" Rates (level for that kind of call): ").append(String.join("; ", parts)).append(".");
            }
            List<String> tails = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(activity, "syscall_latency")) {
                JsonObject call = element.getAsJsonObject();
                if (tails.size() < 4) {
                    tails.add(String.format(Locale.ROOT, "%s median %.3f ms, p99 %.3f ms, max %.3f ms (%s)",
                            UnifiedExplainer.str(call, "syscall"), UnifiedExplainer.dbl(call, "median_ms", 0),
                            UnifiedExplainer.dbl(call, "p99_ms", 0), UnifiedExplainer.dbl(call, "max_ms", 0),
                            UnifiedExplainer.str(call, "tail")));
                }
            }
            if (!tails.isEmpty()) {
                text.append(" Per-call durations of its request and I/O calls: ").append(String.join("; ", tails)).append(".");
            }
            List<String> results = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(activity, "syscall_results")) {
                JsonObject row = element.getAsJsonObject();
                String label = UnifiedExplainer.str(row, "label");
                if (label != null && !label.startsWith("normal")) {
                    results.add(UnifiedExplainer.str(row, "syscall") + " " + label);
                }
            }
            if (!results.isEmpty()) {
                text.append(" Results of its calls: ").append(String.join("; ", results)).append(".");
            }
            List<String> locks = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(activity, "futex_addresses")) {
                JsonObject row = element.getAsJsonObject();
                if (locks.size() < 3) {
                    locks.add(String.format(Locale.ROOT, "%s: %d threads waited %d times (%.0f per second, %.1f ms in all), %s",
                            UnifiedExplainer.str(row, "address"), UnifiedExplainer.num(row, "waiting_thread_count", 0L),
                            UnifiedExplainer.num(row, "waits", 0L), UnifiedExplainer.dbl(row, "waits_per_second", 0),
                            UnifiedExplainer.dbl(row, "waited_ms", 0), UnifiedExplainer.str(row, "kind")));
                }
            }
            if (!locks.isEmpty()) {
                text.append(" Futex addresses waited on most: ").append(String.join("; ", locks)).append(".");
            }
            JsonObject migrations = UnifiedExplainer.obj(activity, "migrations");
            if (migrations != null) {
                List<String> movers = new ArrayList<>();
                for (JsonElement element : UnifiedExplainer.arr(migrations, "threads")) {
                    JsonObject row = element.getAsJsonObject();
                    if (movers.size() < 4) {
                        movers.add(String.format(Locale.ROOT, "%s %.1f per second (%s)", UnifiedExplainer.str(row, "name"),
                                UnifiedExplainer.dbl(row, "per_second", 0), UnifiedExplainer.str(row, "level")));
                    }
                }
                text.append(String.format(Locale.ROOT, " Moves between CPUs (migrations): %.1f per second in all; %s.",
                        UnifiedExplainer.dbl(migrations, "per_second", 0), String.join(", ", movers)));
            }
            for (JsonElement element : UnifiedExplainer.arr(activity, "timer_lateness")) {
                JsonObject row = element.getAsJsonObject();
                text.append(String.format(Locale.ROOT, " Timers of %s fired a median %.3f ms late against the time asked for "
                        + "(p99 %.3f ms, %.0f%% at least 1 ms late; timer slack %.3f ms; %s).", UnifiedExplainer.str(row, "name"),
                        UnifiedExplainer.dbl(row, "median_late_ms", 0), UnifiedExplainer.dbl(row, "p99_late_ms", 0),
                        UnifiedExplainer.dbl(row, "percent_late_1ms_or_more", 0), UnifiedExplainer.dbl(row, "mean_timer_slack_ms", 0),
                        UnifiedExplainer.str(row, "level")));
            }
            JsonObject relations = UnifiedExplainer.obj(activity, "file_relations");
            if (relations != null) {
                long outside = UnifiedExplainer.num(relations, "files_outside_own_folders", 0L);
                text.append(outside == 0 ? " Every file it used is its own (written by it, next to what it writes or runs from, "
                        + "or relative to its working directory), apart from program start-up files."
                        : String.format(Locale.ROOT, " It read %d file(s) outside the folders it writes to or runs from, in %s.",
                                outside, UnifiedExplainer.obj(relations, "outside_folders")));
            }
            return text.toString();
        }

        private static JsonArray activityCaveats() {
            JsonArray caveats = new JsonArray();
            caveats.add("Rate levels: for a costly kind of call (opening, creating or deleting files, mapping memory, "
                    + "starting threads or programs) low is under 20 per second and high from 100; for any other kind, low is "
                    + "under 200 per second and high from 2,000. Low and moderate rates are normal for a busy program.");
            caveats.add("Per-call durations are only for request and I/O calls (network, file, polling), not sleeps or lock "
                    + "waits, whose long calls are idle time.");
            return caveats;
        }

        // ---------------------------------------------------------------
        // Thread activity labels (idle, mostly waiting, working)
        // ---------------------------------------------------------------

        /**
         * Adds to each process.threads row how many times the thread woke up and a label: idle (never woke
         * up to do anything in the window), mostly waiting (short bits of work, such as a monitor loop or a
         * main thread waiting for its workers), or working.
         */
        private void labelThreadActivity(Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive,
                Map<Integer, List<WaitInterval>> intervals, JsonObject activity) {
            JsonObject callsByThread = UnifiedExplainer.obj(activity, "syscalls_by_thread");
            Map<Integer, Integer> woke = new HashMap<>();
            for (List<WaitInterval> waits : intervals.values()) {
                for (WaitInterval wait : waits) {
                    if (wait.cause.startsWith("tid:")) {
                        woke.merge(Integer.parseInt(wait.cause.substring(4)), 1, Integer::sum);
                    }
                }
            }
            List<String> spinning = new ArrayList<>();
            JsonObject threadsFinding = findingById("process.threads");
            if (threadsFinding == null) {
                return;
            }
            JsonObject data = UnifiedExplainer.obj(UnifiedExplainer.obj(threadsFinding, "evidence"), "data");
            double seconds = Math.max(1e-3, (fWindow.end - fWindow.start) / 1e9);
            List<String> idle = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(data, "threads")) {
                JsonObject row = element.getAsJsonObject();
                int tid = row.get("tid").getAsInt();
                int wakeUps = intervals.getOrDefault(tid, List.of()).size();
                double running = UnifiedExplainer.dbl(row, "running_ms", 0);
                double runningPercent = UnifiedExplainer.dbl(row, "running_percent", 0);
                row.addProperty("wake_ups", wakeUps);
                row.addProperty("wake_ups_per_second", wakeUps / seconds);
                String label;
                if (wakeUps <= 2 && running < 2) {
                    label = "idle: never woke up to do anything in this window";
                    idle.add(String.format(Locale.ROOT, "TID %d (%s)", tid, name(tid)));
                } else if (runningPercent < 2) {
                    label = String.format(Locale.ROOT, "mostly waiting: woke %d times (%.1f per second) for short bits of "
                            + "work (%.1f%% running), like a monitor loop or a thread waiting for others", wakeUps,
                            wakeUps / seconds, runningPercent);
                } else {
                    label = String.format(Locale.ROOT, "working: running %.1f%% of the time", runningPercent);
                }
                // Always on the CPU in its own code, almost no system calls: a spin-wait or pure computation.
                Map<String, Long> states = split.get(tid);
                long user = states == null ? 0 : states.getOrDefault("RUNNING_USER_MODE", 0L);
                long calls = 0;
                JsonObject threadCalls = UnifiedExplainer.obj(callsByThread, String.valueOf(tid));
                if (threadCalls != null) {
                    for (Map.Entry<String, JsonElement> call : threadCalls.entrySet()) {
                        calls += call.getValue().getAsLong();
                    }
                }
                if (runningPercent >= 80 && user >= 0.95 * running * 1e6 && calls / seconds < 10) {
                    int wokeOthers = woke.getOrDefault(tid, 0);
                    label = String.format(Locale.ROOT, "spinning or pure computation: on the CPU %.1f%% of the time, almost all "
                            + "in its own code, with %d system calls (%.1f per second) and %d wake-ups of other threads; a thread "
                            + "that waits for a flag in a loop (a busy-wait) looks like this, and so does one that computes "
                            + "nonstop; whether it gets work done is not in the trace", runningPercent, calls, calls / seconds,
                            wokeOthers);
                    spinning.add(String.format(Locale.ROOT, "TID %d (%s)", tid, name(tid)));
                }
                row.addProperty("activity", label);
            }
            threadsFinding.addProperty("claim", UnifiedExplainer.str(threadsFinding, "claim") + (idle.isEmpty()
                    ? " No thread was idle: every thread woke up to work at some point."
                    : " Idle (never woke up to do anything here): " + String.join(", ", idle) + ".")
                    + (spinning.isEmpty() ? "" : " On the CPU nearly all the time in its own code with almost no system calls "
                            + "(spinning or pure computation): " + String.join(", ", spinning) + "."));
        }

        private JsonObject findingById(String id) {
            for (JsonElement element : fFindings) {
                if (id.equals(UnifiedExplainer.str(element.getAsJsonObject(), "id"))) {
                    return element.getAsJsonObject();
                }
            }
            return null;
        }

        // ---------------------------------------------------------------
        // Peer comparison: how each group of like threads (worker-0..3) compares
        // ---------------------------------------------------------------

        /** One measure of one thread against the median of its peers. */
        private static final class Difference {
            final int tid;
            final String measure;
            final double value;
            final double peers;
            final String size;

            Difference(int tid, String measure, double value, double peers, String size) {
                this.tid = tid;
                this.measure = measure;
                this.value = value;
                this.peers = peers;
                this.size = size;
            }
        }

        private static double medianOf(double[] values) {
            double[] sorted = values.clone();
            java.util.Arrays.sort(sorted);
            int n = sorted.length;
            return n == 0 ? 0 : n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
        }

        /**
         * For each group of three or more threads with the same name apart from a number (worker-0..3,
         * calc-0..7), how each member compares with the median of the others: CPU time, blocked time,
         * wait for a CPU, wake-ups and system calls. A difference is large at twice (or half) the
         * others and at least 20 ms or 1% of the window apart (100 wake-ups or calls for counts), or
         * when a thread makes a system call the others make at most a tenth as often; minor at 1.3
         * times. Also how many of them run at the same time: one at a time means they take turns (on a
         * lock, or on too few CPUs, which the states of the waiting ones tell apart).
         */
        private void addPeerComparison(Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive,
                Map<Integer, List<long[]>> status, Map<Integer, List<WaitInterval>> intervals, JsonObject activity) {
            Map<String, List<Integer>> groups = new LinkedHashMap<>();
            for (int tid : split.keySet()) {
                String threadName = name(tid);
                String stem = nameStem(threadName);
                if (tid != fPid && !stem.isEmpty() && !stem.equals(threadName)) {
                    groups.computeIfAbsent(stem, k -> new ArrayList<>()).add(tid);
                }
            }
            JsonObject byThread = UnifiedExplainer.obj(activity, "syscalls_by_thread");
            double windowNs = Math.max(1, fWindow.end - fWindow.start);
            for (Map.Entry<String, List<Integer>> group : groups.entrySet()) {
                List<Integer> members = group.getValue();
                if (members.size() < 3 || members.size() > 256) {
                    continue;
                }
                String stem = group.getKey();
                int n = members.size();
                double[][] measures = new double[4][n];
                String[] measureNames = {"CPU time (ms)", "blocked time (ms)", "wait for a CPU (ms)", "wake-ups"};
                for (int i = 0; i < n; i++) {
                    Map<String, Long> states = split.get(members.get(i));
                    measures[0][i] = (states.getOrDefault("RUNNING_USER_MODE", 0L) + states.getOrDefault("RUNNING_SYSTEM_CALL", 0L)) / 1e6;
                    measures[1][i] = states.getOrDefault("BLOCKED", 0L) / 1e6;
                    measures[2][i] = states.getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L) / 1e6;
                    measures[3][i] = intervals.getOrDefault(members.get(i), List.of()).size();
                }
                List<Difference> differences = new ArrayList<>();
                for (int m = 0; m < measures.length; m++) {
                    boolean count = m == 3;
                    double minGap = count ? 100 : Math.max(20, windowNs / 1e6 * 0.01);
                    for (int i = 0; i < n; i++) {
                        double[] others = new double[n - 1];
                        for (int j = 0, k = 0; j < n; j++) {
                            if (j != i) {
                                others[k++] = measures[m][j];
                            }
                        }
                        double peers = medianOf(others);
                        double value = measures[m][i];
                        double gap = Math.abs(value - peers);
                        double ratio = Math.max(value, peers) / Math.max(1e-9, Math.min(value, peers));
                        if (gap >= minGap && ratio >= 2) {
                            differences.add(new Difference(members.get(i), measureNames[m], value, peers, "large"));
                        } else if (gap >= minGap && ratio >= 1.3) {
                            differences.add(new Difference(members.get(i), measureNames[m], value, peers, "minor"));
                        }
                    }
                }
                // System calls one member makes and the others hardly do.
                if (byThread != null) {
                    Map<String, double[]> callCounts = new HashMap<>();
                    for (int i = 0; i < n; i++) {
                        JsonObject calls = UnifiedExplainer.obj(byThread, String.valueOf(members.get(i)));
                        if (calls == null) {
                            continue;
                        }
                        for (Map.Entry<String, JsonElement> call : calls.entrySet()) {
                            callCounts.computeIfAbsent(call.getKey(), k -> new double[n])[i] = call.getValue().getAsDouble();
                        }
                    }
                    for (Map.Entry<String, double[]> call : callCounts.entrySet()) {
                        double[] counts = call.getValue();
                        for (int i = 0; i < n; i++) {
                            double othersMax = 0;
                            double[] others = new double[n - 1];
                            for (int j = 0, k = 0; j < n; j++) {
                                if (j != i) {
                                    othersMax = Math.max(othersMax, counts[j]);
                                    others[k++] = counts[j];
                                }
                            }
                            if (counts[i] >= 100 && othersMax * 10 <= counts[i]) {
                                differences.add(new Difference(members.get(i), call.getKey() + " calls", counts[i],
                                        medianOf(others), "large"));
                            }
                        }
                    }
                }

                // How many members run at the same time, and what the others do meanwhile.
                List<long[]> edges = new ArrayList<>();
                long othersBlocked = 0;
                long othersQueued = 0;
                for (int tid : members) {
                    for (long[] interval : status.getOrDefault(tid, List.of())) {
                        if (interval[2] == 1) {
                            edges.add(new long[] {interval[0], 1});
                            edges.add(new long[] {interval[1], -1});
                        }
                    }
                }
                edges.sort((a, b) -> a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
                long busy = 0;
                double weighted = 0;
                int running = 0;
                int peak = 0;
                long last = -1;
                List<long[]> busyUnion = new ArrayList<>();
                for (long[] edge : edges) {
                    if (running > 0 && last >= 0) {
                        busy += edge[0] - last;
                        weighted += (double) running * (edge[0] - last);
                        if (!busyUnion.isEmpty() && busyUnion.get(busyUnion.size() - 1)[1] == last) {
                            busyUnion.get(busyUnion.size() - 1)[1] = edge[0];
                        } else {
                            busyUnion.add(new long[] {last, edge[0]});
                        }
                    }
                    running += (int) edge[1];
                    peak = Math.max(peak, running);
                    last = edge[0];
                }
                double concurrency = busy == 0 ? 0 : weighted / busy;
                double groupRunning = 0;
                for (double ms : measures[0]) {
                    groupRunning += ms;
                }
                // What the other members do while one of them runs: queued for a CPU, or blocked; and
                // who ends those blocked waits: a peer (they hand a lock to each other) or another thread
                // (they wait for work it hands out).
                for (int tid : members) {
                    for (long[] interval : status.getOrDefault(tid, List.of())) {
                        if (interval[2] == 2) {
                            othersQueued += overlap(busyUnion, interval[0], interval[1]);
                        } else if (interval[2] == 0) {
                            othersBlocked += overlap(busyUnion, interval[0], interval[1]);
                        }
                    }
                }
                Set<Integer> memberSet = new java.util.HashSet<>(members);
                long endedByPeer = 0;
                int peerWakes = 0;
                int allWakes = 0;
                Map<String, Long> endedByOther = new HashMap<>();
                for (int tid : members) {
                    for (WaitInterval wait : intervals.getOrDefault(tid, List.of())) {
                        allWakes++;
                        boolean byPeer = wait.cause.startsWith("tid:")
                                && memberSet.contains(Integer.parseInt(wait.cause.substring(4)));
                        if (byPeer) {
                            peerWakes++;
                        }
                        long during = overlap(busyUnion, wait.start, wait.end);
                        if (during <= 0) {
                            continue;
                        }
                        if (byPeer) {
                            endedByPeer += during;
                        } else {
                            endedByOther.merge(wait.cause, during, Long::sum);
                        }
                    }
                }
                long otherTotal = endedByOther.values().stream().mapToLong(Long::longValue).sum();
                String otherWaker = endedByOther.entrySet().stream().max(Map.Entry.comparingByValue())
                        .map(entry -> describeCause(entry.getKey())).orElse("another thread");
                String parallel;
                if (groupRunning < windowNs / 1e6 * 0.02 || peak == 0) {
                    parallel = "too little CPU work to tell whether they run in parallel";
                } else if (concurrency <= 1.15 && n >= 3 && othersQueued >= othersBlocked) {
                    parallel = String.format(Locale.ROOT,
                            "limited by CPUs: when any of them runs, on average %.2f of the %d run at once (at most %d), and "
                                    + "the others are mostly ready but waiting for a CPU meanwhile: they share too few CPUs "
                                    + "(CPU contention), not a lock", concurrency, n, peak);
                } else if (concurrency <= 1.15 && n >= 3 && (endedByPeer >= otherTotal || peerWakes * 4 >= allWakes)) {
                    parallel = String.format(Locale.ROOT,
                            "one at a time: when any of them runs, on average %.2f of the %d run at once (at most %d), while "
                                    + "the others are blocked until one of them wakes them (they hand something to each "
                                    + "other, most likely a lock), not short of CPUs: they take turns instead of running in "
                                    + "parallel", concurrency, n, peak);
                } else if (concurrency <= 1.15 && n >= 3) {
                    parallel = String.format(Locale.ROOT,
                            "one after another as work arrives: when any of them runs, on average %.2f of the %d run at once "
                                    + "(at most %d); the others are waiting for work from %s, not for each other or for a "
                                    + "CPU (normal when work comes one item at a time)", concurrency, n, peak, otherWaker);
                } else {
                    parallel = String.format(Locale.ROOT, "in parallel: when any of them runs, on average %.2f of the %d run at "
                            + "once (at most %d)", concurrency, n, peak);
                }

                JsonArray rows = new JsonArray();
                for (int i = 0; i < n; i++) {
                    JsonObject row = new JsonObject();
                    row.addProperty("tid", members.get(i));
                    row.addProperty("name", name(members.get(i)));
                    row.addProperty("running_ms", measures[0][i]);
                    row.addProperty("blocked_ms", measures[1][i]);
                    row.addProperty("waiting_for_cpu_ms", measures[2][i]);
                    row.addProperty("wake_ups", (long) measures[3][i]);
                    rows.add(row);
                }
                JsonArray diffs = new JsonArray();
                differences.sort((a, b) -> a.size.equals(b.size) ? 0 : "large".equals(a.size) ? -1 : 1);
                List<String> largeText = new ArrayList<>();
                List<String> minorText = new ArrayList<>();
                for (Difference difference : differences) {
                    JsonObject json = new JsonObject();
                    json.addProperty("tid", difference.tid);
                    json.addProperty("name", name(difference.tid));
                    json.addProperty("measure", difference.measure);
                    json.addProperty("value", difference.value);
                    json.addProperty("peers_median", difference.peers);
                    json.addProperty("size", difference.size);
                    diffs.add(json);
                    String text = String.format(Locale.ROOT, "TID %d (%s) %s %.1f against %.1f for the others",
                            difference.tid, name(difference.tid), difference.measure, difference.value, difference.peers);
                    ("large".equals(difference.size) ? largeText : minorText).add(text);
                }
                double[] cpu = measures[0].clone();
                java.util.Arrays.sort(cpu);
                String verdict = !largeText.isEmpty()
                        ? "differs: " + String.join("; ", largeText.subList(0, Math.min(6, largeText.size())))
                        : !minorText.isEmpty() ? "no large difference; minor ones: "
                                + String.join("; ", minorText.subList(0, Math.min(4, minorText.size())))
                                : String.format(Locale.ROOT, "none differs: CPU time %.1f to %.1f ms, and the same system calls",
                                        cpu[0], cpu[n - 1]);
                JsonObject data = new JsonObject();
                data.addProperty("group", stem + "*");
                data.addProperty("members", n);
                data.add("threads", rows);
                data.add("differences", diffs);
                data.addProperty("difference", largeText.isEmpty() ? minorText.isEmpty() ? "none" : "minor" : "large");
                data.addProperty("concurrency_when_any_runs", concurrency);
                data.addProperty("peak_running_at_once", peak);
                data.addProperty("parallelism", parallel);
                data.addProperty("wake_ups_by_a_peer_percent", allWakes == 0 ? 0 : peerWakes * 100.0 / allWakes);
                JsonArray caveats = new JsonArray();
                caveats.add("Large: at least twice (or half) the median of the others and at least 20 ms or 1% of the window "
                        + "apart (100 for counts), or a system call the others make at most a tenth as often. Minor: 1.3 times. "
                        + "A thread finishing a fraction of a millisecond after the others is not a difference.");
                fFindings.add(finding("process.peer_comparison", fAbout, null, String.format(Locale.ROOT,
                        "The %d %s* threads compared with each other: %s. They run %s.", n, stem, verdict, parallel),
                        fWin, "tracecompass.state_system+java.thread_activity", data, "high", caveats));
            }
        }

        // ---------------------------------------------------------------
        // CPU competition: who takes the CPU from the process's threads
        // ---------------------------------------------------------------

        /** "real-time priority 50" or "normal, nice 0", from the kernel's priority as LTTng records it. */
        static String priorityText(int prio) {
            if (prio == Integer.MIN_VALUE || prio == -1) {
                return "priority unknown";
            }
            if (prio < 0) {
                return "real-time priority " + (-prio - 1);
            }
            return "normal, nice " + (prio - 20);
        }

        private int priorityOf(int tid, long time) {
            try {
                return KernelThreadInformationProvider.getThreadPriority(fKernel, tid, time);
            } catch (RuntimeException exception) {
                return Integer.MIN_VALUE;
            }
        }

        /**
         * For each thread of the process that waited for a CPU for at least 20 ms (or 1% of its life):
         * which threads held the CPU it was queued on, with their process and priority, how often it was
         * preempted while running, how much longer its work took (waiting / running), and the stretch of
         * the window where the wait was worst. For the process: the CPUs its threads ran on, and how many
         * of its threads were ready to run at once (twice the CPUs or more is oversubscription).
         */
        private void addCpuCompetition(Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive,
                Map<Integer, List<long[]>> status) {
            ITmfStateSystem ss = fKernel.getStateSystem();
            if (ss == null) {
                return;
            }
            Map<Integer, Integer> pids = pidMap(fKernel, fWindow.start, fWindow.end);
            // The CPUs the process's threads ran on, and the trace's CPUs.
            int cpusQuark = ss.optQuarkAbsolute("CPUs");
            int traceCpus = cpusQuark == ITmfStateSystem.INVALID_ATTRIBUTE ? 0 : ss.getSubAttributes(cpusQuark, false).size();
            List<Integer> rqQuarks = new ArrayList<>();
            Map<Integer, Integer> rqOf = new HashMap<>();
            List<Integer> byRunning = new ArrayList<>(split.keySet());
            byRunning.sort((a, b) -> Long.compare(running(split.get(b)), running(split.get(a))));
            for (int tid : byRunning.subList(0, Math.min(64, byRunning.size()))) {
                int quark = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "Current_cpu_rq");
                if (quark != ITmfStateSystem.INVALID_ATTRIBUTE) {
                    rqQuarks.add(quark);
                    rqOf.put(tid, quark);
                }
            }
            History rq = History.load(ss, rqQuarks, fWindow.start, fWindow.end);
            // The CPUs that carry its work: at least 5% of its running time.
            Map<Integer, Long> runningByCpu = new HashMap<>();
            long runningSampled = 0;
            for (Map.Entry<Integer, Integer> entry : rqOf.entrySet()) {
                for (long[] interval : status.getOrDefault(entry.getKey(), List.of())) {
                    if (interval[2] == 1) {
                        Object cpu = rq.valueAt(entry.getValue(), interval[0]);
                        if (cpu instanceof Integer) {
                            runningByCpu.merge((Integer) cpu, interval[1] - interval[0], Long::sum);
                            runningSampled += interval[1] - interval[0];
                        }
                    }
                }
            }
            Set<Integer> cpusUsed = new TreeSet<>();
            for (Map.Entry<Integer, Long> entry : runningByCpu.entrySet()) {
                if (entry.getValue() * 20 >= runningSampled) {
                    cpusUsed.add(entry.getKey());
                }
            }
            fCpusUsed = cpusUsed;
            // How many of its threads are ready (running or waiting for a CPU) at once.
            List<long[]> edges = new ArrayList<>();
            for (List<long[]> timeline : status.values()) {
                for (long[] interval : timeline) {
                    if (interval[2] == 1 || interval[2] == 2) {
                        edges.add(new long[] {interval[0], 1});
                        edges.add(new long[] {interval[1], -1});
                    }
                }
            }
            edges.sort((a, b) -> a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
            long busy = 0;
            double weighted = 0;
            int ready = 0;
            int peakReady = 0;
            long last = -1;
            for (long[] edge : edges) {
                if (ready > 0 && last >= 0) {
                    busy += edge[0] - last;
                    weighted += (double) ready * (edge[0] - last);
                }
                ready += (int) edge[1];
                peakReady = Math.max(peakReady, ready);
                last = edge[0];
            }
            double meanReady = busy == 0 ? 0 : weighted / busy;
            long totalRunning = 0;
            long totalWaiting = 0;
            for (Map<String, Long> states : split.values()) {
                totalRunning += running(states);
                totalWaiting += states.getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L);
            }
            int cpuCount = Math.max(1, cpusUsed.size());
            String load;
            if (meanReady >= 2.0 * cpuCount && totalWaiting * 4 >= totalRunning && totalRunning > 0) {
                load = String.format(Locale.ROOT, "oversubscribed: on average %.1f of its threads were ready to run at once "
                        + "(at most %d) for the %d CPU(s) they ran on, so they queue for the CPU (waiting %.1f ms for every 100 ms "
                        + "of running)", meanReady, peakReady, cpusUsed.size(), totalWaiting * 100.0 / Math.max(1, totalRunning));
            } else {
                load = String.format(Locale.ROOT, "not oversubscribed: on average %.1f of its threads were ready to run at once "
                        + "(at most %d) for the %d CPU(s) they ran on", meanReady, peakReady, cpusUsed.size());
            }

            // Per delayed thread: who held its CPU.
            JsonArray delayed = new JsonArray();
            List<String> parts = new ArrayList<>();
            Map<Integer, History> cpuHistories = new HashMap<>();
            List<Integer> candidates = new ArrayList<>(split.keySet());
            candidates.sort((a, b) -> Long.compare(split.get(b).getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L),
                    split.get(a).getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L)));
            long byOthers = 0;
            long byOwn = 0;
            for (int tid : candidates.subList(0, Math.min(8, candidates.size()))) {
                long waitingNs = split.get(tid).getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L);
                if (waitingNs < 20_000_000L && waitingNs * 100 < alive.get(tid)) {
                    continue;
                }
                Integer quark = rqOf.get(tid);
                if (quark == null) {
                    int q = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "Current_cpu_rq");
                    if (q == ITmfStateSystem.INVALID_ATTRIBUTE) {
                        continue;
                    }
                    quark = q;
                    rq = merge(rq, History.load(ss, List.of(q), fWindow.start, fWindow.end), q);
                }
                Map<Integer, Long> held = new HashMap<>();
                int preemptions = 0;
                int queuedAfterWakeUp = 0;
                long longest = 0;
                long longestStart = 0;
                Integer longestHolder = null;
                long[] bins = new long[20];
                long[] aliveBins = new long[20];
                List<long[]> timeline = status.getOrDefault(tid, List.of());
                for (int k = 0; k < timeline.size(); k++) {
                    long[] interval = timeline.get(k);
                    addToBins(aliveBins, interval[0], interval[1]);
                    if (interval[2] != 2) {
                        continue;
                    }
                    addToBins(bins, interval[0], interval[1]);
                    if (k > 0 && timeline.get(k - 1)[2] == 1) {
                        preemptions++;
                    } else {
                        queuedAfterWakeUp++;
                    }
                    Object cpu = rq.valueAt(quark, interval[0]);
                    if (!(cpu instanceof Integer)) {
                        continue;
                    }
                    int cpuQuark = ss.optQuarkAbsolute("CPUs", String.valueOf(cpu), "Current_thread");
                    if (cpuQuark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                        continue;
                    }
                    History holders = cpuHistories.computeIfAbsent((Integer) cpu,
                            c -> History.load(ss, List.of(cpuQuark), fWindow.start, fWindow.end));
                    Map<Integer, Long> inThisWait = new HashMap<>();
                    for (ITmfStateInterval holding : holders.intervals(cpuQuark, interval[0], interval[1])) {
                        long s = Math.max(holding.getStartTime(), interval[0]);
                        long e = Math.min(holding.getEndTime() + 1, interval[1]);
                        if (e > s && holding.getValue() instanceof Integer) {
                            held.merge((Integer) holding.getValue(), e - s, Long::sum);
                            inThisWait.merge((Integer) holding.getValue(), e - s, Long::sum);
                        }
                    }
                    if (interval[1] - interval[0] > longest) {
                        longest = interval[1] - interval[0];
                        longestStart = interval[0];
                        longestHolder = inThisWait.entrySet().stream().max(Map.Entry.comparingByValue())
                                .map(Map.Entry::getKey).orElse(null);
                    }
                }
                held.remove(tid);
                long heldTotal = held.values().stream().mapToLong(Long::longValue).sum();
                List<Map.Entry<Integer, Long>> sorted = new ArrayList<>(held.entrySet());
                sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
                JsonArray occupants = new JsonArray();
                List<String> occupantText = new ArrayList<>();
                for (Map.Entry<Integer, Long> entry : sorted.subList(0, Math.min(5, sorted.size()))) {
                    int holder = entry.getKey();
                    Integer holderPid = pids.get(holder);
                    boolean own = holderPid != null && holderPid == fPid;
                    String priority = holder == 0 ? "idle" : priorityText(priorityOf(holder, longestStart > 0 ? longestStart : fWindow.start));
                    JsonObject item = new JsonObject();
                    item.addProperty("tid", holder);
                    item.addProperty("name", name(holder));
                    if (holderPid != null) {
                        item.addProperty("pid", holderPid);
                        item.addProperty("process", name(holderPid));
                    }
                    item.addProperty("same_process", own);
                    item.addProperty("priority", priority);
                    item.addProperty("held_ms", entry.getValue() / 1e6);
                    item.addProperty("percent_of_waiting", entry.getValue() * 100.0 / Math.max(1, heldTotal));
                    occupants.add(item);
                    occupantText.add(String.format(Locale.ROOT, "TID %d (%s, %s, %s) %.1f%%", holder, name(holder),
                            holder == 0 ? "the idle task (interrupt handling or a scheduling gap)"
                                    : own ? "same process" : "process " + (holderPid == null ? "?" : holderPid + " " + name(holderPid)),
                            priority, entry.getValue() * 100.0 / Math.max(1, heldTotal)));
                    if (holder != 0) {
                        if (own) {
                            byOwn += entry.getValue();
                        } else {
                            byOthers += entry.getValue();
                        }
                    }
                }
                long runningNs = running(split.get(tid));
                // The stretch where the wait was worst: the run of twentieths of the window above the
                // larger of 20% and twice its overall waiting share.
                double overall = waitingNs / (double) Math.max(1, alive.get(tid));
                double threshold = Math.max(0.20, 2 * overall);
                int bestFrom = -1;
                int bestTo = -1;
                for (int from = 0; from < 20; from++) {
                    int to = from;
                    while (to < 20 && aliveBins[to] > 0 && bins[to] >= threshold * aliveBins[to]) {
                        to++;
                    }
                    if (to - from > bestTo - bestFrom) {
                        bestFrom = from;
                        bestTo = to;
                    }
                }
                JsonObject row = new JsonObject();
                row.addProperty("tid", tid);
                row.addProperty("name", name(tid));
                row.addProperty("priority", priorityText(priorityOf(tid, fWindow.start + (fWindow.end - fWindow.start) / 2)));
                row.addProperty("waiting_for_cpu_ms", waitingNs / 1e6);
                row.addProperty("running_ms", runningNs / 1e6);
                row.addProperty("slowdown_percent", waitingNs * 100.0 / Math.max(1, runningNs));
                row.addProperty("preemptions", preemptions);
                row.addProperty("queued_after_wake_up", queuedAfterWakeUp);
                row.addProperty("longest_wait_ms", longest / 1e6);
                row.addProperty("longest_wait_offset_ms", (longestStart - fTrace.getStartTime().toNanos()) / 1e6);
                if (longestHolder != null) {
                    row.addProperty("longest_wait_cpu_held_by", "TID " + longestHolder + " (" + name(longestHolder) + ")");
                }
                row.add("cpu_held_by", occupants);
                String stretch = "";
                if (bestFrom >= 0 && bestTo > bestFrom && bestTo - bestFrom < 20) {
                    long binNs = (fWindow.end - fWindow.start) / 20;
                    long fromNs = fWindow.start + bestFrom * binNs;
                    long toNs = fWindow.start + bestTo * binNs;
                    long w = 0;
                    long a = 0;
                    for (int b = bestFrom; b < bestTo; b++) {
                        w += bins[b];
                        a += aliveBins[b];
                    }
                    row.addProperty("worst_stretch_start_offset_ms", (fromNs - fTrace.getStartTime().toNanos()) / 1e6);
                    row.addProperty("worst_stretch_end_offset_ms", (toNs - fTrace.getStartTime().toNanos()) / 1e6);
                    row.addProperty("worst_stretch_waiting_percent", w * 100.0 / Math.max(1, a));
                    stretch = String.format(Locale.ROOT, "; worst from %.0f ms to %.0f ms, waiting for a CPU %.0f%% of that time",
                            (fromNs - fTrace.getStartTime().toNanos()) / 1e6, (toNs - fTrace.getStartTime().toNanos()) / 1e6,
                            w * 100.0 / Math.max(1, a));
                }
                delayed.add(row);
                parts.add(String.format(Locale.ROOT, "TID %d (%s, %s) waited %.1f ms for a CPU against %.1f ms running "
                        + "(its work took %.0f%% longer), preempted %d times%s; the CPU was held by %s", tid, name(tid),
                        UnifiedExplainer.str(row, "priority"), waitingNs / 1e6, runningNs / 1e6,
                        waitingNs * 100.0 / Math.max(1, runningNs), preemptions, stretch,
                        occupantText.isEmpty() ? "no one recorded" : String.join(", ", occupantText)));
            }
            JsonObject data = new JsonObject();
            data.addProperty("trace_cpus", traceCpus);
            JsonArray used = new JsonArray();
            cpusUsed.forEach(used::add);
            data.add("cpus_used", used);
            data.addProperty("mean_ready_threads", meanReady);
            data.addProperty("peak_ready_threads", peakReady);
            data.addProperty("running_ms", totalRunning / 1e6);
            data.addProperty("waiting_for_cpu_ms", totalWaiting / 1e6);
            data.addProperty("load", load);
            data.addProperty("cpu_taken_by_other_processes_ms", byOthers / 1e6);
            data.addProperty("cpu_taken_by_own_threads_ms", byOwn / 1e6);
            data.add("delayed_threads", delayed);
            JsonArray caveats = new JsonArray();
            caveats.add("Waiting for a CPU: ready to run but another thread held the CPU it was queued on. 'Its work took X% "
                    + "longer' is that wait over its running time. A higher-priority (real-time) holder preempts; equal "
                    + "priorities take turns. The idle task as holder means interrupt handling or a scheduling gap.");
            String claim = String.format(Locale.ROOT, "CPU use of process %d (%s): its threads ran %.1f ms and waited %.1f ms "
                    + "for a CPU; %s.%s", fPid, name(fPid), totalRunning / 1e6, totalWaiting / 1e6, load,
                    parts.isEmpty() ? " No thread waited for a CPU for 20 ms or more."
                            : String.format(Locale.ROOT, " Of the CPU time taken from its delayed threads, %.1f ms went to other "
                                    + "processes and %.1f ms to its own threads. ", byOthers / 1e6, byOwn / 1e6)
                                    + String.join("; ", parts) + ".");
            fFindings.add(finding("process.cpu_competition", fAbout, "waiting_for_cpu", claim, fWin,
                    "tracecompass.state_system", data, "high", caveats));
        }

        private static History merge(History base, History extra, int quark) {
            base.put(quark, extra.intervals(quark));
            return base;
        }

        private void addToBins(long[] bins, long start, long end) {
            long length = Math.max(1, fWindow.end - fWindow.start);
            for (long s = Math.max(start, fWindow.start); s < Math.min(end, fWindow.end);) {
                int bin = (int) Math.min(bins.length - 1, (s - fWindow.start) * bins.length / length);
                long binEnd = fWindow.start + (bin + 1) * length / bins.length;
                long e = Math.min(end, Math.max(binEnd, s + 1));
                bins[bin] += e - s;
                s = e;
            }
        }

        private static long running(Map<String, Long> states) {
            return states.getOrDefault("RUNNING_USER_MODE", 0L) + states.getOrDefault("RUNNING_SYSTEM_CALL", 0L);
        }

        // ---------------------------------------------------------------
        // Lifecycle: start-up, shutdown, child processes
        // ---------------------------------------------------------------

        private static String phaseSize(double ms) {
            return ms >= 1000 ? "slow (seconds)" : ms >= 100 ? "noticeable (over 100 ms)" : "fast (under 100 ms)";
        }

        /**
         * Start-up: from the process's start (exec or fork) to the first run of the threads that do most
         * of its work, and what the main thread did meanwhile. Shutdown: from its first wait for a
         * thread to finish (a join) in the run of joins before the end, to the process's end, and what
         * each joined thread was doing. Child processes: how each ended (exit status, or the signal that
         * killed it, or that the trace cannot tell).
         */
        private void addLifecycle(Map<Integer, Map<String, Long>> split, Map<Integer, List<long[]>> status,
                Map<Integer, List<WaitInterval>> intervals, JsonObject activity, JsonObject allProcesses) {
            long traceStart = fTrace.getStartTime().toNanos();
            int main = fPid;
            JsonObject data = new JsonObject();
            List<String> parts = new ArrayList<>();

            // Start-up.
            Long startNs = null;
            String startedBy = null;
            if (activity != null && activity.has("program_executed_at_offset_ms")) {
                startNs = traceStart + (long) (activity.get("program_executed_at_offset_ms").getAsDouble() * 1e6);
                startedBy = "exec";
            } else if (activity != null && activity.has("created_at_offset_ms")) {
                startNs = traceStart + (long) (activity.get("created_at_offset_ms").getAsDouble() * 1e6);
                startedBy = "fork";
            }
            List<Integer> workers = new ArrayList<>(split.keySet());
            workers.remove(Integer.valueOf(main));
            workers.sort((a, b) -> Long.compare(running(split.get(b)), running(split.get(a))));
            long workerRunning = workers.stream().mapToLong(tid -> running(split.get(tid))).sum();
            List<Integer> workThreads = new ArrayList<>();
            long covered = 0;
            for (int tid : workers) {
                if (covered >= workerRunning * 0.8 || running(split.get(tid)) == 0) {
                    break;
                }
                workThreads.add(tid);
                covered += running(split.get(tid));
            }
            long firstWork = Long.MAX_VALUE;
            long lastWork = Long.MIN_VALUE;
            for (int tid : workThreads) {
                for (long[] interval : status.getOrDefault(tid, List.of())) {
                    if (interval[2] == 1) {
                        firstWork = Math.min(firstWork, interval[0]);
                        lastWork = Math.max(lastWork, interval[1]);
                    }
                }
            }
            JsonObject startup = new JsonObject();
            if (startNs == null) {
                startup.addProperty("measured", false);
                startup.addProperty("text", "the process was already running when the trace (or window) started, so its "
                        + "start-up is not in the trace");
            } else if (workThreads.isEmpty() || firstWork == Long.MAX_VALUE) {
                startup.addProperty("measured", false);
                startup.addProperty("started_at_offset_ms", (startNs - traceStart) / 1e6);
                startup.addProperty("text", "it has no other thread doing work, so the start of its work cannot be told "
                        + "apart from its start-up");
            } else {
                double ms = (firstWork - startNs) / 1e6;
                Map<String, Long> mainStates = new LinkedHashMap<>();
                Map<String, Long> blockedIn = new HashMap<>();
                for (long[] interval : status.getOrDefault(main, List.of())) {
                    long s = Math.max(interval[0], startNs);
                    long e = Math.min(interval[1], firstWork);
                    if (e <= s) {
                        continue;
                    }
                    String state = interval[2] == 1 ? "running" : interval[2] == 2 ? "waiting for a CPU" : "blocked or not yet started";
                    mainStates.merge(state, e - s, Long::sum);
                    if (interval[2] == 0) {
                        String call = syscallAt(main, s);
                        if (call != null) {
                            blockedIn.merge(call, e - s, Long::sum);
                        }
                    }
                }
                startup.addProperty("measured", true);
                startup.addProperty("started_by", startedBy);
                startup.addProperty("started_at_offset_ms", (startNs - traceStart) / 1e6);
                startup.addProperty("first_work_at_offset_ms", (firstWork - traceStart) / 1e6);
                JsonArray names = new JsonArray();
                workThreads.forEach(tid -> names.add(tid + " " + name(tid)));
                startup.add("work_threads", names);
                startup.addProperty("startup_ms", ms);
                startup.addProperty("size", phaseSize(ms));
                JsonObject mainJson = new JsonObject();
                List<String> mainText = new ArrayList<>();
                mainStates.forEach((state, ns) -> {
                    mainJson.addProperty(state.replace(' ', '_') + "_ms", ns / 1e6);
                    mainText.add(String.format(Locale.ROOT, "%s %.1f ms", state, ns / 1e6));
                });
                startup.add("main_thread_during_startup", mainJson);
                JsonObject blockedJson = new JsonObject();
                List<String> blockedText = new ArrayList<>();
                blockedIn.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(4)
                        .forEach(entry -> {
                            blockedJson.addProperty(entry.getKey(), entry.getValue() / 1e6);
                            if (entry.getValue() >= 1_000_000L) {
                                blockedText.add(String.format(Locale.ROOT, "%s %.1f ms", entry.getKey(), entry.getValue() / 1e6));
                            }
                        });
                startup.add("main_thread_blocked_in_ms", blockedJson);
                List<String> shortNames = new ArrayList<>();
                workThreads.forEach(tid -> shortNames.add(name(tid)));
                startup.addProperty("text", String.format(Locale.ROOT,
                        "start-up: %.1f ms from its %s (at %.1f ms) to the first run of the threads that do most of its work "
                                + "(%s, at %.1f ms): %s; meanwhile the main thread was %s%s",
                        ms, startedBy, (startNs - traceStart) / 1e6, shortNames.size() > 6 ? shortNames.size() + " threads"
                                : String.join(", ", shortNames), (firstWork - traceStart) / 1e6, phaseSize(ms),
                        String.join(", ", mainText), blockedText.isEmpty() ? "" : " (blocked in " + String.join(", ", blockedText) + ")"));
            }
            data.add("startup", startup);
            parts.add(UnifiedExplainer.str(startup, "text"));

            // Shutdown.
            JsonObject ended = UnifiedExplainer.obj(activity, "ended");
            Long endNs = null;
            if (ended != null && ended.has("at_offset_ms")) {
                endNs = traceStart + (long) (ended.get("at_offset_ms").getAsDouble() * 1e6);
            }
            JsonObject shutdown = new JsonObject();
            if (endNs == null) {
                shutdown.addProperty("measured", false);
                shutdown.addProperty("text", "the process did not end in the trace (or window), so there is no shutdown to "
                        + "measure" + (ended != null ? "; it " + UnifiedExplainer.str(ended, "text") : ""));
            } else {
                List<WaitInterval> joins = new ArrayList<>();
                for (WaitInterval wait : intervals.getOrDefault(main, List.of())) {
                    if (wait.cause.startsWith("tid:")) {
                        int waker = Integer.parseInt(wait.cause.substring(4));
                        Long gone = fLastRun.get(waker);
                        if (waker != main && gone != null && gone >= wait.end - 1_000_000L && gone - wait.end <= 5_000_000L
                                && gone < fWindow.end - 1_000_000L) {
                            /* A join is shutdown only if the thread was winding down, not doing its normal work. */
                            long ran = 0;
                            for (long[] interval : status.getOrDefault(waker, List.of())) {
                                if (interval[2] == 1) {
                                    ran += Math.max(0, Math.min(interval[1], wait.end) - Math.max(interval[0], wait.start));
                                }
                            }
                            if (ran * 10 <= wait.end - wait.start) {
                                joins.add(wait);
                            }
                        }
                    }
                }
                joins.sort((a, b) -> Long.compare(a.start, b.start));
                // The run of joins before the end: walk back while each starts soon after the previous ends.
                int first = joins.size() - 1;
                while (first > 0 && joins.get(first).start - joins.get(first - 1).end <= 50_000_000L) {
                    first--;
                }
                long from;
                String fromText;
                JsonArray joined = new JsonArray();
                if (!joins.isEmpty() && endNs - joins.get(joins.size() - 1).end <= 1_000_000_000L) {
                    from = joins.get(first).start;
                    fromText = "its first wait for a thread to finish (join)";
                    for (WaitInterval join : joins.subList(first, joins.size())) {
                        int tid = Integer.parseInt(join.cause.substring(4));
                        JsonObject item = new JsonObject();
                        item.addProperty("tid", tid);
                        item.addProperty("name", name(tid));
                        item.addProperty("waited_ms", (join.end - join.start) / 1e6);
                        long run = 0;
                        long blocked = 0;
                        Map<String, Long> calls = new HashMap<>();
                        for (long[] interval : status.getOrDefault(tid, List.of())) {
                            long s = Math.max(interval[0], join.start);
                            long e = Math.min(interval[1], join.end);
                            if (e <= s) {
                                continue;
                            }
                            if (interval[2] == 1) {
                                run += e - s;
                            } else if (interval[2] == 0) {
                                blocked += e - s;
                                String call = syscallAt(tid, s);
                                if (call != null) {
                                    calls.merge(call, e - s, Long::sum);
                                }
                            }
                        }
                        item.addProperty("it_was_running_ms", run / 1e6);
                        item.addProperty("it_was_blocked_ms", blocked / 1e6);
                        calls.entrySet().stream().max(Map.Entry.comparingByValue())
                                .ifPresent(entry -> item.addProperty("it_was_blocked_mostly_in", entry.getKey()));
                        joined.add(item);
                    }
                } else {
                    from = lastWork == Long.MIN_VALUE ? endNs : Math.min(lastWork, endNs);
                    fromText = "the last run of the threads that do most of its work";
                }
                double ms = (endNs - from) / 1e6;
                shutdown.addProperty("measured", true);
                shutdown.addProperty("from", fromText);
                shutdown.addProperty("from_offset_ms", (from - traceStart) / 1e6);
                shutdown.addProperty("end_offset_ms", (endNs - traceStart) / 1e6);
                shutdown.addProperty("shutdown_ms", ms);
                shutdown.addProperty("size", phaseSize(ms));
                shutdown.add("joined_threads", joined);
                List<String> joinText = new ArrayList<>();
                for (JsonElement element : joined) {
                    JsonObject item = element.getAsJsonObject();
                    if (joinText.size() < 6) {
                        joinText.add(String.format(Locale.ROOT, "%s waited %.1f ms (it ran %.1f ms, blocked %.1f ms%s)",
                                UnifiedExplainer.str(item, "name"), UnifiedExplainer.dbl(item, "waited_ms", 0),
                                UnifiedExplainer.dbl(item, "it_was_running_ms", 0), UnifiedExplainer.dbl(item, "it_was_blocked_ms", 0),
                                item.has("it_was_blocked_mostly_in") ? " mostly in " + UnifiedExplainer.str(item, "it_was_blocked_mostly_in") : ""));
                    }
                }
                shutdown.addProperty("text", String.format(Locale.ROOT, "shutdown: %.1f ms from %s (at %.1f ms) to the end of "
                        + "the process (at %.1f ms): %s%s", ms, fromText, (from - traceStart) / 1e6, (endNs - traceStart) / 1e6,
                        phaseSize(ms), joinText.isEmpty() ? "" : "; joins: " + String.join("; ", joinText)));
            }
            data.add("shutdown", shutdown);
            parts.add(UnifiedExplainer.str(shutdown, "text"));
            if (ended != null) {
                data.add("process_ended", ended.deepCopy());
                parts.add("the process " + UnifiedExplainer.str(ended, "text"));
            }

            // Child processes.
            JsonArray children = new JsonArray();
            Map<String, Integer> byHow = new LinkedHashMap<>();
            List<JsonObject> abnormal = new ArrayList<>();
            if (allProcesses != null) {
                for (Map.Entry<String, JsonElement> entry : allProcesses.entrySet()) {
                    JsonObject child = entry.getValue().getAsJsonObject();
                    if (UnifiedExplainer.num(child, "parent_pid", -1L) != main) {
                        continue;
                    }
                    JsonObject childEnd = UnifiedExplainer.obj(child, "ended");
                    String how = childEnd == null ? "unknown" : UnifiedExplainer.str(childEnd, "how");
                    String key = "exited".equals(how) ? "exited with status " + UnifiedExplainer.num(childEnd, "status", 0L)
                            : "killed by a signal".equals(how) ? "killed by " + UnifiedExplainer.str(childEnd, "signal") : how;
                    byHow.merge(key, 1, Integer::sum);
                    JsonObject row = new JsonObject();
                    row.addProperty("pid", Integer.parseInt(entry.getKey()));
                    if (child.has("executable")) {
                        row.add("name", child.get("executable"));
                    }
                    if (child.has("program_executed")) {
                        row.add("program", child.get("program_executed"));
                    }
                    if (child.has("created_at_offset_ms")) {
                        row.add("created_at_offset_ms", child.get("created_at_offset_ms"));
                    }
                    row.addProperty("ended", childEnd == null ? "unknown" : UnifiedExplainer.str(childEnd, "text"));
                    if (childEnd != null && childEnd.has("at_offset_ms")) {
                        row.add("ended_at_offset_ms", childEnd.get("at_offset_ms"));
                    }
                    if (!"exited".equals(how)) {
                        abnormal.add(row);
                    } else {
                        children.add(row);
                    }
                }
            }
            JsonArray childRows = new JsonArray();
            abnormal.forEach(childRows::add);
            children.forEach(childRows::add);
            if (childRows.size() > 0) {
                JsonObject counts = new JsonObject();
                byHow.forEach(counts::addProperty);
                data.add("child_processes", childRows);
                data.add("child_processes_by_end", counts);
                List<String> abnormalText = new ArrayList<>();
                for (JsonObject row : abnormal.subList(0, Math.min(5, abnormal.size()))) {
                    abnormalText.add(String.format(Locale.ROOT, "PID %d (%s) %s%s", row.get("pid").getAsInt(),
                            UnifiedExplainer.str(row, "name"), UnifiedExplainer.str(row, "ended"),
                            row.has("ended_at_offset_ms") ? String.format(Locale.ROOT, " at %.1f ms",
                                    row.get("ended_at_offset_ms").getAsDouble()) : ""));
                }
                parts.add(String.format(Locale.ROOT, "it started %d child process(es): %s%s", childRows.size(), counts,
                        abnormalText.isEmpty() ? "" : "; " + String.join("; ", abnormalText)));
            } else {
                parts.add("it started no child processes in this window");
            }
            JsonArray caveats = new JsonArray();
            caveats.add("Sizes: under 100 ms is fast, over 100 ms noticeable, a second or more slow. Start-up ends at the "
                    + "first run of the threads that do most of the process's CPU work; shutdown starts at the first of the "
                    + "joins (waits for a thread to finish) before the end.");
            caveats.add("A process that ends without calling exit was killed by a signal; the trace names the signal only "
                    + "when it records signal events (signal_events_recorded).");
            fFindings.add(finding("process.lifecycle", fAbout, null, "Lifecycle of process " + fPid + " (" + name(fPid)
                    + "): " + String.join("; ", parts) + ".", fWin, "tracecompass.state_system+java.thread_activity", data,
                    "high", caveats));
        }

        private void addThreads(String processName, Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive) {
            JsonArray rows = new JsonArray();
            List<String> parts = new ArrayList<>();
            for (Map.Entry<Integer, Map<String, Long>> entry : split.entrySet()) {
                int tid = entry.getKey();
                Map<String, Long> states = entry.getValue();
                long aliveNs = alive.get(tid);
                long running = states.getOrDefault("RUNNING_USER_MODE", 0L) + states.getOrDefault("RUNNING_SYSTEM_CALL", 0L);
                long waiting = states.getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L);
                long blocked = states.getOrDefault("BLOCKED", 0L);
                JsonObject row = new JsonObject();
                row.addProperty("tid", tid);
                row.addProperty("name", name(tid));
                row.addProperty("alive_ms", aliveNs / 1_000_000.0);
                row.addProperty("running_ms", running / 1_000_000.0);
                row.addProperty("running_percent", running * 100.0 / aliveNs);
                row.addProperty("waiting_for_cpu_ms", waiting / 1_000_000.0);
                row.addProperty("waiting_for_cpu_percent", waiting * 100.0 / aliveNs);
                row.addProperty("blocked_ms", blocked / 1_000_000.0);
                row.addProperty("blocked_percent", blocked * 100.0 / aliveNs);
                rows.add(row);
                parts.add(String.format(Locale.ROOT, "TID %d (%s) running %.1f%%, waiting for a CPU %.1f%%, blocked %.1f%%",
                        tid, name(tid), running * 100.0 / aliveNs, waiting * 100.0 / aliveNs, blocked * 100.0 / aliveNs));
            }
            JsonObject data = new JsonObject();
            data.addProperty("pid", fPid);
            data.addProperty("name", processName);
            data.add("threads", rows);
            fFindings.add(finding("process.threads", fAbout, null, String.format(Locale.ROOT,
                    "Process %d (%s) had %d live thread(s) here: %s.", fPid, processName, split.size(),
                    String.join("; ", parts)),
                    fWin, "tracecompass.state_system", data, "high", new JsonArray()));
        }

        /** waiter TID -> cause ("tid:N" or a wait type) -> waiting; null if the graph is unavailable. */
        /** The trace's OS execution graph, built on first use; null if unavailable. */
        static ITmfGraph executionGraph(ITmfTrace trace) {
            OsExecutionGraph module = TmfTraceUtils.getAnalysisModuleOfClass(
                    trace, OsExecutionGraph.class, OsExecutionGraph.ANALYSIS_ID);
            if (module == null) {
                return null;
            }
            module.schedule();
            module.waitForCompletion();
            return module.getTmfGraph();
        }

        /**
         * Every wait of {@code tid} in [start, end], in time order, with what
         * ended it: "tid:N" when another thread woke it (the graph's vertical
         * edge into the end of the wait), "IDLE_TASK" when the graph
         * attributes the wake-up to the idle task, else the wait type
         * (TIMER, NETWORK, BLOCK_DEVICE, ...).
         */
        static List<WaitInterval> waitsOf(ITmfGraph graph, int tid, long startNs, long endNs) {
            List<WaitInterval> waits = new ArrayList<>();
            OsWorker worker = findOsWorker(graph, tid);
            if (worker == null) {
                return waits;
            }
            Iterator<ITmfVertex> vertices = graph.getNodesOf(worker);
            while (vertices.hasNext()) {
                ITmfVertex vertex = vertices.next();
                ITmfEdge edge = graph.getEdgeFrom(vertex, ITmfGraph.EdgeDirection.OUTGOING_HORIZONTAL_EDGE);
                if (edge == null) {
                    continue;
                }
                String type = String.valueOf(edge.getEdgeContextState().getContextEnum());
                if (!WAIT_EDGES.contains(type)) {
                    continue;
                }
                long start = Math.max(edge.getVertexFrom().getTimestamp(), startNs);
                long end = Math.min(edge.getVertexTo().getTimestamp(), endNs);
                if (end <= start) {
                    continue;
                }
                String cause = type;
                ITmfEdge wakeup = graph.getEdgeFrom(edge.getVertexTo(), ITmfGraph.EdgeDirection.INCOMING_VERTICAL_EDGE);
                if (wakeup != null) {
                    IGraphWorker waker = graph.getParentOf(wakeup.getVertexFrom());
                    if (waker instanceof OsWorker) {
                        int wakerTid = ((OsWorker) waker).getHostThread().getTid();
                        cause = wakerTid == 0 ? "IDLE_TASK" : "tid:" + wakerTid;
                    }
                }
                waits.add(new WaitInterval(start, end, cause));
            }
            return waits;
        }

        private Map<Integer, Map<String, Wait>> waitGraph(Set<Integer> tids, Map<Integer, List<WaitInterval>> intervals) {
            ITmfGraph graph = executionGraph(fTrace);
            if (graph == null) {
                fFindings.add(finding("process.wait_graph", fAbout, "blocked",
                        "Who woke whom could not be computed: the execution graph is not available for this trace.",
                        fWin, "tracecompass.execution_graph", new JsonObject(), "n/a", new JsonArray()));
                return null;
            }
            Map<Integer, Map<String, Wait>> waits = new LinkedHashMap<>();
            for (int tid : tids) {
                Map<String, Wait> causes = waits.computeIfAbsent(tid, k -> new HashMap<>());
                for (WaitInterval wait : waitsOf(graph, tid, fWindow.start, fWindow.end)) {
                    causes.computeIfAbsent(wait.cause, k -> new Wait()).add(wait.start, wait.end);
                    intervals.computeIfAbsent(tid, k -> new ArrayList<>()).add(wait);
                }
            }
            return waits;
        }

        private String describeCause(String cause) {
            if (cause.startsWith("tid:")) {
                int tid = Integer.parseInt(cause.substring(4));
                return "TID " + tid + " (" + name(tid) + ")";
            }
            switch (cause) {
            case "TIMER":
                return "a timer (sleep or timeout)";
            case "NETWORK":
                return "the network";
            case "BLOCK_DEVICE":
                return "disk I/O";
            case "IPI":
                return "an inter-processor interrupt";
            case "INTERRUPTED":
            case "BLOCKED":
                return "an interrupt or unattributed wake-up";
            case "IDLE_TASK":
                return "a wake-up attributed to the idle task (usually a cross-CPU wake-up the graph cannot attribute)";
            default:
                return cause;
            }
        }

        private void addWaitGraph(String processName, Set<Integer> tids, Map<Integer, Map<String, Wait>> waits) {
            List<Object[]> edges = new ArrayList<>();
            waits.forEach((waiter, causes) -> causes.forEach((cause, wait) -> edges.add(new Object[] {waiter, cause, wait})));
            edges.sort((a, b) -> Long.compare(((Wait) b[2]).ns, ((Wait) a[2]).ns));
            JsonArray list = new JsonArray();
            List<String> parts = new ArrayList<>();
            for (Object[] edge : edges.subList(0, Math.min(MAX_EDGES, edges.size()))) {
                int waiter = (Integer) edge[0];
                String cause = (String) edge[1];
                Wait wait = (Wait) edge[2];
                JsonObject item = new JsonObject();
                item.addProperty("waiter_tid", waiter);
                item.addProperty("waiter_name", name(waiter));
                if (cause.startsWith("tid:")) {
                    int waker = Integer.parseInt(cause.substring(4));
                    item.addProperty("woken_by_tid", waker);
                    item.addProperty("woken_by_name", name(waker));
                    item.addProperty("waker_in_process", tids.contains(waker));
                } else {
                    item.addProperty("woken_by", cause);
                }
                item.addProperty("waited_ms", wait.ns / 1_000_000.0);
                item.addProperty("wake_ups", wait.count);
                item.addProperty("longest_wait_ms", (wait.longestEnd - wait.longestStart) / 1_000_000.0);
                item.addProperty("longest_wait_start_offset_ms", (wait.longestStart - fTrace.getStartTime().toNanos()) / 1_000_000.0);
                list.add(item);
                if (parts.size() < 8) {
                    parts.add(String.format(Locale.ROOT, "TID %d waited %.3f ms in total (%d waits) until woken by %s",
                            waiter, wait.ns / 1_000_000.0, wait.count, describeCause(cause)));
                }
            }
            JsonObject data = new JsonObject();
            data.add("edges", list);
            data.addProperty("edges_omitted", Math.max(0, edges.size() - MAX_EDGES));
            JsonArray caveats = new JsonArray();
            caveats.add("This lists every thread's waits, including waits for new work (idle time), so the thread "
                    + "that ends the most waits here is not necessarily the bottleneck; see process.bottleneck.");
            caveats.add("A wake-up names the thread that ended the wait (e.g. released the lock or posted the data), "
                    + "not necessarily the whole chain behind it; wake-ups across CPUs or from interrupt context can be "
                    + "unattributed or attributed to the idle task.");
            fFindings.add(finding("process.wait_graph", fAbout, "blocked",
                    parts.isEmpty() ? "The threads of process " + fPid + " never waited in this window."
                            : "Who woke the threads of " + processName + " after their waits: " + String.join("; ", parts) + ".",
                    fWin, "tracecompass.execution_graph", data, "high", caveats));
        }

        /**
         * The bottleneck as seen from the process's main thread (TID = PID),
         * whose waits are the process's own progress (a coordinator waiting for
         * its workers, a main thread joining them). Other threads' waits are
         * not counted: a worker waiting for its next batch is idle, not held
         * up. From the threads that ended the main thread's waits, follows the
         * chain: what the waker was doing while the main thread waited on it,
         * what ended the waker's own waits in those windows, and so on to a
         * root that is not a thread (a timer, the CPU, I/O). Aggregated over
         * every wait, then one real critical path over one example wait.
         *
         * @return false if the main thread never waited on another thread here
         */
        /** A thread name without its trailing number: "worker-2" -> "worker-", "calc-12" -> "calc-". */
        static String nameStem(String name) {
            return name == null ? "" : name.replaceAll("\\d+$", "");
        }

        /** The main thread must wait on its bottleneck at least this often for it to pace recurring rounds. */
        private static final int MIN_ROUNDS = 5;

        /**
         * How much the bottleneck holds the program up: how much later than the last of the other
         * threads it finishes, per round, as a share of the round (process.round_profile). Added to the
         * process.bottleneck finding, with a plain label: negligible (under 5%), minor (5-25%) or
         * significant (25% or more). Naming the thread that finishes last says nothing by itself:
         * in a healthy program some thread is always last.
         */
        private void addBottleneckImpact(JsonObject bottleneckFinding, int bottleneck, JsonArray roundMs) {
            JsonObject profile = null;
            for (JsonElement element : fFindings) {
                if ("process.round_profile".equals(UnifiedExplainer.str(element.getAsJsonObject(), "id"))) {
                    profile = UnifiedExplainer.obj(UnifiedExplainer.obj(element.getAsJsonObject(), "evidence"), "data");
                }
            }
            if (profile == null || !profile.has("bottleneck_later_than_others_mean_ms") || roundMs.size() == 0) {
                return;
            }
            double lead = profile.get("bottleneck_later_than_others_mean_ms").getAsDouble();
            double round = 0;
            for (JsonElement ms : roundMs) {
                round += ms.getAsDouble();
            }
            round /= roundMs.size();
            if (round <= 0) {
                return;
            }
            double percent = Math.max(0, lead) * 100.0 / round;
            String label = percent >= 25 ? "significant" : percent >= 5 ? "minor" : "negligible";
            JsonObject data = UnifiedExplainer.obj(UnifiedExplainer.obj(bottleneckFinding, "evidence"), "data");
            data.addProperty("round_mean_ms", round);
            data.addProperty("finishes_after_others_mean_ms", lead);
            data.addProperty("impact_percent_of_round", percent);
            data.addProperty("impact", label);
            bottleneckFinding.addProperty("claim", UnifiedExplainer.str(bottleneckFinding, "claim") + String.format(Locale.ROOT,
                    " How much it holds the program up: it finishes on average %.3f ms after the last of the other threads, "
                            + "in rounds of %.3f ms, so the rounds would be about %.1f%% shorter if it kept up with them: a %s "
                            + "hold-up%s.",
                    lead, round, percent, label, "significant".equals(label) ? ""
                            : " (in any program some thread finishes last; this one does not hold the program up much)"));
        }

        private boolean addMainThreadBottleneck(String processName, Map<Integer, List<long[]>> status,
                Map<Integer, List<WaitInterval>> intervals, Set<Integer> tids) {
            int main = fPid;
            List<WaitInterval> mainWaits = intervals.getOrDefault(main, List.of());
            long mainWaitTotal = 0;
            long mainThreadWait = 0;
            Map<Integer, Long> wakers = new HashMap<>();
            Map<Integer, Integer> wakeCounts = new HashMap<>();
            Map<String, Long> mainByCause = new HashMap<>();
            for (WaitInterval wait : mainWaits) {
                long length = wait.end - wait.start;
                mainWaitTotal += length;
                mainByCause.merge(wait.cause, length, Long::sum);
                if (wait.cause.startsWith("tid:")) {
                    mainThreadWait += length;
                    int waker = Integer.parseInt(wait.cause.substring(4));
                    if (waker != main && tids.contains(waker)) {
                        wakers.merge(waker, length, Long::sum);
                        wakeCounts.merge(waker, 1, Integer::sum);
                    }
                }
            }
            if (wakers.isEmpty()) {
                return false;
            }
            int bottleneck = wakers.entrySet().stream().max(Map.Entry.comparingByValue()).orElseThrow().getKey();
            /*
             * The main thread's waits are the process's progress only if it hands out recurring rounds of
             * work: at least MIN_ROUNDS waits on the bottleneck, and its waiting on other threads at least
             * 5% of the window. A main thread that waits once (a join at the end) or mostly sleeps on its
             * own timer is not paced by any thread; the other method below then looks at all the threads.
             */
            if (wakeCounts.get(bottleneck) < MIN_ROUNDS || mainThreadWait * 20 < Math.max(1, fWindow.end - fWindow.start)) {
                return false;
            }
            double ofThreadWaits = wakers.get(bottleneck) * 100.0 / Math.max(1, mainThreadWait);
            double ofAllWaits = wakers.get(bottleneck) * 100.0 / Math.max(1, mainWaitTotal);

            // Follow the chain from the main thread's waits on the bottleneck.
            List<long[]> windows = new ArrayList<>();
            List<Long> roundStarts = new ArrayList<>();
            List<WaitInterval> bottleneckWaits = new ArrayList<>();
            JsonArray seriesMs = new JsonArray();
            JsonArray seriesNs = new JsonArray();
            for (int k = 0; k < mainWaits.size(); k++) {
                WaitInterval wait = mainWaits.get(k);
                if (wait.cause.equals("tid:" + bottleneck)) {
                    /*
                     * A round starts when the main thread wakes (its previous
                     * wait ends) and hands out work, before it blocks on the
                     * bottleneck; measuring only the block would miss that.
                     */
                    long roundStart = k > 0 ? mainWaits.get(k - 1).end : wait.start;
                    roundStarts.add(roundStart);
                    seriesMs.add((wait.end - roundStart) / 1_000_000.0);
                    seriesNs.add(roundStart);
                    windows.add(new long[] {wait.start, wait.end});
                    bottleneckWaits.add(wait);
                }
            }
            // The example is a typical wait (the median-length one), not the longest, which may be an outlier round.
            List<WaitInterval> byLength = new ArrayList<>(bottleneckWaits);
            byLength.sort((a, b) -> Long.compare(a.end - a.start, b.end - b.start));
            WaitInterval typical = byLength.isEmpty() ? null : byLength.get(byLength.size() / 2);
            List<long[]> mainWindows = new ArrayList<>(windows);
            JsonArray chain = new JsonArray();
            List<String> chainText = new ArrayList<>();
            chainText.add(name(main) + " (TID " + main + ")");
            Set<Integer> visited = new java.util.HashSet<>(List.of(main));
            int current = bottleneck;
            String root = null;
            for (int depth = 0; depth < 4 && windows.size() > 0; depth++) {
                visited.add(current);
                JsonObject step = chainStep(current, windows, status.getOrDefault(current, List.of()),
                        intervals.getOrDefault(current, List.of()));
                chain.add(step);
                String how = UnifiedExplainer.str(step, "summary");
                chainText.add(name(current) + " (TID " + current + ", " + how + ")");
                String next = UnifiedExplainer.str(step, "dominant_wait_cause");
                if (next == null || "running".equals(UnifiedExplainer.str(step, "dominant_state"))
                        || "waiting_for_cpu".equals(UnifiedExplainer.str(step, "dominant_state"))) {
                    root = UnifiedExplainer.str(step, "dominant_state_text");
                    break;
                }
                if (!next.startsWith("tid:")) {
                    root = describeCause(next);
                    break;
                }
                int nextTid = Integer.parseInt(next.substring(4));
                if (visited.contains(nextTid)) {
                    root = "a cycle back to TID " + nextTid;
                    break;
                }
                List<long[]> nextWindows = new ArrayList<>();
                for (WaitInterval wait : intervals.getOrDefault(current, List.of())) {
                    if (wait.cause.equals(next)) {
                        for (long[] clipped : clip(windows, wait.start, wait.end)) {
                            nextWindows.add(clipped);
                        }
                    }
                }
                nextWindows.sort((a, b) -> Long.compare(a[0], b[0]));
                windows = nextWindows;
                current = nextTid;
            }
            if (root != null) {
                chainText.add(root);
            }

            if (fSide != null) {
                fSide.addProperty("main_tid", main);
                fSide.addProperty("bottleneck_tid", bottleneck);
                fSide.addProperty("bottleneck_name", name(bottleneck));
                fSide.add("waits_ms", seriesMs);
                fSide.add("waits_start_ns", seriesNs);
            }
            JsonObject data = new JsonObject();
            data.addProperty("verdict", "bottleneck_thread");
            data.addProperty("method", "main_thread_wait_chain");
            data.addProperty("main_tid", main);
            data.addProperty("main_name", name(main));
            data.addProperty("main_wait_ms", mainWaitTotal / 1_000_000.0);
            data.addProperty("main_wait_on_threads_ms", mainThreadWait / 1_000_000.0);
            data.addProperty("bottleneck_tid", bottleneck);
            data.addProperty("bottleneck_name", name(bottleneck));
            data.addProperty("bottleneck_waits_ended", wakeCounts.get(bottleneck));
            data.addProperty("bottleneck_ms", wakers.get(bottleneck) / 1_000_000.0);
            data.addProperty("bottleneck_percent_of_main_thread_waits", ofThreadWaits);
            data.addProperty("bottleneck_percent_of_main_all_waits", ofAllWaits);
            JsonArray others = new JsonArray();
            wakers.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).forEach(entry -> {
                JsonObject item = new JsonObject();
                item.addProperty("tid", entry.getKey());
                item.addProperty("name", name(entry.getKey()));
                item.addProperty("ended_main_waits_ms", entry.getValue() / 1_000_000.0);
                item.addProperty("waits_ended", wakeCounts.get(entry.getKey()));
                others.add(item);
            });
            data.add("wakers_of_main_thread", others);
            JsonObject mainCauses = new JsonObject();
            mainByCause.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .forEach(entry -> mainCauses.addProperty(describeCause(entry.getKey()), entry.getValue() / 1_000_000.0));
            data.add("main_waits_by_cause_ms", mainCauses);
            data.add("chain", chain);
            if (root != null) {
                data.addProperty("root", root);
            }
            JsonObject last = chain.size() == 0 ? null : chain.get(chain.size() - 1).getAsJsonObject();
            if (last != null) {
                data.addProperty("root_tid", last.get("tid").getAsInt());
                data.addProperty("root_name", UnifiedExplainer.str(last, "name"));
            }

            JsonArray caveats = new JsonArray();
            caveats.add("Follows the main thread (TID = PID), whose waits are the process's progress; other threads' "
                    + "waits for new work are idle time, not delay, and are not counted here.");
            caveats.add("Each step of the chain is aggregated over all the waits it explains, so it shows what usually "
                    + "happens, not one particular wait; the example critical path shows one.");
            String claim = String.format(Locale.ROOT,
                    "Following the main thread TID %d (%s), whose waits are the process's progress: %.1f%% of its waiting "
                            + "on other threads (%.3f ms over %d waits) ended with a wake-up from TID %d (%s), so TID %d is the "
                            + "bottleneck. Wait chain, aggregated over those waits: %s.",
                    main, name(main), ofThreadWaits, wakers.get(bottleneck) / 1_000_000.0, wakeCounts.get(bottleneck),
                    bottleneck, name(bottleneck), bottleneck, String.join(" <- ", chainText));
            JsonObject bottleneckFinding = finding("process.bottleneck", fAbout, "blocked", claim, fWin,
                    "tracecompass.execution_graph", data, ofThreadWaits >= 60 ? "high" : ofThreadWaits >= 30 ? "medium" : "low",
                    caveats);
            fFindings.add(bottleneckFinding);

            addWhatIf(main, bottleneck, mainWindows, roundStarts, chain, status, intervals);
            addRoundProfile(main, bottleneck, roundWindows(mainWindows, roundStarts), chain, status);
            addBottleneckImpact(bottleneckFinding, bottleneck, seriesMs);

            if (typical != null) {
                JsonObject criticalPath = collectCriticalPath(fTrace, main, typical.start, typical.end + 2);
                JsonObject chainData = new JsonObject();
                chainData.addProperty("waiter_tid", main);
                chainData.addProperty("example_kind", "typical");
                chainData.addProperty("interval_ms", (typical.end - typical.start) / 1_000_000.0);
                chainData.addProperty("interval_start_offset_ms", (typical.start - fTrace.getStartTime().toNanos()) / 1_000_000.0);
                chainData.addProperty("longest_wait_ms", (byLength.get(byLength.size() - 1).end
                        - byLength.get(byLength.size() - 1).start) / 1_000_000.0);
                chainData.addProperty("available", UnifiedExplainer.bool(criticalPath, "available"));
                JsonObject pathChain = UnifiedExplainer.obj(criticalPath, "chain");
                JsonArray chainCaveats = new JsonArray();
                if (pathChain != null) {
                    chainData.add("direct_waker", pathChain.get("direct_waker"));
                    chainData.add("root_activity", pathChain.get("root_activity"));
                    chainData.add("segments", pathChain.get("segments"));
                    if (pathChain.has("warning")) {
                        chainCaveats.add(pathChain.get("warning"));
                    }
                }
                fFindings.add(finding("process.example_chain", fAbout, "blocked",
                        UnifiedExplainer.bool(criticalPath, "available")
                                ? String.format(Locale.ROOT, "Example: a typical (median-length, %.3f ms) wait of the main thread on TID %d. ",
                                        (typical.end - typical.start) / 1_000_000.0, bottleneck)
                                        + summarizeBlockedGap(main, criticalPath)
                                : "Critical path not available for the example wait: " + UnifiedExplainer.str(criticalPath, "reason"),
                        fWin, "tracecompass.critical_path", chainData, "high", chainCaveats));
            }
            return true;
        }

        /**
         * What the main thread's waits would become if the bottleneck no
         * longer waited on the next link of the chain: per wait, the longer
         * of (the wait minus that part) and (when the threads outside the
         * chain finished their own work in it, since the round still needs
         * them). An estimate from this trace, not a measurement of a change.
         */
        private void addWhatIf(int main, int bottleneck, List<long[]> mainWindows, List<Long> roundStarts, JsonArray chain,
                Map<Integer, List<long[]>> status, Map<Integer, List<WaitInterval>> intervals) {
            if (chain.size() == 0 || mainWindows.size() < 1) {
                return;
            }
            JsonObject first = chain.get(0).getAsJsonObject();
            String removed = UnifiedExplainer.str(first, "dominant_wait_cause");
            if (removed == null) {
                return;
            }
            List<long[]> removedWaits = new ArrayList<>();
            for (WaitInterval wait : intervals.getOrDefault(bottleneck, List.of())) {
                if (wait.cause.equals(removed)) {
                    removedWaits.add(new long[] {wait.start, wait.end});
                }
            }
            long[] removedPerWindow = perWindowOverlap(mainWindows, removedWaits);

            Set<Integer> chainTids = new java.util.HashSet<>();
            chainTids.add(main);
            chain.forEach(step -> chainTids.add(step.getAsJsonObject().get("tid").getAsInt()));
            long[] othersDone = new long[mainWindows.size()];
            java.util.Arrays.fill(othersDone, -1);
            JsonArray others = new JsonArray();
            for (Map.Entry<Integer, List<long[]>> entry : status.entrySet()) {
                if (chainTids.contains(entry.getKey())) {
                    continue;
                }
                others.add(entry.getKey());
                List<long[]> running = new ArrayList<>();
                for (long[] interval : entry.getValue()) {
                    if (interval[2] == 1) {
                        running.add(interval);
                    }
                }
                long[] lastEnd = perWindowLastEnd(roundWindows(mainWindows, roundStarts), running);
                for (int i = 0; i < lastEnd.length; i++) {
                    othersDone[i] = Math.max(othersDone[i], lastEnd[i]);
                }
            }

            double current = 0;
            double estimate = 0;
            double removedTotal = 0;
            double othersTotal = 0;
            int limitedByOthers = 0;
            for (int i = 0; i < mainWindows.size(); i++) {
                long start = roundStarts.get(i);
                long length = mainWindows.get(i)[1] - start;
                long withoutWait = length - removedPerWindow[i];
                long othersNs = othersDone[i] < 0 ? 0 : othersDone[i] - start;
                long estimated = Math.max(withoutWait, othersNs);
                if (othersNs > withoutWait) {
                    limitedByOthers++;
                }
                current += length;
                estimate += estimated;
                removedTotal += removedPerWindow[i];
                othersTotal += othersNs;
            }
            int n = mainWindows.size();
            double currentMean = current / n / 1_000_000.0;
            double estimateMean = estimate / n / 1_000_000.0;
            String removedText = describeCause(removed);
            String syscall = UnifiedExplainer.str(first, "system_call");

            JsonObject data = new JsonObject();
            data.addProperty("main_tid", main);
            data.addProperty("bottleneck_tid", bottleneck);
            data.addProperty("removed_wait", removedText);
            if (syscall != null) {
                data.addProperty("removed_wait_system_call", syscall);
            }
            data.addProperty("waits", n);
            data.addProperty("current_mean_ms", currentMean);
            data.addProperty("estimated_mean_ms", estimateMean);
            data.addProperty("speedup_factor", estimateMean == 0 ? 0 : currentMean / estimateMean);
            data.addProperty("removed_wait_mean_ms", removedTotal / n / 1_000_000.0);
            data.addProperty("others_done_mean_ms", othersTotal / n / 1_000_000.0);
            data.addProperty("waits_limited_by_other_threads", limitedByOthers);
            data.add("other_threads", others);

            // A thread that sleeps while another waits on its futex most likely holds that lock while sleeping.
            String holding = "";
            if (chain.size() > 1 && "futex".equals(syscall)) {
                JsonObject second = chain.get(1).getAsJsonObject();
                String secondCall = UnifiedExplainer.str(second, "system_call");
                if ("TIMER".equals(UnifiedExplainer.str(second, "dominant_wait_cause"))
                        && secondCall != null && secondCall.contains("sleep")) {
                    data.addProperty("likely_lock_held_while_sleeping_by_tid", second.get("tid").getAsInt());
                    addLockHold(bottleneck, second.get("tid").getAsInt(), status, intervals);
                    holding = String.format(Locale.ROOT,
                            " TID %d (%s) spent that time in %s, so it most likely holds the lock TID %d waits for "
                                    + "while it sleeps; not sleeping (or doing slow work) while holding the lock would remove this wait.",
                            second.get("tid").getAsInt(), UnifiedExplainer.str(second, "name"), secondCall, bottleneck);
                }
            }
            JsonArray caveats = new JsonArray();
            caveats.add("An estimate from this trace, assuming everything else in each round stays as recorded; "
                    + "only re-tracing after the change measures it.");
            caveats.add("The round cannot end before the threads outside the chain finish their work, so that time "
                    + "bounds the gain (it did in " + limitedByOthers + " of " + n + " waits).");
            fFindings.add(finding("process.what_if", fAbout, "blocked", String.format(Locale.ROOT,
                    "If TID %d (%s) no longer waited until woken by %s (%.3f ms per round%s), the main thread's rounds "
                            + "(from its wake-up to the end of its wait on TID %d) would shrink from %.3f ms to about %.3f ms on "
                            + "average (%.1fx faster): each would then end when the other threads finish their work (%.3f ms "
                            + "into the round, on average).%s",
                    bottleneck, name(bottleneck), removedText, removedTotal / n / 1_000_000.0,
                    syscall == null ? "" : ", in " + syscall, bottleneck, currentMean, estimateMean,
                    estimateMean == 0 ? 0 : currentMean / estimateMean, othersTotal / n / 1_000_000.0, holding),
                    fWin, "tracecompass.execution_graph+state_system", data,
                    "medium", caveats));
        }

        /**
         * Per round, for every thread of the process: when it finished its
         * work (its last running moment, from the round's start), its CPU
         * time and its wait for a CPU; and how much later the bottleneck
         * finished than the threads outside the wait chain. Mean and median
         * over all rounds.
         */
        private void addRoundProfile(int main, int bottleneck, List<long[]> rounds, JsonArray chain,
                Map<Integer, List<long[]>> status) {
            int n = rounds.size();
            if (n == 0) {
                return;
            }
            Set<Integer> chainTids = new java.util.HashSet<>();
            chainTids.add(main);
            chain.forEach(step -> chainTids.add(step.getAsJsonObject().get("tid").getAsInt()));

            JsonArray threads = new JsonArray();
            long[] bottleneckFinish = null;
            long[] othersFinish = new long[n];
            java.util.Arrays.fill(othersFinish, -1);
            List<String> cpuParts = new ArrayList<>();
            /*
             * Compare the bottleneck with its peers, the threads doing the same job (the same name apart from
             * a number: worker-0..3, calc-0..7), when it has any outside the wait chain. A helper that is busy
             * until the bottleneck finishes (a thread preempting it, say) is not doing the round's work and
             * would hide the bottleneck's lead.
             */
            String stem = nameStem(name(bottleneck));
            boolean byPeers = status.keySet().stream().anyMatch(tid -> tid != main && tid != bottleneck
                    && !chainTids.contains(tid) && stem.equals(nameStem(name(tid))));
            for (Map.Entry<Integer, List<long[]>> entry : new java.util.TreeMap<>(status).entrySet()) {
                int tid = entry.getKey();
                if (tid == main) {
                    continue;
                }
                List<long[]> running = new ArrayList<>();
                List<long[]> waiting = new ArrayList<>();
                for (long[] interval : entry.getValue()) {
                    if (interval[2] == 1) {
                        running.add(interval);
                    } else if (interval[2] == 2) {
                        waiting.add(interval);
                    }
                }
                long[] lastEnd = perWindowLastEnd(rounds, running);
                long[] runningNs = perWindowOverlap(rounds, running);
                long[] waitingNs = perWindowOverlap(rounds, waiting);
                List<Long> finish = new ArrayList<>();
                long runningTotal = 0;
                long waitingTotal = 0;
                for (int i = 0; i < n; i++) {
                    runningTotal += runningNs[i];
                    waitingTotal += waitingNs[i];
                    if (lastEnd[i] >= 0) {
                        finish.add(lastEnd[i] - rounds.get(i)[0]);
                    }
                }
                if (tid == bottleneck) {
                    bottleneckFinish = lastEnd;
                } else if (!chainTids.contains(tid) && (!byPeers || stem.equals(nameStem(name(tid))))) {
                    for (int i = 0; i < n; i++) {
                        othersFinish[i] = Math.max(othersFinish[i], lastEnd[i]);
                    }
                }
                JsonObject item = new JsonObject();
                item.addProperty("tid", tid);
                item.addProperty("name", name(tid));
                item.addProperty("in_wait_chain", chainTids.contains(tid));
                item.addProperty("rounds_with_work", finish.size());
                item.addProperty("finish_mean_ms", mean(finish) / 1_000_000.0);
                item.addProperty("finish_median_ms", medianOf(finish) / 1_000_000.0);
                item.addProperty("running_per_round_ms", runningTotal / (double) n / 1_000_000.0);
                item.addProperty("waiting_for_cpu_per_round_ms", waitingTotal / (double) n / 1_000_000.0);
                threads.add(item);
                cpuParts.add(String.format(Locale.ROOT, "TID %d (%s) runs %.3f ms and waits %.3f ms for a CPU per round, finishing %.3f ms in (median)",
                        tid, name(tid), runningTotal / (double) n / 1_000_000.0, waitingTotal / (double) n / 1_000_000.0,
                        medianOf(finish) / 1_000_000.0));
            }

            JsonObject data = new JsonObject();
            data.addProperty("rounds", n);
            data.addProperty("main_tid", main);
            data.addProperty("bottleneck_tid", bottleneck);
            data.addProperty("compared_with", byPeers ? "its peers (threads named " + stem + "*)"
                    : "all other threads outside the wait chain");
            data.add("threads", threads);
            String gapText = "";
            if (bottleneckFinish != null) {
                List<Long> gaps = new ArrayList<>();
                List<Long> bottleneckOffsets = new ArrayList<>();
                List<Long> othersOffsets = new ArrayList<>();
                for (int i = 0; i < n; i++) {
                    if (bottleneckFinish[i] >= 0 && othersFinish[i] >= 0) {
                        gaps.add(bottleneckFinish[i] - othersFinish[i]);
                        bottleneckOffsets.add(bottleneckFinish[i] - rounds.get(i)[0]);
                        othersOffsets.add(othersFinish[i] - rounds.get(i)[0]);
                    }
                }
                if (!gaps.isEmpty()) {
                    data.addProperty("bottleneck_finish_mean_ms", mean(bottleneckOffsets) / 1_000_000.0);
                    data.addProperty("others_finish_mean_ms", mean(othersOffsets) / 1_000_000.0);
                    data.addProperty("bottleneck_later_than_others_mean_ms", mean(gaps) / 1_000_000.0);
                    data.addProperty("bottleneck_later_than_others_median_ms", medianOf(gaps) / 1_000_000.0);
                    data.addProperty("rounds_compared", gaps.size());
                    gapText = String.format(Locale.ROOT,
                            " TID %d (%s) finishes its work %.3f ms into the round on average, the last of %s by %.3f ms, so "
                                    + "TID %d finishes %.3f ms later than them (mean; median %.3f ms) over %d rounds.",
                            bottleneck, name(bottleneck), mean(bottleneckOffsets) / 1_000_000.0,
                            byPeers ? "its peers (" + stem + "*)" : "the other threads outside the wait chain",
                            mean(othersOffsets) / 1_000_000.0, bottleneck, mean(gaps) / 1_000_000.0,
                            medianOf(gaps) / 1_000_000.0, gaps.size());
                }
            }
            JsonArray caveats = new JsonArray();
            caveats.add("A round runs from the main thread's wake-up to the end of its wait on the bottleneck; a thread "
                    + "\"finishes\" at its last running moment in the round (e.g. when it reports done).");
            fFindings.add(finding("process.round_profile", fAbout, null, String.format(Locale.ROOT,
                    "Per round of %s's main thread (%d rounds):%s %s.", name(main), n, gapText, String.join("; ", cpuParts)),
                    fWin, "tracecompass.state_system", data, "high", caveats));
        }

        private static double mean(List<Long> values) {
            if (values.isEmpty()) {
                return 0;
            }
            double sum = 0;
            for (long value : values) {
                sum += value;
            }
            return sum / values.size();
        }

        private static long medianOf(List<Long> values) {
            if (values.isEmpty()) {
                return 0;
            }
            List<Long> sorted = new ArrayList<>(values);
            sorted.sort(Long::compare);
            return sorted.get(sorted.size() / 2);
        }

        /** Rounds: from each round's start to the end of the main thread's wait on the bottleneck. */
        private static List<long[]> roundWindows(List<long[]> mainWindows, List<Long> roundStarts) {
            List<long[]> rounds = new ArrayList<>();
            for (int i = 0; i < mainWindows.size(); i++) {
                rounds.add(new long[] {roundStarts.get(i), mainWindows.get(i)[1]});
            }
            return rounds;
        }

        /**
         * How long the lock holder holds the lock per round, and how long it
         * would if it slept outside the lock. A hold runs from the holder's
         * wake-up before its sleep (when it is told to start, then takes the
         * lock) to the moment it wakes the bottleneck from its futex wait
         * (when it releases the lock). Inferred: a kernel trace records the
         * waits and wake-ups around a lock, not its acquire and release.
         */
        private void addLockHold(int bottleneck, int holder, Map<Integer, List<long[]>> status,
                Map<Integer, List<WaitInterval>> intervals) {
            List<WaitInterval> holderWaits = intervals.getOrDefault(holder, List.of());
            List<long[]> running = new ArrayList<>();
            List<long[]> waiting = new ArrayList<>();
            for (long[] interval : status.getOrDefault(holder, List.of())) {
                if (interval[2] == 1) {
                    running.add(interval);
                } else if (interval[2] == 2) {
                    waiting.add(interval);
                }
            }
            List<long[]> holds = new ArrayList<>();
            List<Long> sleeps = new ArrayList<>();
            for (WaitInterval release : intervals.getOrDefault(bottleneck, List.of())) {
                if (!release.cause.equals("tid:" + holder)) {
                    continue;
                }
                // The holder's last timer sleep ending before it woke the bottleneck,
                // and the end of its wait before that sleep (its wake-up to start).
                int sleepIndex = -1;
                for (int k = 0; k < holderWaits.size() && holderWaits.get(k).end <= release.end; k++) {
                    if ("TIMER".equals(holderWaits.get(k).cause)) {
                        sleepIndex = k;
                    }
                }
                if (sleepIndex < 1) {
                    continue;
                }
                WaitInterval sleep = holderWaits.get(sleepIndex);
                /*
                 * The holder can only take the lock once it runs: woken, it may
                 * first wait for a CPU (about 1.7 ms per round on batch_server's
                 * shared CPU), which is not lock-hold time. The hold starts at
                 * its first running moment after the wake-up.
                 */
                long wokenAt = holderWaits.get(sleepIndex - 1).end;
                long holdStart = firstRunningAtOrAfter(running, wokenAt);
                if (holdStart < 0 || holdStart > sleep.start || release.end < sleep.end) {
                    continue;
                }
                holds.add(new long[] {holdStart, release.end});
                sleeps.add(sleep.end - sleep.start);
            }
            if (holds.isEmpty()) {
                return;
            }
            long[] runningNs = perWindowOverlap(holds, running);
            long[] waitingNs = perWindowOverlap(holds, waiting);
            List<Long> holdLengths = new ArrayList<>();
            List<Long> outside = new ArrayList<>();
            long runningTotal = 0;
            long waitingTotal = 0;
            for (int i = 0; i < holds.size(); i++) {
                long length = holds.get(i)[1] - holds.get(i)[0];
                holdLengths.add(length);
                outside.add(Math.max(0, length - sleeps.get(i)));
                runningTotal += runningNs[i];
                waitingTotal += waitingNs[i];
            }
            int n = holds.size();
            JsonObject data = new JsonObject();
            data.addProperty("holder_tid", holder);
            data.addProperty("holder_name", name(holder));
            data.addProperty("waiter_tid", bottleneck);
            data.addProperty("rounds", n);
            data.addProperty("hold_mean_ms", mean(holdLengths) / 1_000_000.0);
            data.addProperty("hold_median_ms", medianOf(holdLengths) / 1_000_000.0);
            data.addProperty("sleep_mean_ms", mean(sleeps) / 1_000_000.0);
            data.addProperty("hold_without_sleep_mean_ms", mean(outside) / 1_000_000.0);
            data.addProperty("hold_without_sleep_median_ms", medianOf(outside) / 1_000_000.0);
            data.addProperty("running_in_hold_per_round_ms", runningTotal / (double) n / 1_000_000.0);
            data.addProperty("waiting_for_cpu_in_hold_per_round_ms", waitingTotal / (double) n / 1_000_000.0);
            JsonArray caveats = new JsonArray();
            caveats.add("Inferred: the hold is taken from the holder's first moment on a CPU after it is woken (it cannot take "
                    + "the lock before it runs) to its wake-up of the waiting thread; a kernel trace does not record the "
                    + "lock's acquire and release themselves.");
            caveats.add("The estimate assumes only the sleep moves out of the lock; whatever work the holder does around it "
                    + "stays inside.");
            fFindings.add(finding("process.lock_hold", fAbout, "blocked", String.format(Locale.ROOT,
                    "TID %d (%s) holds the lock TID %d waits for for about %.3f ms per round (mean over %d rounds; median %.3f ms): "
                            + "from when it first runs after being woken, through a %.3f ms sleep, to its wake-up of TID %d. Doing the sleep (the slow "
                            + "write-back) outside the lock would leave only its work outside the sleep inside the lock: about "
                            + "%.3f ms per round (median %.3f ms; it runs %.3f ms and waits %.3f ms for a CPU in that time).",
                    holder, name(holder), bottleneck, mean(holdLengths) / 1_000_000.0, n, medianOf(holdLengths) / 1_000_000.0,
                    mean(sleeps) / 1_000_000.0, bottleneck, mean(outside) / 1_000_000.0, medianOf(outside) / 1_000_000.0,
                    runningTotal / (double) n / 1_000_000.0, waitingTotal / (double) n / 1_000_000.0),
                    fWin, "tracecompass.execution_graph+state_system", data, "medium", caveats));
        }

        /** Start of the first running interval that starts at or after {@code time}, or -1. */
        private static long firstRunningAtOrAfter(List<long[]> running, long time) {
            int low = 0;
            int high = running.size();
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (running.get(mid)[0] < time) {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            return low < running.size() ? running.get(low)[0] : -1;
        }

        /** Per window: total overlap with sorted, non-overlapping intervals. */
        private static long[] perWindowOverlap(List<long[]> windows, List<long[]> intervals) {
            long[] out = new long[windows.size()];
            int j = 0;
            for (int i = 0; i < windows.size(); i++) {
                long ws = windows.get(i)[0];
                long we = windows.get(i)[1];
                while (j < intervals.size() && intervals.get(j)[1] <= ws) {
                    j++;
                }
                for (int k = j; k < intervals.size() && intervals.get(k)[0] < we; k++) {
                    long s = Math.max(ws, intervals.get(k)[0]);
                    long e = Math.min(we, intervals.get(k)[1]);
                    if (e > s) {
                        out[i] += e - s;
                    }
                }
            }
            return out;
        }

        /** Per window: the latest end of the intervals inside it (absolute ns), or -1. */
        private static long[] perWindowLastEnd(List<long[]> windows, List<long[]> intervals) {
            long[] out = new long[windows.size()];
            java.util.Arrays.fill(out, -1);
            int j = 0;
            for (int i = 0; i < windows.size(); i++) {
                long ws = windows.get(i)[0];
                long we = windows.get(i)[1];
                while (j < intervals.size() && intervals.get(j)[1] <= ws) {
                    j++;
                }
                for (int k = j; k < intervals.size() && intervals.get(k)[0] < we; k++) {
                    long e = Math.min(we, intervals.get(k)[1]);
                    if (e > ws) {
                        out[i] = Math.max(out[i], e);
                    }
                }
            }
            return out;
        }

        /** What {@code tid} was doing inside {@code windows}: its states, and what ended its waits there. */
        private JsonObject chainStep(int tid, List<long[]> windows, List<long[]> status, List<WaitInterval> waits) {
            long within = 0;
            for (long[] window : windows) {
                within += window[1] - window[0];
            }
            long running = 0;
            long waitingCpu = 0;
            for (long[] interval : status) {
                long overlap = overlap(windows, interval[0], interval[1]);
                if (interval[2] == 1) {
                    running += overlap;
                } else if (interval[2] == 2) {
                    waitingCpu += overlap;
                }
            }
            Map<String, Long> byCause = new HashMap<>();
            Map<String, Long> syscallByCause = new HashMap<>();
            Map<String, String> syscallOf = new HashMap<>();
            long blocked = 0;
            for (WaitInterval wait : waits) {
                long overlap = overlap(windows, wait.start, wait.end);
                if (overlap <= 0) {
                    continue;
                }
                blocked += overlap;
                byCause.merge(wait.cause, overlap, Long::sum);
                if (overlap > syscallByCause.getOrDefault(wait.cause, 0L)) {
                    syscallByCause.put(wait.cause, overlap);
                    String syscall = syscallAt(tid, wait.start);
                    if (syscall != null) {
                        syscallOf.put(wait.cause, syscall);
                    }
                }
            }
            String dominantCause = byCause.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
            String dominantState = running >= waitingCpu && running >= blocked ? "running"
                    : waitingCpu >= blocked ? "waiting_for_cpu" : "blocked";
            JsonObject step = new JsonObject();
            step.addProperty("tid", tid);
            step.addProperty("name", name(tid));
            step.addProperty("within_ms", within / 1_000_000.0);
            step.addProperty("windows", windows.size());
            step.addProperty("running_ms", running / 1_000_000.0);
            step.addProperty("waiting_for_cpu_ms", waitingCpu / 1_000_000.0);
            step.addProperty("blocked_ms", blocked / 1_000_000.0);
            step.addProperty("dominant_state", dominantState);
            JsonArray causes = new JsonArray();
            byCause.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(5).forEach(entry -> {
                JsonObject item = new JsonObject();
                item.addProperty("woken_by", describeCause(entry.getKey()));
                item.addProperty("ms", entry.getValue() / 1_000_000.0);
                if (syscallOf.containsKey(entry.getKey())) {
                    item.addProperty("system_call", syscallOf.get(entry.getKey()));
                }
                causes.add(item);
            });
            step.add("blocked_until_woken_by", causes);
            if (dominantCause != null && "blocked".equals(dominantState)) {
                step.addProperty("dominant_wait_cause", dominantCause);
                if (dominantCause.startsWith("tid:")) {
                    int waker = Integer.parseInt(dominantCause.substring(4));
                    step.addProperty("woken_by_tid", waker);
                    step.addProperty("woken_by_name", name(waker));
                }
                if (syscallOf.containsKey(dominantCause)) {
                    step.addProperty("system_call", syscallOf.get(dominantCause));
                }
            }
            double perWindow = windows.isEmpty() ? 0 : 1.0 / windows.size() / 1_000_000.0;
            step.addProperty("summary", String.format(Locale.ROOT,
                    "per wait on average: running %.3f ms, waiting for a CPU %.3f ms, blocked %.3f ms%s",
                    running * perWindow, waitingCpu * perWindow, blocked * perWindow,
                    dominantCause != null && "blocked".equals(dominantState)
                            ? (syscallOf.containsKey(dominantCause) ? " in " + syscallOf.get(dominantCause) : "")
                                    + " until woken by " + describeCause(dominantCause)
                            : ""));
            step.addProperty("dominant_state_text", "running".equals(dominantState)
                    ? "its own CPU work (running)" : "waiting_for_cpu".equals(dominantState)
                            ? "CPU contention (ready to run, waiting for a CPU)" : "blocked");
            return step;
        }

        private String syscallAt(int tid, long ts) {
            ITmfStateSystem ss = fKernel.getStateSystem();
            if (ss == null || fHistory == null) {
                return null;
            }
            int quark = ss.optQuarkAbsolute("Threads", String.valueOf(tid), "System_call");
            if (quark == ITmfStateSystem.INVALID_ATTRIBUTE) {
                return null;
            }
            Object value = fHistory.valueAt(quark, Math.max(ts, ss.getStartTime()));
            return value instanceof String ? (String) value : null;
        }

        private History fHistory;

        /** The process's threads' state and system call over the window, loaded once in one sweep. */
        private History processHistory(Collection<Integer> tids) {
            if (fHistory == null) {
                ITmfStateSystem ss = fKernel.getStateSystem();
                List<Integer> quarks = new ArrayList<>();
                if (ss != null) {
                    for (int tid : tids) {
                        quarks.add(ss.optQuarkAbsolute("Threads", String.valueOf(tid)));
                        quarks.add(ss.optQuarkAbsolute("Threads", String.valueOf(tid), "System_call"));
                    }
                }
                fHistory = History.load(ss, quarks, fWindow.start, fWindow.end);
            }
            return fHistory;
        }

        private int threadQuark(int tid) {
            ITmfStateSystem ss = fKernel.getStateSystem();
            return ss == null ? ITmfStateSystem.INVALID_ATTRIBUTE : ss.optQuarkAbsolute("Threads", String.valueOf(tid));
        }

        /** Total overlap of [start, end) with sorted, non-overlapping windows. */
        private static long overlap(List<long[]> windows, long start, long end) {
            long total = 0;
            for (long[] clipped : clip(windows, start, end)) {
                total += clipped[1] - clipped[0];
            }
            return total;
        }

        private static List<long[]> clip(List<long[]> windows, long start, long end) {
            List<long[]> result = new ArrayList<>();
            int low = 0;
            int high = windows.size();
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (windows.get(mid)[1] <= start) {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            for (int i = low; i < windows.size() && windows.get(i)[0] < end; i++) {
                long s = Math.max(start, windows.get(i)[0]);
                long e = Math.min(end, windows.get(i)[1]);
                if (e > s) {
                    result.add(new long[] {s, e});
                }
            }
            return result;
        }

        private void addBottleneck(String processName, Map<Integer, Map<String, Long>> split, Map<Integer, Long> alive,
                Map<Integer, Map<String, Wait>> waits) {
            Set<Integer> tids = split.keySet();
            long totalWait = 0;
            Map<String, Long> byCause = new HashMap<>();
            for (Map<String, Wait> causes : waits.values()) {
                for (Map.Entry<String, Wait> entry : causes.entrySet()) {
                    totalWait += entry.getValue().ns;
                    byCause.merge(entry.getKey(), entry.getValue().ns, Long::sum);
                }
            }
            long waitingForCpu = split.values().stream()
                    .mapToLong(states -> states.getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L)).sum();
            long aliveTotal = alive.values().stream().mapToLong(Long::longValue).sum();

            // How long the other threads of the process waited on each of its threads.
            Map<Integer, Long> waitedOn = new HashMap<>();
            waits.forEach((waiter, causes) -> causes.forEach((cause, wait) -> {
                if (cause.startsWith("tid:")) {
                    int waker = Integer.parseInt(cause.substring(4));
                    if (waker != waiter && tids.contains(waker)) {
                        waitedOn.merge(waker, wait.ns, Long::sum);
                    }
                }
            }));
            Integer top = waitedOn.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
            String topCause = byCause.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);

            JsonObject data = new JsonObject();
            data.addProperty("total_wait_ms", totalWait / 1_000_000.0);
            data.addProperty("waiting_for_cpu_ms", waitingForCpu / 1_000_000.0);
            data.addProperty("alive_ms", aliveTotal / 1_000_000.0);
            JsonArray ranking = new JsonArray();
            long allWait = totalWait;
            waitedOn.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).forEach(entry -> {
                JsonObject item = new JsonObject();
                item.addProperty("tid", entry.getKey());
                item.addProperty("name", name(entry.getKey()));
                long othersWait = allWait - waits.getOrDefault(entry.getKey(), Map.of()).values().stream()
                        .mapToLong(wait -> wait.ns).sum();
                item.addProperty("others_waited_ms", entry.getValue() / 1_000_000.0);
                item.addProperty("percent_of_others_wait", othersWait == 0 ? 0 : entry.getValue() * 100.0 / othersWait);
                ranking.add(item);
            });
            data.add("threads_waited_on", ranking);

            String claim;
            String confidence;
            Integer chainWaiter = null;
            Wait chainWait = null;
            double topPercent = ranking.size() == 0 ? 0 : ranking.get(0).getAsJsonObject().get("percent_of_others_wait").getAsDouble();
            if (waitingForCpu > totalWait && waitingForCpu * 5 > aliveTotal) {
                data.addProperty("verdict", "cpu_contention");
                claim = String.format(Locale.ROOT,
                        "No thread of %s holds up the others as much as CPU contention does: its threads spent %.3f ms ready to run but waiting for a CPU, more than the %.3f ms they spent blocked.",
                        processName, waitingForCpu / 1_000_000.0, totalWait / 1_000_000.0);
                confidence = "medium";
            } else if (top != null && topPercent >= 30) {
                Map<String, Long> own = split.get(top);
                long ownAlive = alive.get(top);
                long ownRunning = own.getOrDefault("RUNNING_USER_MODE", 0L) + own.getOrDefault("RUNNING_SYSTEM_CALL", 0L);
                long ownBlocked = own.getOrDefault("BLOCKED", 0L);
                String ownCause = waits.getOrDefault(top, Map.of()).entrySet().stream()
                        .max((a, b) -> Long.compare(a.getValue().ns, b.getValue().ns))
                        .map(entry -> describeCause(entry.getKey())).orElse(null);
                data.addProperty("verdict", "bottleneck_thread");
                data.addProperty("bottleneck_tid", top);
                data.addProperty("bottleneck_name", name(top));
                data.addProperty("bottleneck_percent_of_others_wait", topPercent);
                data.addProperty("bottleneck_running_percent", ownRunning * 100.0 / ownAlive);
                data.addProperty("bottleneck_blocked_percent", ownBlocked * 100.0 / ownAlive);
                if (ownCause != null) {
                    data.addProperty("bottleneck_mostly_waits_on", ownCause);
                }
                /*
                 * A thread the others wait on holds them up only if it cannot keep up: busy (running or
                 * waiting for a CPU) most of its time. One that is mostly blocked itself is passing on a
                 * pace set elsewhere (its own input, a timer), so it does not hold the program up.
                 */
                long ownWaitingCpu = own.getOrDefault("RUNNABLE_WAITING_FOR_CPU", 0L);
                double busyPercent = (ownRunning + ownWaitingCpu) * 100.0 / ownAlive;
                String impact = busyPercent >= 75 ? "significant" : busyPercent >= 40 ? "minor" : "negligible";
                data.addProperty("bottleneck_busy_percent", busyPercent);
                data.addProperty("impact", impact);
                claim = String.format(Locale.ROOT,
                        "The threads of %s wait on TID %d (%s) most: %.1f%% of the time the other threads waited ended with a wake-up from it (%.3f ms). "
                                + "TID %d itself was running %.1f%% and blocked %.1f%% of its time%s. %s",
                        processName, top, name(top), topPercent, waitedOn.get(top) / 1_000_000.0, top,
                        ownRunning * 100.0 / ownAlive, ownBlocked * 100.0 / ownAlive,
                        ownCause == null ? "" : ", mostly until woken by " + ownCause,
                        "significant".equals(impact)
                                ? String.format(Locale.ROOT, "It is busy %.1f%% of its time, so it cannot keep up: it is the "
                                        + "bottleneck (a significant hold-up).", busyPercent)
                                : String.format(Locale.ROOT, "It is busy only %.1f%% of its time, so it keeps up with its work and "
                                        + "passes on a pace set elsewhere%s: a %s hold-up, not a bottleneck.", busyPercent,
                                        ownCause == null ? "" : " (" + ownCause + ")", impact));
                confidence = topPercent >= 50 ? "high" : "medium";
                // The thread that waited longest on the bottleneck: its longest such wait becomes the example chain.
                long most = -1;
                for (Map.Entry<Integer, Map<String, Wait>> entry : waits.entrySet()) {
                    Wait wait = entry.getValue().get("tid:" + top);
                    if (entry.getKey() != top.intValue() && wait != null && wait.ns > most) {
                        most = wait.ns;
                        chainWaiter = entry.getKey();
                        chainWait = wait;
                    }
                }
            } else if (topCause != null && !topCause.startsWith("tid:")) {
                data.addProperty("verdict", "external_" + topCause.toLowerCase(Locale.ROOT));
                claim = String.format(Locale.ROOT,
                        "No thread of %s is a bottleneck for the others: most of their waiting (%.1f%%) ended with %s, not with another thread%s.",
                        processName, byCause.get(topCause) * 100.0 / Math.max(1, totalWait), describeCause(topCause),
                        "TIMER".equals(topCause) ? " (they mostly sleep or time out, i.e. they are idle by design)" : "");
                confidence = "medium";
            } else if (topCause != null) {
                int waker = Integer.parseInt(topCause.substring(4));
                data.addProperty("verdict", tids.contains(waker) ? "no_single_bottleneck" : "external_thread");
                data.addProperty("main_waker_tid", waker);
                claim = tids.contains(waker)
                        ? String.format(Locale.ROOT,
                                "No single thread of %s dominates: the thread waited on most (TID %d) accounts for only %.1f%% of the others' waiting.",
                                processName, waker, topPercent)
                        : String.format(Locale.ROOT,
                                "The threads of %s mostly waited on a thread outside the process: TID %d (%s), %.1f%% of their waiting.",
                                processName, waker, name(waker), byCause.get(topCause) * 100.0 / Math.max(1, totalWait));
                confidence = "medium";
            } else {
                data.addProperty("verdict", "no_waiting");
                claim = String.format(Locale.ROOT, "The threads of %s did not wait on each other in this window.", processName);
                confidence = "high";
            }
            JsonArray caveats = new JsonArray();
            caveats.add("'Waited on' counts the waits a thread ended by waking the waiter; a thread that sleeps while others "
                    + "wait for it is still the bottleneck even if it is not busy (its sleep is the work the others wait for).");
            fFindings.add(finding("process.bottleneck", fAbout, "blocked", claim, fWin, "tracecompass.execution_graph",
                    data, confidence, caveats));

            if (chainWaiter != null && chainWait != null && chainWait.longestEnd > chainWait.longestStart) {
                JsonObject criticalPath = collectCriticalPath(fTrace, chainWaiter, chainWait.longestStart, chainWait.longestEnd + 2);
                JsonObject chainData = new JsonObject();
                chainData.addProperty("waiter_tid", chainWaiter);
                chainData.addProperty("example_kind", "longest");
                chainData.addProperty("interval_ms", (chainWait.longestEnd - chainWait.longestStart) / 1_000_000.0);
                chainData.addProperty("interval_start_offset_ms", (chainWait.longestStart - fTrace.getStartTime().toNanos()) / 1_000_000.0);
                chainData.addProperty("available", UnifiedExplainer.bool(criticalPath, "available"));
                JsonObject chain = UnifiedExplainer.obj(criticalPath, "chain");
                JsonArray chainCaveats = new JsonArray();
                if (chain != null) {
                    chainData.add("direct_waker", chain.get("direct_waker"));
                    chainData.add("root_activity", chain.get("root_activity"));
                    chainData.add("segments", chain.get("segments"));
                    if (chain.has("warning")) {
                        chainCaveats.add(chain.get("warning"));
                    }
                }
                fFindings.add(finding("process.example_chain", fAbout, "blocked",
                        UnifiedExplainer.bool(criticalPath, "available")
                                ? "Example: TID " + chainWaiter + "'s longest wait on TID " + top + ". "
                                        + summarizeBlockedGap(chainWaiter, criticalPath)
                                : "Critical path not available for the example wait: " + UnifiedExplainer.str(criticalPath, "reason"),
                        fWin, "tracecompass.critical_path", chainData, "high", chainCaveats));
            }
        }
    }

    /** "PID 1234" / "process 1234" names a process directly. */
    static final Pattern PID_PATTERN =
            Pattern.compile("(?i)\\b(?:pid|process)\\s*[:#]?\\s*(\\d+)\\b");

    /** Words of a question that are never process or thread names. */
    static final Set<String> NOT_NAMES = Set.of("what", "which", "does", "did", "this", "that", "the",
            "thread", "threads", "process", "processes", "trace", "time", "between", "and", "with", "from", "why",
            "how", "who", "when", "where", "run", "runs", "ran", "slow", "bottleneck", "cpu", "cpus", "its", "for",
            "are", "was", "were", "has", "have", "doing", "spend", "spent", "most", "all", "any", "one");

    /**
     * Resolves a process or thread named in a question with no TID:
     * "PID 1234", or a word equal to a process's name ("batch_server"), or
     * to a thread's own name ("the reader thread"). Kernel names are cut to
     * 15 characters, so a longer word matches its first 15. Returns
     * {"pid": ...} or {"tid": ...} with what matched, or null.
     */
    static JsonObject resolveNamedTarget(String question, ITmfTrace trace) {
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        if (kernel == null) {
            return null;
        }
        kernel.schedule();
        kernel.waitForCompletion();
        long end = trace.getEndTime().toNanos();
        JsonObject result = new JsonObject();
        Matcher pidMatch = PID_PATTERN.matcher(question);
        if (pidMatch.find()) {
            int pid = Integer.parseInt(pidMatch.group(1));
            result.addProperty("pid", pid);
            result.addProperty("name", KernelThreadInformationProvider.getExecutableName(kernel, pid, end));
            result.addProperty("matched", pidMatch.group());
            return result;
        }
        Set<String> words = new java.util.LinkedHashSet<>();
        Matcher wordMatch = Pattern.compile("[A-Za-z0-9_.~#-]{3,}").matcher(question);
        while (wordMatch.find()) {
            String word = wordMatch.group().toLowerCase(Locale.ROOT).replaceAll("[.?!,:;]+$", "");
            if (word.length() >= 3 && !NOT_NAMES.contains(word) && !word.chars().allMatch(Character::isDigit)) {
                words.add(word);
            }
        }
        if (words.isEmpty()) {
            return null;
        }
        Map<String, Map<Integer, Integer>> processes = new HashMap<>(); // word -> pid -> thread count
        Map<String, Set<Integer>> threads = new HashMap<>();             // word -> tids named so
        Map<Integer, Integer> threadCount = new HashMap<>();
        Map<Integer, String> processName = new HashMap<>();
        long start = trace.getStartTime().toNanos();
        for (Integer tid : KernelThreadInformationProvider.getThreadIds(kernel)) {
            Integer pid = ProcessExplainer.pidOfThread(kernel, tid, start, end);
            int owner = pid == null ? tid : pid;
            threadCount.merge(owner, 1, Integer::sum);
            String name = KernelThreadInformationProvider.getExecutableName(kernel, tid);
            if (name == null) {
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            if (owner == tid) {
                processName.put(owner, name);
            }
            for (String word : words) {
                if (word.equals(lower) || (lower.length() == 15 && word.startsWith(lower))) {
                    if (owner == tid) {
                        processes.computeIfAbsent(word, k -> new HashMap<>()).put(owner, 0);
                    } else {
                        threads.computeIfAbsent(word, k -> new java.util.TreeSet<>()).add(tid);
                    }
                }
            }
        }
        for (String word : words) {
            Map<Integer, Integer> pids = processes.get(word);
            if (pids != null && !pids.isEmpty()) {
                int best = pids.keySet().stream()
                        .max((a, b) -> Integer.compare(threadCount.getOrDefault(a, 0), threadCount.getOrDefault(b, 0)))
                        .orElseThrow();
                result.addProperty("pid", best);
                result.addProperty("name", processName.get(best));
                result.addProperty("matched", word);
                if (pids.size() > 1) {
                    JsonArray others = new JsonArray();
                    pids.keySet().stream().filter(pid -> pid != best).sorted().forEach(others::add);
                    result.add("other_processes_with_this_name", others);
                }
                return result;
            }
        }
        for (String word : words) {
            Set<Integer> tids = threads.get(word);
            if (tids != null && tids.size() == 1) {
                int tid = tids.iterator().next();
                result.addProperty("tid", tid);
                result.addProperty("name", KernelThreadInformationProvider.getExecutableName(kernel, tid));
                result.addProperty("matched", word);
                return result;
            }
        }
        return null;
    }

    /**
     * Words that make a question about what a thread does (its operations,
     * role, activity) rather than about where its time went.
     */
    static final Pattern DESCRIBE_INTENT_PATTERN =
            Pattern.compile(
                    "(?i)\\b(what\\s+(does|did|is|was)\\b[^?]*\\b(do|doing)\\b|operations?|"
                    + "activit(y|ies)|behaviou?r|purpose|responsible|role|timeline|"
                    + "sequence|steps|describe)\\b");

    /**
     * Words that say one occurrence deviated from the thread's normal
     * behaviour, which is what the late-cycle window finder looks for. Plain
     * "slow" is not enough: "why is thread X slow" is about all of its time.
     */
    static final Pattern DEVIATION_PATTERN =
            Pattern.compile(
                    "(?i)\\b(late|delayed|delay|jitter|deadline|periodic(ally)?|period|"
                    + "every\\s+\\d+(\\.\\d+)?\\s*(ms|milliseconds?|us|microseconds?|s|seconds?)|"
                    + "once|one\\s+(cycle|request|iteration|run|call|of\\s+(them|its))|sometimes|"
                    + "occasionally|spikes?|outliers?|missed|unusual(ly)?|abnormal(ly)?|"
                    + "than\\s+(the\\s+)?(rest|usual|normal|others|other\\s+\\w+))\\b");

    /**
     * The query planner (unified_architecture_design.pdf, step 1): turns a
     * question into the thread, the windows to explain and the intent, from
     * the meaning of the question rather than from which feature's keyword it
     * happens to contain. Deterministic; {@link #json} records each decision
     * and the words behind it.
     */
    static final class QueryPlan {
        /** The thread asked about, or null for a question about a process or the whole trace. */
        final Integer tid;
        /** The process asked about (process scope), or null. */
        final Integer pid;
        /** True: the question asks what the thread does; false: where its time went. */
        final boolean describe;
        final boolean findLateCycles;
        final TimeWindow userWindow;
        final Long expectedPeriodNs;
        final JsonObject json = new JsonObject();

        private QueryPlan(String question, Integer tid, Integer pid, ITmfTrace trace, boolean oneOffDelay) {
            this.tid = tid;
            this.pid = tid == null ? pid : null;
            Matcher describeMatch = DESCRIBE_INTENT_PATTERN.matcher(question);
            Matcher deviationMatch = DEVIATION_PATTERN.matcher(question);
            boolean describes = describeMatch.find();
            boolean deviates = deviationMatch.find();
            boolean wholeTrace = tid == null && this.pid == null;
            boolean process = tid == null && this.pid != null;
            this.describe = wholeTrace || (describes && !deviates);
            // The thread finder may recognize a one-off delay the words below miss ("one request was slower").
            this.findLateCycles = !wholeTrace && !process && (!this.describe && deviates || oneOffDelay);
            this.userWindow = parseTimeWindow(question,
                    trace.getStartTime().toNanos(), trace.getEndTime().toNanos());
            this.expectedPeriodNs = extractExpectedPeriodNs(question);

            json.addProperty("scope", wholeTrace ? "trace" : process ? "process" : "thread");
            json.addProperty("tid", tid);
            if (process) {
                json.addProperty("pid", this.pid);
            }
            json.addProperty("intent", wholeTrace ? "describe_trace"
                    : process ? (describes && !deviates ? "describe_process" : "explain_process")
                    : describe ? "describe_activity" : "explain_time");
            json.addProperty("describe_words", describes ? describeMatch.group() : null);
            json.addProperty("deviation_words", deviates ? deviationMatch.group() : null);
            json.addProperty("find_late_cycles", findLateCycles);
            if (oneOffDelay && !(deviates && !this.describe)) {
                json.addProperty("late_cycles_from", "thread_finder symptom one_off_delay");
            }
            if (userWindow != null) {
                json.addProperty("user_window", userWindow.interpretation);
            }
            if (expectedPeriodNs != null) {
                json.addProperty("expected_period_ns", expectedPeriodNs);
            }
        }

        static QueryPlan of(String question, Integer tid, ITmfTrace trace) {
            return new QueryPlan(question, tid, null, trace, false);
        }

        static QueryPlan of(String question, Integer tid, Integer pid, ITmfTrace trace) {
            return new QueryPlan(question, tid, pid, trace, false);
        }

        /** @param oneOffDelay the thread finder found a one-off delay: look for late cycles */
        static QueryPlan of(String question, Integer tid, Integer pid, ITmfTrace trace, boolean oneOffDelay) {
            return new QueryPlan(question, tid, pid, trace, oneOffDelay);
        }
    }

    /**
     * The late-cycle window finder: TMLL's z-score over the thread's period.
     * Never throws: a failure becomes an "unavailable" scan that the
     * explainer reports as a finding.
     */
    JsonObject findLateCycles(QueryPlan plan) {
        try {
            return JsonParser.parseString(
                    callTmllPeriodicJitter(plan.tid, plan.expectedPeriodNs))
                    .getAsJsonObject();
        } catch (Exception exception) {
            JsonObject stageA = new JsonObject();
            stageA.addProperty("available", false);
            stageA.addProperty("reason", exception.getMessage() != null
                    ? exception.getMessage() : exception.toString());
            JsonObject jitter = new JsonObject();
            jitter.add("stage_a", stageA);
            JsonObject failed = new JsonObject();
            failed.add("periodic_jitter", jitter);
            return failed;
        }
    }

    /**
     * Adds the TMLL evidence the explainers do not compute themselves: the
     * thread's syscall mix over the whole trace, and messages matched to
     * other hosts. Everything else TMLL reports (state breakdown, blocked
     * syscalls, file I/O) is covered more exactly by the explainers.
     */
    static void addTmllEvidence(JsonArray findings, JsonObject analysis, ITmfTrace trace) {
        if (analysis == null) {
            return;
        }
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();
        JsonObject window = new JsonObject();
        window.addProperty("source", "whole_trace");
        window.addProperty("start_ns", start);
        window.addProperty("end_ns", end);
        window.addProperty("start_offset_ms", 0.0);
        window.addProperty("end_offset_ms", (end - start) / 1_000_000.0);

        JsonObject frequency = UnifiedExplainer.obj(analysis, "syscall_frequency");
        if (UnifiedExplainer.bool(frequency, "available")) {
            JsonArray bySyscall = UnifiedExplainer.arr(frequency, "by_syscall");
            List<String> parts = new ArrayList<>();
            JsonArray top = new JsonArray();
            for (JsonElement element : bySyscall) {
                JsonObject call = element.getAsJsonObject();
                top.add(call);
                parts.add(String.format(Locale.ROOT, "%s x%d (%.1f calls/s, %.3f ms in total)",
                        UnifiedExplainer.str(call, "system_call"),
                        UnifiedExplainer.num(call, "call_count", 0L),
                        UnifiedExplainer.dbl(call, "calls_per_second", 0),
                        UnifiedExplainer.dbl(call, "total_duration_ms", 0)));
                if (top.size() == 5) {
                    break;
                }
            }
            JsonObject data = new JsonObject();
            data.add("total_call_count", frequency.get("total_call_count"));
            data.add("span_seconds", frequency.get("span_seconds"));
            data.add("top_syscalls", top);
            JsonArray caveats = new JsonArray();
            caveats.add("Total time per system call includes time the thread spent blocked inside it.");
            JsonObject scan = UnifiedExplainer.obj(analysis, "syscall_latency_correlation");
            boolean partial = (scan != null && scan.has("table_scan_complete") && !UnifiedExplainer.bool(scan, "table_scan_complete"))
                    || (frequency.has("table_scan_complete") && !UnifiedExplainer.bool(frequency, "table_scan_complete"));
            if (partial) {
                caveats.add(String.format(Locale.ROOT,
                        "PARTIAL: the Trace Server table scan stopped at its limit (%s rows), so it covers only part of the "
                                + "trace and these counts are lower bounds, not totals. Say so when quoting them.",
                        String.valueOf(frequency.get("table_rows_scanned"))));
                data.addProperty("partial", true);
            }
            findings.add(finding("syscalls.frequency", "whole_trace", null,
                    String.format(Locale.ROOT, "Over the whole trace the thread made %d system calls; most frequent: %s.",
                            UnifiedExplainer.num(frequency, "total_call_count", 0L), String.join(", ", parts)),
                    window, "tmll.syscall_latency_table", data, "high", caveats));
        }

        JsonObject network = UnifiedExplainer.obj(analysis, "cross_host_messaging");
        if (UnifiedExplainer.bool(network, "available") && UnifiedExplainer.num(network, "message_count", 0L) > 0) {
            JsonObject data = network.deepCopy();
            data.remove("interpretation_note");
            findings.add(finding("network.cross_host", "whole_trace", null,
                    String.format(Locale.ROOT,
                            "%d of the thread's network messages were matched to another traced host (%s), %.3f ms in transit in total.",
                            UnifiedExplainer.num(network, "message_count", 0L),
                            String.valueOf(network.get("partner_hosts")),
                            UnifiedExplainer.dbl(network, "total_transit_ms", 0)),
                    window, "tmll.cross_host_matching", data, "medium", new JsonArray()));
        }
    }

    /** A process analysis: its findings, and what TMLL needs (bottleneck, main thread's waits on it). */
    static final class ProcessAnalysis {
        final JsonArray findings;
        final JsonObject side;

        ProcessAnalysis(JsonArray findings, JsonObject side) {
            this.findings = findings;
            this.side = side;
        }

        ProcessAnalysis copy() {
            return new ProcessAnalysis(findings.deepCopy(), side.deepCopy());
        }
    }

    /** Recent process analyses, by trace, PID, window and describe; a describe analysis also serves the other. */
    static final Map<String, ProcessAnalysis> PROCESS_CACHE = java.util.Collections.synchronizedMap(
            new LinkedHashMap<String, ProcessAnalysis>(16, 0.75f, true) {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, ProcessAnalysis> eldest) {
                    return size() > 8;
                }
            });

    static ProcessAnalysis processAnalysis(ITmfTrace trace, int pid, ExplainWindow window, boolean describe) {
        String key = trace.getPath() + "|" + pid + "|" + window.start + "|" + window.end + "|";
        ProcessAnalysis cached = PROCESS_CACHE.get(key + describe);
        if (cached == null && !describe) {
            cached = PROCESS_CACHE.get(key + true);
        }
        if (cached != null) {
            return cached.copy();
        }
        JsonObject side = new JsonObject();
        JsonArray findings = ProcessExplainer.explain(trace, pid, window, describe, side);
        ProcessAnalysis analysis = new ProcessAnalysis(findings, side);
        PROCESS_CACHE.put(key + describe, analysis);
        return analysis.copy();
    }

    /**
     * The thread's part in its process's wait chain (the process analysis
     * behind "which thread is the bottleneck"): if the main thread waits on
     * it, or on a thread that waits on it, what it was doing per such wait
     * and what ended its own waits; and, for a thread that sleeps while
     * another waits on its futex, that it most likely holds that lock.
     */
    static void addProcessRole(JsonArray findings, ProcessAnalysis analysis, int tid) {
        JsonObject bottleneck = null;
        JsonObject whatIf = null;
        for (JsonElement element : analysis.findings) {
            JsonObject finding = element.getAsJsonObject();
            String id = UnifiedExplainer.str(finding, "id");
            if ("process.round_profile".equals(id) || "process.lock_hold".equals(id)) {
                findings.add(finding.deepCopy());
            }
            if ("process.bottleneck".equals(id)) {
                bottleneck = finding;
            } else if ("process.what_if".equals(id)) {
                whatIf = finding;
            }
        }
        if (bottleneck == null) {
            return;
        }
        JsonObject data = UnifiedExplainer.obj(UnifiedExplainer.obj(bottleneck, "evidence"), "data");
        if (!"main_thread_wait_chain".equals(UnifiedExplainer.str(data, "method"))) {
            return;
        }
        JsonArray chain = UnifiedExplainer.arr(data, "chain");
        int position = -1;
        for (int i = 0; i < chain.size(); i++) {
            if (chain.get(i).getAsJsonObject().get("tid").getAsInt() == tid) {
                position = i;
            }
        }
        int main = data.get("main_tid").getAsInt();
        String mainName = UnifiedExplainer.str(data, "main_name");
        JsonObject role = new JsonObject();
        role.addProperty("tid", tid);
        role.addProperty("main_tid", main);
        role.addProperty("process_name", mainName);
        role.add("process_chain", chain);
        role.add("process_bottleneck_claim", bottleneck.get("claim"));
        String claim;
        if (position < 0) {
            role.addProperty("in_chain", false);
            claim = String.format(Locale.ROOT,
                    "TID %d is not on its process's wait chain: the main thread TID %d (%s) waits on TID %d (%s), not on it "
                            + "(%s).", tid, main, mainName, data.get("bottleneck_tid").getAsInt(),
                    UnifiedExplainer.str(data, "bottleneck_name"), UnifiedExplainer.str(bottleneck, "claim"));
        } else {
            JsonObject step = chain.get(position).getAsJsonObject();
            role.addProperty("in_chain", true);
            role.addProperty("position", position);
            role.add("step", step);
            String waiter = position == 0 ? "the main thread TID " + main + " (" + mainName + ")"
                    : "TID " + chain.get(position - 1).getAsJsonObject().get("tid").getAsInt() + " ("
                            + UnifiedExplainer.str(chain.get(position - 1).getAsJsonObject(), "name") + ")";
            claim = String.format(Locale.ROOT,
                    "In its process, %s waits on TID %d %d times here%s. While it waited, TID %d was, %s.",
                    waiter, tid, step.get("windows").getAsInt(),
                    position == 0 ? String.format(Locale.ROOT, " (%.1f%% of the main thread's waits on other threads), so TID %d is the process's bottleneck",
                            UnifiedExplainer.dbl(data, "bottleneck_percent_of_main_thread_waits", 0), tid) : "",
                    tid, UnifiedExplainer.str(step, "summary"));
            JsonObject whatIfData = whatIf == null ? null : UnifiedExplainer.obj(UnifiedExplainer.obj(whatIf, "evidence"), "data");
            if (whatIfData != null && whatIfData.has("likely_lock_held_while_sleeping_by_tid")
                    && whatIfData.get("likely_lock_held_while_sleeping_by_tid").getAsInt() == tid) {
                int waiterTid = whatIfData.get("bottleneck_tid").getAsInt();
                role.addProperty("likely_holds_lock_while_sleeping", true);
                claim += String.format(Locale.ROOT,
                        " Each time, TID %d's futex wait ends with a wake-up from TID %d right after TID %d's sleep, so TID %d most "
                                + "likely holds the lock TID %d waits for while it sleeps (inferred: a kernel trace does not record "
                                + "lock ownership).", waiterTid, tid, tid, tid, waiterTid);
            }
        }
        JsonArray caveats = new JsonArray();
        caveats.add("Per wait of the thread that waits on it, aggregated over all such waits; this is the recurring pattern, "
                + "not one particular wait.");
        JsonObject window = UnifiedExplainer.obj(bottleneck, "window");
        findings.add(finding("thread.process_role", "process " + main, "blocked", claim,
                window == null ? new JsonObject() : window, "tracecompass.execution_graph", role,
                role.has("likely_holds_lock_while_sleeping") ? "medium" : UnifiedExplainer.str(bottleneck, "confidence"), caveats));
    }

    /** Whether the thread explainer found the target's longest wait still going on at the end of the trace. */
    static boolean targetNeverWoken(JsonArray findings) {
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            if (!"blocked.syscalls".equals(UnifiedExplainer.str(finding, "id"))) {
                continue;
            }
            JsonArray intervals = UnifiedExplainer.arr(UnifiedExplainer.obj(UnifiedExplainer.obj(finding, "evidence"), "data"),
                    "intervals");
            if (intervals != null && intervals.size() > 0 && UnifiedExplainer.bool(intervals.get(0).getAsJsonObject(), "unfinished")) {
                return true;
            }
        }
        return false;
    }

    /** The process's waits that never ended (StuckWaits), for a thread question; nothing if none. */
    static void addStuckWaits(JsonArray findings, ITmfTrace trace, int pid, ExplainWindow window) {
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(
                trace, KernelAnalysisModule.class, KernelAnalysisModule.ID);
        ITmfStateSystem ss = kernel == null ? null : kernel.getStateSystem();
        if (ss == null) {
            return;
        }
        List<Integer> tids = ProcessExplainer.threadsOf(kernel, pid, window.start, window.end);
        List<Integer> quarks = new ArrayList<>();
        for (int tid : tids) {
            quarks.add(ss.optQuarkAbsolute("Threads", String.valueOf(tid)));
            quarks.add(ss.optQuarkAbsolute("Threads", String.valueOf(tid), "System_call"));
        }
        History history = History.load(ss, quarks, window.start, window.end);
        String processName = KernelThreadInformationProvider.getExecutableName(kernel, pid, window.end);
        StuckWaits.add(findings, trace, kernel, history, tids, tid -> {
            String name = KernelThreadInformationProvider.getExecutableName(kernel, tid, window.end);
            return name == null ? "unknown" : name;
        }, new StuckWaits.ExplainWindowView(window.start, window.end, trace.getStartTime().toNanos()),
                processWindow(window), "process " + pid, pid, processName == null ? "unknown" : processName);
    }

    static JsonObject processWindow(ExplainWindow window) {
        JsonObject win = new JsonObject();
        win.addProperty("source", window.source);
        win.addProperty("start_ns", window.start);
        win.addProperty("end_ns", window.end);
        return win;
    }

    /** TMLL's view of the bottleneck thread's system calls (Trace Server syscall tables). */
    static void addBottleneckSyscalls(JsonArray findings, JsonObject analysis, JsonObject side, ExplainWindow window) {
        if (analysis == null) {
            return;
        }
        int tid = side.get("bottleneck_tid").getAsInt();
        String name = UnifiedExplainer.str(side, "bottleneck_name");
        JsonObject data = new JsonObject();
        data.addProperty("tid", tid);
        data.addProperty("name", name);
        List<String> parts = new ArrayList<>();
        JsonObject futex = UnifiedExplainer.obj(analysis, "futex_contention");
        if (UnifiedExplainer.bool(futex, "available")) {
            JsonObject futexData = futex.deepCopy();
            futexData.remove("interpretation_note");
            data.add("futex_contention", futexData);
            parts.add(String.format(Locale.ROOT, "futex waits: %,d, %.3f ms in total (longest %.3f ms, %d distinct lock address(es))",
                    UnifiedExplainer.num(futex, "wait_count", 0L), UnifiedExplainer.dbl(futex, "total_wait_ms", 0),
                    UnifiedExplainer.dbl(futex, "longest_wait_ms", 0), UnifiedExplainer.num(futex, "distinct_lock_addresses", 0L)));
        }
        JsonObject frequency = UnifiedExplainer.obj(analysis, "syscall_frequency");
        if (UnifiedExplainer.bool(frequency, "available")) {
            JsonArray top = new JsonArray();
            List<String> calls = new ArrayList<>();
            for (JsonElement element : UnifiedExplainer.arr(frequency, "by_syscall")) {
                JsonObject call = element.getAsJsonObject();
                top.add(call);
                calls.add(String.format(Locale.ROOT, "%s x%d (%.3f ms)", UnifiedExplainer.str(call, "system_call"),
                        UnifiedExplainer.num(call, "call_count", 0L), UnifiedExplainer.dbl(call, "total_duration_ms", 0)));
                if (top.size() == 5) {
                    break;
                }
            }
            data.add("top_syscalls", top);
            parts.add("most frequent system calls: " + String.join(", ", calls));
        }
        if (parts.isEmpty()) {
            return;
        }
        JsonArray caveats = new JsonArray();
        caveats.add("These cover the whole trace, including the thread's waits for new work; the wait chain in "
                + "process.bottleneck gives the part spent while the main thread waited on it.");
        boolean partial = (futex != null && futex.has("table_scan_complete") && !UnifiedExplainer.bool(futex, "table_scan_complete"))
                || (frequency != null && frequency.has("table_scan_complete") && !UnifiedExplainer.bool(frequency, "table_scan_complete"));
        if (partial) {
            caveats.add("PARTIAL: the Trace Server table scan stopped at its row limit, so it covers only part of the trace "
                    + "and these counts are lower bounds, not totals. Say so when quoting them.");
            data.addProperty("partial", true);
        }
        findings.add(finding("process.bottleneck_syscalls", "process " + side.get("main_tid").getAsInt(), "blocked",
                String.format(Locale.ROOT, "TMLL (Trace Server syscall tables) for the bottleneck TID %d (%s): %s.",
                        tid, name, String.join("; ", parts)),
                processWindow(window), "tmll.syscall_tables", data, "high", caveats));
    }

    /** TMLL's z-score over the main thread's waits on the bottleneck: every round alike, or spikes? */
    static void addRoundConsistency(JsonArray findings, JsonObject series, JsonObject side, ExplainWindow window,
            ITmfTrace trace) {
        if (!UnifiedExplainer.bool(series, "available")) {
            return;
        }
        long traceStart = trace.getStartTime().toNanos();
        int main = side.get("main_tid").getAsInt();
        int bottleneck = side.get("bottleneck_tid").getAsInt();
        long count = UnifiedExplainer.num(series, "count", 0L);
        long outliers = UnifiedExplainer.num(series, "anomaly_count", 0L);
        JsonObject data = series.deepCopy();
        data.remove("timing_ms");
        JsonArray anomalies = new JsonArray();
        List<String> when = new ArrayList<>();
        for (JsonElement element : UnifiedExplainer.arr(series, "anomalies")) {
            JsonObject anomaly = element.getAsJsonObject().deepCopy();
            double offset = (UnifiedExplainer.num(anomaly, "timestamp_ns", traceStart) - traceStart) / 1_000_000.0;
            anomaly.addProperty("start_offset_ms", offset);
            if (anomalies.size() < 10) {
                anomalies.add(anomaly);
                when.add(String.format(Locale.ROOT, "%.3f ms at %.3f ms", UnifiedExplainer.dbl(anomaly, "value_ms", 0), offset));
            }
        }
        data.add("anomalies", anomalies);
        // A few isolated outliers do not make a constant slowdown "spiky".
        boolean consistent = outliers * 20 < count;
        data.addProperty("pattern", consistent ? "consistent" : "spikes");
        String claim = consistent
                ? String.format(Locale.ROOT,
                        "TMLL's z-score over the main thread's %d rounds (wake-up to the end of its wait on TID %d) finds them "
                                + "consistent: about %.3f ms each (median; p99 %.3f ms), so the delay happens in every round, "
                                + "not in occasional spikes.%s",
                        count, bottleneck, UnifiedExplainer.dbl(series, "median_ms", 0), UnifiedExplainer.dbl(series, "p99_ms", 0),
                        outliers == 0 ? "" : String.format(Locale.ROOT, " %d isolated round(s) stand out (%s).", outliers,
                                String.join("; ", when)))
                : String.format(Locale.ROOT,
                        "TMLL's z-score flagged %d of the main thread's %d rounds (ending with its wait on TID %d) as outliers "
                                + "(median %.3f ms, max %.3f ms): the delay comes in spikes, e.g. %s.",
                        outliers, count, bottleneck, UnifiedExplainer.dbl(series, "median_ms", 0),
                        UnifiedExplainer.dbl(series, "max_ms", 0), String.join("; ", when));
        findings.add(finding("process.round_consistency", "process " + main, "blocked", claim, processWindow(window),
                "tmll.zscore", data, "high", new JsonArray()));
    }

    String callTmllSeriesAnomalies(JsonObject side) throws Exception {
        JsonObject body = new JsonObject();
        body.add("values_ms", side.get("waits_ms"));
        body.add("timestamps_ns", side.get("waits_start_ns"));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TMLL_SERIES_ANOMALIES_URL))
                        .timeout(TMLL_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("TMLL series anomaly check failed: HTTP " + response.statusCode()
                    + "\n" + response.body());
        }
        return response.body();
    }

    static JsonObject finding(String id, String about, String state, String claim, JsonObject window,
            String analysis, JsonObject data, String confidence, JsonArray caveats) {
        JsonObject finding = new JsonObject();
        finding.addProperty("id", id);
        finding.addProperty("about", about);
        finding.addProperty("state", state);
        finding.addProperty("claim", claim);
        finding.add("window", window);
        JsonObject evidence = new JsonObject();
        evidence.addProperty("analysis", analysis);
        evidence.add("data", data);
        finding.add("evidence", evidence);
        finding.addProperty("confidence", confidence);
        finding.add("caveats", caveats);
        return finding;
    }

    static JsonObject unavailableFinding(String id, String claim) {
        JsonObject data = new JsonObject();
        data.addProperty("available", false);
        return finding(id, "whole_trace", null, claim, new JsonObject(), "n/a", data, "n/a", new JsonArray());
    }

    /**
     * Concepts to retrieve documentation for, read from the findings: the
     * system calls the thread blocked in or made most, the states that hold
     * its time, and the analyses that explained them.
     */
    static List<String> ragConcepts(JsonArray findings) {
        Set<String> concepts = new java.util.LinkedHashSet<>();
        /* The program the question is about, so its documentation (if any) is retrieved first. */
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            String id = UnifiedExplainer.str(finding, "id");
            JsonObject data = UnifiedExplainer.obj(UnifiedExplainer.obj(finding, "evidence"), "data");
            String program = "trace.workload_process".equals(id) || "process.threads".equals(id)
                    ? UnifiedExplainer.str(data, "name")
                    : "thread.process_role".equals(id) ? UnifiedExplainer.str(data, "process_name") : null;
            if (program != null && !program.isBlank() && !"unknown".equals(program)) {
                concepts.add(program + " program");
            }
        }
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            String id = UnifiedExplainer.str(finding, "id");
            JsonObject data = UnifiedExplainer.obj(UnifiedExplainer.obj(finding, "evidence"), "data");
            if ("blocked.syscalls".equals(id)) {
                String syscall = UnifiedExplainer.str(data, "longest_syscall");
                if (syscall != null) {
                    concepts.add(syscall);
                }
                concepts.add("blocked thread waiting");
            } else if ("blocked.wake_chain".equals(id)) {
                concepts.add("critical path wake-up dependency");
            } else if ("waiting.cpu_occupancy".equals(id)) {
                concepts.add("runnable waiting for CPU contention");
            } else if ("running.work".equals(id)) {
                JsonObject counts = UnifiedExplainer.obj(data, "syscall_counts");
                if (counts != null) {
                    counts.entrySet().stream()
                            .sorted((x, y) -> Long.compare(y.getValue().getAsLong(), x.getValue().getAsLong()))
                            .limit(2)
                            .forEach(entry -> concepts.add(entry.getKey()));
                }
            } else if ("running.target".equals(id) && UnifiedExplainer.num(data, "syncs_to_disk", 0L) > 0) {
                concepts.add("fsync");
            } else if ("process.bottleneck".equals(id) || "process.wait_graph".equals(id)) {
                concepts.add("critical path wake-up dependency");
            } else if ("process.bottleneck_syscalls".equals(id) && data != null && data.has("futex_contention")) {
                concepts.add("futex");
            } else if ("trace.recorded".equals(id)) {
                concepts.add("LTTng kernel trace events");
            } else if ("network.cross_host".equals(id)) {
                concepts.add("cross-host TCP message matching");
            }
        }
        return new ArrayList<>(concepts);
    }

    /** Asks the TMLL service for documentation on the question and concepts. */
    String callRagRetrieve(String question, List<String> concepts) throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("question", question);
        JsonArray list = new JsonArray();
        concepts.forEach(list::add);
        body.add("concepts", list);
        body.addProperty("limit", 6);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TMLL_RAG_RETRIEVE_URL))
                        .timeout(TMLL_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("RAG retrieval failed: HTTP " + response.statusCode() + "\n" + response.body());
        }
        return response.body();
    }

    /** Keeps each document's summary and at most 1,500 characters of fetched source. */
    static JsonArray trimDocuments(JsonArray documents) {
        JsonArray trimmed = new JsonArray();
        for (JsonElement element : documents) {
            JsonObject document = element.getAsJsonObject().deepCopy();
            String source = UnifiedExplainer.str(document, "full_source_text");
            if (source != null && source.length() > 1500) {
                document.addProperty("full_source_text", source.substring(0, 1500) + " [truncated]");
            }
            document.remove("distance");
            trimmed.add(document);
        }
        return trimmed;
    }

    /**
     * Windows for the unified explainer: the whole trace, the user's time
     * window if the question names one, and each late cycle the window finder
     * found (only run when the plan asks for it).
     */
    static List<ExplainWindow> chooseWindows(QueryPlan plan, ITmfTrace trace, JsonObject finder) {
        List<ExplainWindow> windows = new ArrayList<>();
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();
        windows.add(new ExplainWindow("whole_trace", "whole_trace", start, end, null));

        TimeWindow user = plan.userWindow;
        if (user != null && user.startNs <= user.endNs) {
            JsonObject details = new JsonObject();
            details.addProperty("interpreted_as", user.interpretation);
            windows.add(new ExplainWindow("user_window", "user", user.startNs, user.endNs, details));
        }

        JsonObject stageA = UnifiedExplainer.obj(UnifiedExplainer.obj(finder, "periodic_jitter"), "stage_a");
        if (stageA != null && UnifiedExplainer.bool(stageA, "available")) {
            JsonArray anomalies = UnifiedExplainer.arr(stageA, "anomalies");
            // Explained one by one: the cycles that stand out from the cycles around them (1.5 times or
            // more), at most 8, largest first (the detector's order); with none, the 3 largest flagged.
            // A z-score on a very regular loop flags overruns of a few percent, dozens of them.
            List<JsonObject> chosen = new ArrayList<>();
            for (JsonElement element : anomalies) {
                JsonObject late = element.getAsJsonObject();
                if (!late.has("local_delay_factor") || UnifiedExplainer.dbl(late, "local_delay_factor", 0) >= 1.5) {
                    chosen.add(late);
                }
            }
            if (chosen.isEmpty()) {
                for (int i = 0; i < Math.min(3, anomalies.size()); i++) {
                    chosen.add(anomalies.get(i).getAsJsonObject());
                }
            }
            chosen = chosen.subList(0, Math.min(8, chosen.size()));
            for (int i = 0; i < chosen.size(); i++) {
                JsonObject late = chosen.get(i);
                JsonObject details = new JsonObject();
                details.add("period_ms", late.get("observed_period_ms"));
                details.add("expected_period_ms", late.get("expected_period_ms"));
                details.add("delay_ms", late.get("delay_ms"));
                details.add("delay_factor", late.get("delay_factor"));
                for (String key : new String[] {"local_period_ms", "local_delay_ms", "local_delay_factor", "local_size"}) {
                    if (late.has(key)) {
                        details.add(key, late.get(key));
                    }
                }
                details.add("gap_kind", late.get("gap_kind"));
                details.add("activation_count", stageA.get("activation_count"));
                details.addProperty("late_cycle_count", anomalies.size());
                windows.add(new ExplainWindow("late_cycle[" + i + "]", "late_cycle",
                        UnifiedExplainer.num(late, "gap_start_timestamp_ns", start),
                        UnifiedExplainer.num(late, "gap_end_timestamp_ns", start), details));
            }
        }
        return windows;
    }

    /** The late-cycle detector's summary as a finding payload, or null if it did not run. */
    static JsonObject lateCycleScan(JsonObject finder) {
        JsonObject stageA = UnifiedExplainer.obj(UnifiedExplainer.obj(finder, "periodic_jitter"), "stage_a");
        if (stageA == null) {
            return null;
        }
        JsonObject scan = new JsonObject();
        if (!UnifiedExplainer.bool(stageA, "available")) {
            scan.addProperty("available", false);
            scan.add("reason", stageA.get("reason"));
            scan.addProperty("claim", "Late-cycle detection could not run: " + UnifiedExplainer.str(stageA, "reason"));
            return scan;
        }
        int late = UnifiedExplainer.arr(stageA, "anomalies").size();
        scan.add("activation_count", stageA.get("activation_count"));
        scan.add("expected_period_ms", stageA.get("expected_period_ms"));
        scan.addProperty("late_cycle_count", late);
        scan.add("method", stageA.get("method"));
        String longest = "";
        if (stageA.has("longest_period_ms") && stageA.has("longest_period_factor")
                && !stageA.get("longest_period_factor").isJsonNull()) {
            scan.add("longest_period_ms", stageA.get("longest_period_ms"));
            scan.add("longest_period_factor", stageA.get("longest_period_factor"));
            scan.add("longest_period_end_timestamp_ns", stageA.get("longest_period_end_timestamp_ns"));
            scan.add("p99_period_ms", stageA.get("p99_period_ms"));
            longest = String.format(Locale.ROOT, " The longest cycle took %.3f ms, %.2f times the normal period; 99%% of "
                    + "cycles took at most %.3f ms.", UnifiedExplainer.dbl(stageA, "longest_period_ms", 0),
                    UnifiedExplainer.dbl(stageA, "longest_period_factor", 0), UnifiedExplainer.dbl(stageA, "p99_period_ms", 0));
        }
        String sizes = "";
        JsonObject bySize = UnifiedExplainer.obj(stageA, "late_cycles_by_size");
        if (bySize != null && stageA.has("longest_local_size")) {
            scan.add("late_cycles_by_size", bySize);
            scan.add("longest_local_period_ms", stageA.get("longest_local_period_ms"));
            scan.add("longest_local_factor", stageA.get("longest_local_factor"));
            scan.add("longest_local_size", stageA.get("longest_local_size"));
            long major = UnifiedExplainer.num(bySize, "major", 0L);
            long noticeable = UnifiedExplainer.num(bySize, "noticeable", 0L);
            String label = major + noticeable == 0
                    ? "only small delays: no cycle took twice the cycles around it (scheduling noise of this size is "
                            + "common on a shared machine)"
                    : major + noticeable <= 3 ? "a one-off delay: " + (major + noticeable) + " cycle(s) stand out from the "
                            + "cycles around them" : "repeated delays: " + (major + noticeable) + " cycles stand out from the "
                            + "cycles around them";
            scan.addProperty("delay_size", label);
            sizes = String.format(Locale.ROOT, " Against the cycles around it, the longest took %.2f times their %.3f ms "
                    + "(%s). Flagged cycles by that measure: %d major (5 times or more), %d noticeable (2 to 5 times), %d small "
                    + "(under twice). Delay size: %s.", UnifiedExplainer.dbl(stageA, "longest_local_factor", 0),
                    UnifiedExplainer.dbl(stageA, "longest_local_period_ms", 0), UnifiedExplainer.str(stageA, "longest_local_size"),
                    major, noticeable, UnifiedExplainer.num(bySize, "small", 0L), label);
        }
        scan.addProperty("claim", String.format(Locale.ROOT,
                "%d of %d cycles came abnormally late (normal period %.3f ms).%s%s", late,
                UnifiedExplainer.num(stageA, "activation_count", 0L),
                UnifiedExplainer.dbl(stageA, "expected_period_ms", 0), longest, sizes));
        return scan;
    }

    /**
     * Local-only HTTP endpoint for regression tests: runs a question through
     * the same pipeline as the chat, up to but not including the LLM call,
     * and returns the context the LLM would have received.
     *
     * Off unless the JVM is started with {@code -Dagent.test.port=<port>}.
     * Binds to 127.0.0.1 only. Requests are handled one at a time on one
     * background thread, because each one makes its trace the active trace in
     * Trace Compass. Plain sockets rather than com.sun.net.httpserver, which
     * is not part of the Java SE API the plugin is compiled against.
     *
     * <pre>
     * POST /test/context  {"trace_path": "...", "question": "...", "rag": true}
     * GET  /test/health
     * </pre>
     */
    static final class AgentTestServer {

        static final String PORT_PROPERTY = "agent.test.port";

        private final AnswerPipeline fView;
        private final ServerSocket fSocket;
        private final Map<String, ITmfTrace> fOpenTraces = new HashMap<>();
        private volatile boolean fRunning = true;

        private AgentTestServer(AnswerPipeline view, int port) throws IOException {
            fView = view;
            fSocket = new ServerSocket(port, 4, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(this::serve, "agent-test-endpoint");
            thread.setDaemon(true);
            thread.start();
        }

        /** Starts the server if {@value #PORT_PROPERTY} is set; otherwise null. */
        static AgentTestServer startIfConfigured(AnswerPipeline view) {
            String port = System.getProperty(PORT_PROPERTY);
            if (port == null || port.isBlank()) {
                return null;
            }
            try {
                AgentTestServer server = new AgentTestServer(view, Integer.parseInt(port.trim()));
                System.out.println("Agent test endpoint listening on http://127.0.0.1:" + port.trim());
                return server;
            } catch (IOException | NumberFormatException exception) {
                System.err.println("Agent test endpoint not started: " + exception);
                return null;
            }
        }

        /** Starts the server on {@code port} (the TraceAssist bundle in the Trace Server). */
        static AgentTestServer start(AnswerPipeline pipeline, int port) throws IOException {
            return new AgentTestServer(pipeline, port);
        }

        void stop() {
            fRunning = false;
            try {
                fSocket.close();
            } catch (IOException exception) {
                // Closing is best effort.
            }
            for (ITmfTrace trace : fOpenTraces.values()) {
                trace.dispose();
            }
            fOpenTraces.clear();
        }

        /** Questions run one at a time (the pipeline switches the active trace); health checks do not wait. */
        private final Object fPipelineLock = new Object();

        private void serve() {
            while (fRunning) {
                try {
                    Socket client = fSocket.accept();
                    Thread worker = new Thread(() -> {
                        try (client) {
                            handle(client);
                        } catch (IOException exception) {
                            if (fRunning) {
                                System.err.println("Agent test endpoint: " + exception);
                            }
                        }
                    }, "agent-test-request");
                    worker.setDaemon(true);
                    worker.start();
                } catch (IOException exception) {
                    if (fRunning) {
                        System.err.println("Agent test endpoint: " + exception);
                    }
                }
            }
        }

        /**
         * {@code GET /test/health}; {@code POST /test/context} (the pipeline only, for the
         * regression suite); {@code POST /ask} (the pipeline and the answer, for a chat client).
         *
         * <p>Both take {@code experiment_uuid}: the Trace Server's own experiment to answer on
         * (the one a TSP client shows; see {@link #serverExperiment}); without it, or outside the
         * Trace Server, the endpoint opens its own copy of {@code trace_path}. On an experiment,
         * a plan that opens the Critical Path following a thread also gets that critical path
         * ({@link #showCriticalPath}).</p>
         *
         * <p>{@code /ask} takes the {@code /test/context} request plus
         * {@code previous_response_id} (to continue the conversation) and {@code stream}. Without
         * {@code stream} it returns one JSON object. With {@code "stream": true} it returns
         * newline-delimited JSON events: {@code plan} (target, view plan, "Why this thread"), as
         * soon as the pipeline is done so the views can open while the answer is written; then
         * {@code delta} events with the answer's text; then {@code done} (the whole answer,
         * response id, model, usage, stage times) or {@code error}.</p>
         */
        private void handle(Socket client) throws IOException {
            client.setSoTimeout(30_000);
            InputStream in = new BufferedInputStream(client.getInputStream());
            OutputStream out = client.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null) {
                return;
            }
            String[] parts = requestLine.split(" ");
            String method = parts[0];
            String path = parts.length > 1 ? parts[1] : "";

            int contentLength = 0;
            String header;
            while ((header = readLine(in)) != null && !header.isEmpty()) {
                int colon = header.indexOf(':');
                if (colon > 0 && header.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
                    contentLength = Integer.parseInt(header.substring(colon + 1).trim());
                }
            }
            byte[] body = in.readNBytes(contentLength);

            if ("/test/health".equals(path)) {
                JsonObject health = new JsonObject();
                health.addProperty("status", "ok");
                send(out, 200, health);
                return;
            }
            boolean ask = "/ask".equals(path);
            if (!ask && !"/test/context".equals(path)) {
                send(out, 404, error("unknown path " + path));
                return;
            }
            if (!"POST".equals(method)) {
                send(out, 405, error("POST required"));
                return;
            }

            JsonObject request;
            try {
                request = JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject();
                if (!request.has("trace_path") || !request.has("question")) {
                    throw new IllegalArgumentException("trace_path and question are required");
                }
            } catch (RuntimeException exception) {
                send(out, 400, error("bad request: " + exception.getMessage()));
                return;
            }
            boolean stream = ask && request.has("stream") && request.get("stream").getAsBoolean();
            if (stream) {
                out.write(("HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/x-ndjson; charset=utf-8\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
            }

            JsonObject response;
            Map<String, Long> stageDurationsNs = new LinkedHashMap<>();
            PipelineContext built;
            ITmfTrace experiment = serverExperiment(request);
            try {
                synchronized (fPipelineLock) {
                    built = runPipeline(request, experiment, stageDurationsNs);
                    if (experiment != null) {
                        showCriticalPath(experiment, built.viewPlan, stageDurationsNs);
                    }
                }
                response = describe(request, built, stageDurationsNs);
                response.addProperty("trace_source", experiment != null ? "server_experiment" : "own_copy");
            } catch (Exception exception) {
                exception.printStackTrace();
                if (stream) {
                    event(out, "error", error(exception.toString()));
                } else {
                    send(out, 500, error(exception.toString()));
                }
                return;
            }
            if (!ask) {
                response.add("context", built.context);
                response.add("findings", built.findings);
                if (built.serverReportedTiming != null) {
                    response.add("tmll_service_timing_ms", built.serverReportedTiming);
                }
                send(out, 200, response);
                return;
            }

            /* /ask: the plan first (streamed), then the answer. */
            response.addProperty("findings_count", built.findings.size());
            if (stream) {
                event(out, "plan", response);
            }
            String previousResponseId = request.has("previous_response_id")
                    && !request.get("previous_response_id").isJsonNull()
                            ? request.get("previous_response_id").getAsString() : null;
            String question = request.get("question").getAsString();
            try {
                AnswerWriter.Answer answer = timed(stageDurationsNs, "llm_call", () -> AnswerWriter.write(
                        question, built.context.toString(), previousResponseId,
                        stream ? delta -> {
                            JsonObject piece = new JsonObject();
                            piece.addProperty("text", delta);
                            try {
                                event(out, "delta", piece);
                            } catch (IOException gone) {
                                throw new java.io.UncheckedIOException(gone); // the client left: stop the call
                            }
                        } : null));
                JsonObject done = new JsonObject();
                done.addProperty("answer", answer.text());
                done.addProperty("response_id", answer.responseId());
                done.addProperty("model", UnifiedExplainer.str(answer.meta(), "model"));
                if (answer.meta().has("usage")) {
                    done.add("usage", answer.meta().get("usage"));
                }
                done.add("stage_durations_ms", stageTimes(stageDurationsNs));
                if (stream) {
                    event(out, "done", done);
                } else {
                    done.entrySet().forEach(entry -> response.add(entry.getKey(), entry.getValue()));
                    send(out, 200, response);
                }
            } catch (java.io.UncheckedIOException gone) {
                System.err.println("TraceAssist /ask: the client closed the connection during the answer");
            } catch (Exception exception) {
                exception.printStackTrace();
                if (stream) {
                    event(out, "error", error(exception.toString()));
                } else {
                    response.addProperty("error", exception.toString());
                    send(out, 500, response);
                }
            }
        }

        /**
         * Runs the pipeline (everything before the LLM call) on the server's experiment when
         * there is one, otherwise on the request's trace, opened (once) by this endpoint.
         */
        private PipelineContext runPipeline(JsonObject request, @Nullable ITmfTrace experiment,
                Map<String, Long> stageDurationsNs) throws Exception {
            String tracePath = request.get("trace_path").getAsString();
            String question = request.get("question").getAsString();
            boolean rag = !request.has("rag") || request.get("rag").getAsBoolean();
            /* Repeatability tests: "skill_cache": false makes every AI skill call the model again. */
            boolean skillCache = !request.has("skill_cache") || request.get("skill_cache").getAsBoolean();

            /* Tests open their own traces; give the user's selection back afterwards. */
            ITmfTrace previouslyActive = TmfTraceManager.getInstance().getActiveTrace();
            if (experiment != null) {
                TmfSignalManager.dispatchSignal(new TmfTraceSelectedSignal(this, experiment));
            } else {
                activate(tracePath);
            }
            AiSkill.useCache(skillCache);
            try {
                Integer tid = extractTid(question);
                /* A follow-up: what the previous question was about (defaults to this trace). */
                JsonObject previousTarget = request.has("previous_target") && request.get("previous_target").isJsonObject()
                        ? request.getAsJsonObject("previous_target").deepCopy() : null;
                if (previousTarget != null && !previousTarget.has("trace_path")) {
                    previousTarget.addProperty("trace_path", activeTracePath());
                }
                return fView.buildAnswerContext(question, tid, rag, stageDurationsNs, previousTarget);
            } finally {
                AiSkill.useCache(true);
                if (previouslyActive != null
                        && previouslyActive != TmfTraceManager.getInstance().getActiveTrace()) {
                    TmfSignalManager.dispatchSignal(new TmfTraceSelectedSignal(this, previouslyActive));
                }
            }
        }

        /** The Trace Server's REST bundle and its experiment registry (absent in Eclipse). */
        private static final String REST_BUNDLE = "org.eclipse.tracecompass.incubator.trace.server.jersey.rest.core";
        private static final String EXPERIMENT_SERVICE =
                "org.eclipse.tracecompass.incubator.internal.trace.server.jersey.rest.core.services.ExperimentManagerService";

        /**
         * The Trace Server's own experiment named by the request's {@code experiment_uuid} (the
         * one a TSP client such as the VS Code viewer shows), or null: no uuid, not running in
         * the Trace Server, or no such experiment. Answering on it shares its analyses with the
         * viewer, instead of indexing and analyzing a second copy of the trace; and only on it
         * can the viewer's Critical Path show a thread. Looked up by reflection, so the plug-in
         * does not depend on the Trace Server.
         */
        private static @Nullable ITmfTrace serverExperiment(JsonObject request) {
            if (!request.has("experiment_uuid") || request.get("experiment_uuid").isJsonNull()) {
                return null;
            }
            org.osgi.framework.Bundle rest = org.eclipse.core.runtime.Platform.getBundle(REST_BUNDLE);
            if (rest == null) {
                return null;
            }
            try {
                Object experiment = rest.loadClass(EXPERIMENT_SERVICE)
                        .getMethod("getExperimentByUUID", java.util.UUID.class)
                        .invoke(null, java.util.UUID.fromString(request.get("experiment_uuid").getAsString()));
                if (experiment instanceof ITmfTrace) {
                    return (ITmfTrace) experiment;
                }
                System.err.println("TraceAssist: no Trace Server experiment " + request.get("experiment_uuid")
                        + "; answering on the trace path");
            } catch (ReflectiveOperationException | RuntimeException exception) {
                System.err.println("TraceAssist: Trace Server experiment lookup failed: " + exception);
            }
            return null;
        }

        /**
         * When the plan opens the Critical Path following a thread: starts that thread's
         * critical path over the plan's selection on the experiment, and gives the view its
         * output ({@code tsp_output} and {@code tsp_descriptor}, as the server lists no such
         * output), or {@code tsp_unavailable} with the reason.
         */
        private static void showCriticalPath(ITmfTrace experiment, @Nullable JsonObject viewPlan,
                Map<String, Long> stageDurationsNs) throws Exception {
            if (viewPlan == null || !viewPlan.has("follow_tid")) {
                return;
            }
            JsonObject criticalPath = null;
            for (JsonElement element : UnifiedExplainer.arr(viewPlan, "views")) {
                if (VIEW_CRITICAL_PATH.equals(UnifiedExplainer.str(element.getAsJsonObject(), "id"))) {
                    criticalPath = element.getAsJsonObject();
                }
            }
            if (criticalPath == null) {
                return;
            }
            int tid = viewPlan.get("follow_tid").getAsInt();
            JsonObject selection = UnifiedExplainer.obj(viewPlan, "selection");
            long traceStart = experiment.getStartTime().toNanos();
            long traceEnd = experiment.getEndTime().toNanos();
            long start = selection == null ? traceStart : UnifiedExplainer.num(selection, "start_ns", traceStart);
            long end = selection == null ? traceEnd : UnifiedExplainer.num(selection, "end_ns", traceEnd);
            String failed = timed(stageDurationsNs, "critical_path_view",
                    () -> ServerCriticalPath.follow(experiment, tid, start, end));
            if (failed == null) {
                criticalPath.addProperty("tsp_output", CRITICAL_PATH_PROVIDER_ID);
                criticalPath.add("tsp_descriptor", ServerCriticalPath.descriptor());
            } else {
                criticalPath.addProperty("tsp_unavailable", failed);
                System.err.println("TraceAssist: Critical Path of TID " + tid + " not shown: " + failed);
            }
        }

        /** The response fields both endpoints share: the question, target, plan, view plan, "Why this thread". */
        private static JsonObject describe(JsonObject request, PipelineContext built, Map<String, Long> stageDurationsNs) {
            String question = request.get("question").getAsString();
            JsonObject response = new JsonObject();
            response.addProperty("question", question);
            response.addProperty("trace_path", request.get("trace_path").getAsString());
            Integer tid = extractTid(question);
            if (tid != null) {
                response.addProperty("requested_tid", tid);
            }
            if (built.plan != null) {
                response.add("plan", built.plan);
            }
            if (built.target != null) {
                response.add("target", built.target);
            }
            if (built.viewPlan != null) {
                response.add("view_plan", built.viewPlan);
            }
            String why = ThreadSearch.whySection(UnifiedExplainer.obj(built.plan, "thread_finder"));
            if (why != null) {
                response.addProperty("why_section", why);
            }
            response.add("stage_durations_ms", stageTimes(stageDurationsNs));
            return response;
        }

        private static JsonObject stageTimes(Map<String, Long> stageDurationsNs) {
            JsonObject stages = new JsonObject();
            stageDurationsNs.forEach((stage, ns) -> stages.addProperty(stage, ns / 1_000_000.0));
            return stages;
        }

        /** One newline-delimited JSON event of a streamed /ask response. */
        private static void event(OutputStream out, String type, JsonObject data) throws IOException {
            JsonObject event = new JsonObject();
            event.addProperty("type", type);
            data.entrySet().forEach(entry -> event.add(entry.getKey(), entry.getValue()));
            synchronized (out) {
                out.write((event.toString() + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        }

        /**
         * Makes the trace at {@code tracePath} the active trace, opening and
         * indexing it on first use. Opening broadcasts the same signal the
         * editor does, which also instantiates the trace's analysis modules.
         */
        private void activate(String tracePath) throws Exception {
            ITmfTrace trace = fOpenTraces.get(tracePath);
            if (trace == null) {
                LttngKernelTrace kernelTrace = new LttngKernelTrace();
                kernelTrace.initTrace(null, tracePath, CtfTmfEvent.class);
                kernelTrace.indexTrace(true);
                TmfSignalManager.dispatchSignal(new TmfTraceOpenedSignal(this, kernelTrace, null));
                fOpenTraces.put(tracePath, kernelTrace);
                return;
            }
            TmfSignalManager.dispatchSignal(new TmfTraceSelectedSignal(this, trace));
        }

        private static String readLine(InputStream in) throws IOException {
            StringBuilder line = new StringBuilder();
            int c;
            while ((c = in.read()) != -1) {
                if (c == '\n') {
                    break;
                }
                if (c != '\r') {
                    line.append((char) c);
                }
            }
            return c == -1 && line.length() == 0 ? null : line.toString();
        }

        private static JsonObject error(String message) {
            JsonObject error = new JsonObject();
            error.addProperty("error", message);
            return error;
        }

        private static void send(OutputStream out, int status, JsonObject body) throws IOException {
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            String head = "HTTP/1.1 " + status + (status == 200 ? " OK" : " Error") + "\r\n" +
                    "Content-Type: application/json; charset=utf-8\r\n" +
                    "Content-Length: " + bytes.length + "\r\n" +
                    "Connection: close\r\n\r\n";
            out.write(head.getBytes(StandardCharsets.US_ASCII));
            out.write(bytes);
            out.flush();
        }
    }
}
