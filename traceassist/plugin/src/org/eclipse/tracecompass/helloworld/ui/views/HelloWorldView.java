package org.eclipse.tracecompass.helloworld.ui.views;

import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.*;

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

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StyleRange;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.FontData;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Text;
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
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IViewPart;
import org.eclipse.tracecompass.analysis.os.linux.core.signals.TmfThreadSelectedSignal;
import org.eclipse.tracecompass.analysis.os.linux.core.signals.TmfCpuSelectedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfWindowRangeUpdatedSignal;
import org.eclipse.tracecompass.tmf.core.signal.TmfSelectionRangeUpdatedSignal;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimeRange;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimestamp;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PartInitException;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.part.ViewPart;

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

public class HelloWorldView extends ViewPart {

    public static final String ID =
            "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldView";

    private AgentTestServer testServer;

    /** The answer pipeline (no UI); the same code runs headless in the TraceAssist server bundle. */
    private final AnswerPipeline pipeline = new AnswerPipeline();

    private StyledText conversation;
    private Text messageBox;
    private Button sendButton;
    private Button ragToggle;
    private Font chatFont;

    /*
     * Used to continue the previous OpenAI conversation.
     */
    private String previousResponseId;

    /** What the last question was about (thread or process, with its trace), so a follow-up can continue it. */
    private volatile JsonObject lastTarget;

    /** The view plan of the last answered question (null if it had none). */
    private volatile JsonObject lastViewPlan;

    /** The last batch's view plans by question number, with the trace each was computed on ("show Q3"). */
    private final Map<Integer, JsonObject> batchViewPlans = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<Integer, ITmfTrace> batchViewTraces = new java.util.concurrent.ConcurrentHashMap<>();

    /*
     * Model, id and token usage of the last OpenAI response, recorded with
     * each answer by AnswerLog.
     */
    private volatile JsonObject lastResponseMeta;

    @Override
    public void createPartControl(Composite parent) {
        TmfSignalManager.register(this);
        try {
            testServer = AgentTestServer.startIfConfigured(pipeline);
        } catch (LinkageError | RuntimeException exception) {
            System.err.println("Agent test endpoint not started: " + exception);
        }

        parent.setLayout(new GridLayout(1, false));

        /*
         * Main conversation display.
         */
        conversation = new StyledText(
                parent,
                SWT.BORDER |
                SWT.MULTI |
                SWT.WRAP |
                SWT.V_SCROLL |
                SWT.READ_ONLY);

        conversation.setLayoutData(
                new GridData(
                        SWT.FILL,
                        SWT.FILL,
                        true,
                        true));

        conversation.setText(
                "Trace Compass Assistant\n\n" +
                "Open a Linux kernel trace and ask me a question.\n");

        /*
         * Use a larger font for both the transcript and message box.
         */
        FontData defaultFont =
                conversation
                        .getFont()
                        .getFontData()[0];

        chatFont = new Font(
                parent.getDisplay(),
                defaultFont.getName(),
                14,
                SWT.NORMAL);

        conversation.setFont(chatFont);

        /*
         * RAG toggle. When unchecked, sendMessage() skips the TMLL/RAG
         * call entirely (no thread analysis, no knowledge retrieval, no
         * critical path) and sends only the plain Java-side trace context
         * to the LLM -- useful for comparing grounded vs. ungrounded
         * answers on the same question.
         */
        ragToggle = new Button(parent, SWT.CHECK);
        ragToggle.setText("Use RAG (TMLL knowledge retrieval)");
        ragToggle.setSelection(true);

        ragToggle.setLayoutData(
                new GridData(
                        SWT.LEFT,
                        SWT.BOTTOM,
                        false,
                        false));

        /*
         * Area containing the message box and Send button.
         */
        Composite inputArea =
                new Composite(parent, SWT.NONE);

        inputArea.setLayoutData(
                new GridData(
                        SWT.FILL,
                        SWT.BOTTOM,
                        true,
                        false));

        inputArea.setLayout(new GridLayout(2, false));

        /*
         * User message box.
         */
        messageBox = new Text(
                inputArea,
                SWT.BORDER |
                SWT.MULTI |
                SWT.WRAP |
                SWT.V_SCROLL);

        GridData messageLayout =
                new GridData(
                        SWT.FILL,
                        SWT.FILL,
                        true,
                        false);

        messageLayout.heightHint = 60;
        messageBox.setLayoutData(messageLayout);
        messageBox.setFont(chatFont);

        /*
         * Send button.
         */
        sendButton = new Button(inputArea, SWT.PUSH);
        sendButton.setText("Send");

        sendButton.setLayoutData(
                new GridData(
                        SWT.RIGHT,
                        SWT.BOTTOM,
                        false,
                        false));

        sendButton.addListener(
                SWT.Selection,
                event -> sendMessage());

        /*
         * Fonts created by the plug-in must be disposed with the view.
         */
        parent.addDisposeListener(event -> {
            if (chatFont != null &&
                    !chatFont.isDisposed()) {
                chatFont.dispose();
            }
        });
    }

    /**
     * The Control Flow view's extension-registered id. Its implementing
     * class ({@code ControlFlowView}) lives in an internal package
     * (org.eclipse.tracecompass.internal.analysis.os.linux.ui.views.
     * controlflow), so it cannot be imported directly from this plugin;
     * {@link IWorkbenchPage#showView(String)} only needs the id string.
     */
    private static final String CONTROL_FLOW_VIEW_ID =
            "org.eclipse.tracecompass.analysis.os.linux.views." +
            "controlflow";

    /**
     * Pattern for an explicit "open/highlight this thread" command, e.g.
     * "open up this thread TID: 3740" or "highlight thread 3740". Requires
     * an action verb followed reasonably closely by "thread"/"tid", so
     * that ordinary analysis questions that merely mention a TID (e.g.
     * "why is TID 3740 blocked so much?") do not trigger it -- highlighting
     * only happens when the user actually asks for it, not just because a
     * TID appears in the message.
     */
    private static final Pattern HIGHLIGHT_THREAD_COMMAND_PATTERN =
            Pattern.compile(
                    "(?i)\\b(?:open(?:\\s+up)?|show|highlight|select|" +
                    "jump\\s+to|go\\s+to)\\b.{0,20}?\\b(?:thread|tid)\\b");

    /**
     * Handles an explicit "open/highlight this thread" command by
     * selecting/scrolling to that TID's row in the Control Flow view (see
     * {@link #highlightThreadInControlFlowView}), bypassing the LLM
     * entirely -- this is a UI action, not a question. Returns null (and
     * does nothing) when the message does not match the command pattern
     * or names no TID, so sendMessage() falls through to its normal
     * analysis flow.
     *
     * @param userMessage
     *            the raw text the user typed
     * @param requestedTid
     *            the TID extractTid() found in that message, if any
     * @return a confirmation/error string if this was a highlight-thread
     *         command, otherwise null
     */
    private static String tryHandleHighlightThreadCommand(
            String userMessage,
            Integer requestedTid) {

        if (requestedTid == null ||
                !HIGHLIGHT_THREAD_COMMAND_PATTERN
                        .matcher(userMessage)
                        .find()) {
            return null;
        }

        try {
            highlightThreadInControlFlowView(
                    requestedTid.intValue());

            return "Highlighted TID " +
                    requestedTid +
                    " in the Control Flow view.";
        } catch (PartInitException exception) {
            return "I found TID " +
                    requestedTid +
                    ", but Eclipse could not open the Control Flow " +
                    "view: " +
                    exception.getMessage();
        }
    }

    /**
     * Opens the Control Flow view (if not already open) and selects/
     * scrolls to the row for the given TID.
     *
     * This does not talk to the Control Flow view directly. It broadcasts
     * a {@link TmfDataModelSelectedSignal} carrying TID metadata under the
     * same key ({@link OsStrings#tid()}) Control Flow's own thread entries
     * already carry -- the same generic mechanism Trace Compass itself
     * uses internally to keep views in sync when a data-model element is
     * selected somewhere (e.g. double-clicking a segment in one view
     * highlighting its owning thread in another). Every open time-graph
     * view listens for this signal (AbstractTimeGraphView.selectionChanged,
     * in org.eclipse.tracecompass.tmf.ui) and selects any row whose own
     * metadata matches, so this works for Control Flow without this plugin
     * needing any reference to Control Flow's own (internal) implementation
     * class.
     *
     * Callers must already be on the UI thread (both current callers --
     * sendMessage() and tryHandleHighlightThreadCommand() -- are).
     *
     * @param tid
     *            thread ID to select in the Control Flow view
     * @throws PartInitException
     *             if Eclipse could not open the Control Flow view
     */
    private static void highlightThreadInControlFlowView(int tid)
            throws PartInitException {

        openWorkbenchView(CONTROL_FLOW_VIEW_ID);

        Multimap<String, Object> metadata =
                HashMultimap.create();

        metadata.put(
                OsStrings.tid(),
                Integer.valueOf(tid));

        TmfSignalManager.dispatchSignal(
                new TmfDataModelSelectedSignal(
                        HelloWorldView.class,
                        metadata));
    }

    /**
     * Pattern for an explicit "critical path" command, e.g. "run critical
     * path analysis on thread 20989" or "what is the critical path for TID
     * 3740". Requires a TID in the same message.
     *
     * This bypasses TMLL's syscall-frequency category gate that normally
     * decides whether {@link #collectCriticalPath} runs (see
     * {@link #collectCriticalPathIfIndicated}): that gate exists to avoid
     * running the graph algorithm on every TID-specific question, most of
     * which have nothing to do with worker churn, but it also means a
     * thread whose syscalls happen to read as a different category (e.g.
     * disk I/O) never reaches {@link OSCriticalPathModule} even if the
     * thread has abundant recorded running time. An explicit ask for the
     * critical path should always reach the module directly, the same way
     * {@link #tryHandleHighlightThreadCommand} always opens the Control
     * Flow view when explicitly asked rather than only when the heuristics
     * elsewhere happen to agree.
     */
    private static final Pattern CRITICAL_PATH_COMMAND_PATTERN =
            Pattern.compile("(?i)\\bcritical\\s+path\\b");

    /**
     * Optional suffix on the critical-path command: "... last 10s" / "...
     * last 30 seconds". When present, triggers
     * {@link #compareCriticalPathTiming} instead of a single unbounded run
     * -- a one-message way to run critical_path_improvements.md's
     * windowed-vs-unbounded comparison on a worker chosen for having a
     * large recorded history, without needing raw nanosecond timestamps.
     */
    private static final Pattern LAST_N_SECONDS_PATTERN =
            Pattern.compile("(?i)\\blast\\s+(\\d+)\\s*s(?:ec(?:ond)?s?)?\\b");

    /**
     * Handles an explicit "critical path" command by calling
     * {@link #collectCriticalPath} directly and formatting its result as
     * plain text, bypassing both the LLM and TMLL's syscall-category gate.
     * Returns null (and does nothing) when the message does not match the
     * command pattern or names no TID, so sendMessage() falls through to
     * its normal analysis flow.
     *
     * @param userMessage
     *            the raw text the user typed
     * @param requestedTid
     *            the TID extractTid() found in that message, if any
     * @return a result/error string if this was a critical-path command,
     *         otherwise null
     */
    private static String tryHandleCriticalPathCommand(
            String userMessage,
            Integer requestedTid) {

        if (requestedTid == null ||
                !CRITICAL_PATH_COMMAND_PATTERN
                        .matcher(userMessage)
                        .find()) {
            return null;
        }

        ITmfTrace trace =
                TmfTraceManager
                        .getInstance()
                        .getActiveTrace();

        if (trace == null) {
            return "I can compute the critical path for TID " +
                    requestedTid +
                    ", but no trace is currently active in Trace Compass.";
        }

        Matcher lastNSecondsMatcher =
                LAST_N_SECONDS_PATTERN.matcher(userMessage);

        if (lastNSecondsMatcher.find()) {
            long windowSeconds =
                    Long.parseLong(lastNSecondsMatcher.group(1));

            return compareCriticalPathTiming(
                    trace,
                    requestedTid.intValue(),
                    windowSeconds);
        }

        long startNanos = System.nanoTime();

        JsonObject result =
                collectCriticalPath(
                        trace,
                        requestedTid.intValue());

        long elapsedMs =
                (System.nanoTime() - startNanos) / 1_000_000L;

        return formatCriticalPathResult(
                requestedTid.intValue(),
                result) +
                "\n(Java-side elapsed: " + elapsedMs + " ms)";
    }

    /**
     * Testing helper: runs {@link #collectCriticalPath} twice for the same
     * TID -- once unbounded, once windowed to just the last
     * {@code windowSeconds} of the worker's own recorded lifetime -- and
     * reports both timings and results side by side. Exists to let
     * critical_path_improvements.md's windowed-vs-unbounded comparison be
     * run with a single chat message, on a worker chosen for having a
     * large recorded history, instead of needing two separate manual
     * commands and raw nanosecond timestamps.
     *
     * Triggered by "critical path for thread &lt;TID&gt; last &lt;N&gt;s".
     */
    private static String compareCriticalPathTiming(
            ITmfTrace trace,
            int tid,
            long windowSeconds) {

        Long tailTimestampNs = findWorkerTailTimestampNs(trace, tid);

        if (tailTimestampNs == null) {
            return "Cannot compare: TID " + tid +
                    " was not found as a worker in the execution graph, " +
                    "so there is no recorded lifetime to window against.";
        }

        long windowStartNs =
                tailTimestampNs.longValue() -
                (windowSeconds * 1_000_000_000L);

        long unboundedStartNanos = System.nanoTime();

        JsonObject unboundedResult =
                collectCriticalPath(trace, tid);

        long unboundedElapsedMs =
                (System.nanoTime() - unboundedStartNanos) / 1_000_000L;

        long windowedStartNanos = System.nanoTime();

        JsonObject windowedResult =
                collectCriticalPath(
                        trace,
                        tid,
                        windowStartNs,
                        null);

        long windowedElapsedMs =
                (System.nanoTime() - windowedStartNanos) / 1_000_000L;

        StringBuilder text = new StringBuilder();

        text.append("Critical path timing comparison for TID ")
                .append(tid)
                .append(" (window: last ")
                .append(windowSeconds)
                .append("s of its recorded lifetime):\n\n")
                .append("Unbounded (full worker lifetime):\n")
                .append(formatCriticalPathResult(tid, unboundedResult))
                .append("(Java-side elapsed: ")
                .append(unboundedElapsedMs)
                .append(" ms)\n\n")
                .append("Windowed (last ")
                .append(windowSeconds)
                .append("s only):\n")
                .append(formatCriticalPathResult(tid, windowedResult))
                .append("(Java-side elapsed: ")
                .append(windowedElapsedMs)
                .append(" ms)\n\n")
                .append("See the Eclipse console for [CRITPATH-TIMING] " +
                        "lines with more precise internal " +
                        "computeCriticalPath()-only timing for both runs " +
                        "(the elapsed times above also include graph " +
                        "lookup/scheduling overhead common to both).");

        return text.toString();
    }

    /**
     * Resolves the worker for {@code tid} in {@code trace}'s execution
     * graph and returns its tail (last recorded) vertex timestamp in
     * nanoseconds, or {@code null} if the trace has no execution-graph
     * analysis or the TID is not a worker in it. Duplicates
     * {@link #collectCriticalPath}'s own worker lookup (cheap -- the
     * execution graph is already built/cached by that point) rather than
     * changing that method's return type just for this testing helper.
     */
    private static @Nullable Long findWorkerTailTimestampNs(
            ITmfTrace trace,
            int tid) {

        OsExecutionGraph executionGraphModule =
                TmfTraceUtils.getAnalysisModuleOfClass(
                        trace,
                        OsExecutionGraph.class,
                        OsExecutionGraph.ANALYSIS_ID);

        if (executionGraphModule == null) {
            return null;
        }

        executionGraphModule.schedule();
        executionGraphModule.waitForCompletion();

        ITmfGraph graph = executionGraphModule.getTmfGraph();

        if (graph == null) {
            return null;
        }

        OsWorker worker = findOsWorker(graph, tid);

        if (worker == null) {
            return null;
        }

        ITmfVertex tail = graph.getTail(worker);

        return tail == null ? null : Long.valueOf(tail.getTimestamp());
    }

    /**
     * Formats the JSON result of {@link #collectCriticalPath} as plain
     * text for direct display, without going through the LLM.
     */
    private static String formatCriticalPathResult(
            int tid,
            JsonObject result) {

        boolean available =
                result.has("available") &&
                result.get("available").getAsBoolean();

        if (!available) {
            String reason =
                    result.has("reason") ?
                            result.get("reason").getAsString() :
                            "unknown reason";

            return "Critical path analysis for TID " + tid +
                    " (OSCriticalPathModule): unavailable -- " + reason;
        }

        StringBuilder text = new StringBuilder();

        text.append("Critical path analysis for TID ")
                .append(tid)
                .append(" (OSCriticalPathModule): available.\n")
                .append("- Span: ")
                .append(result.get("span_ms").getAsDouble())
                .append(" ms\n")
                .append("- Participants: ")
                .append(result.get("participant_count").getAsInt())
                .append(" (")
                .append(result.get("other_thread_count").getAsInt())
                .append(" other thread(s) besides TID ")
                .append(tid)
                .append(")\n");

        for (JsonElement element :
                result.getAsJsonArray("participants")) {

            JsonObject participant =
                    element.getAsJsonObject();

            text.append("    - TID ")
                    .append(participant.get("tid").getAsInt())
                    .append(" (")
                    .append(participant.get("name").getAsString())
                    .append(")")
                    .append(participant.get("is_requested_thread")
                                    .getAsBoolean() ?
                                    " [requested thread]" : "")
                    .append("\n");
        }

        return text.toString();
    }

    /**
     * Shows a view plan: opens its views (the first one last, so it is on
     * top), zooms every view to the range and marks it, follows the thread
     * (the Critical Path view switches to it, Resources highlights it),
     * selects its row, selects the CPU, and plots threads in CPU Usage.
     * Runs on the UI thread; views fill in asynchronously.
     */
    void showViewPlan(JsonObject viewPlan) {
        showViewPlan(viewPlan, null);
    }

    /**
     * @param planTrace
     *            the trace the plan was computed on (selected first if it is
     *            not the active one), or null for the active trace
     */
    void showViewPlan(JsonObject viewPlan, ITmfTrace planTrace) {
        if (viewPlan == null) {
            return;
        }
        Display.getDefault().asyncExec(() -> {
            if (planTrace != null && planTrace != TmfTraceManager.getInstance().getActiveTrace()) {
                TmfSignalManager.dispatchSignal(new TmfTraceSelectedSignal(this, planTrace));
            }
            ITmfTrace trace = planTrace != null ? planTrace : TmfTraceManager.getInstance().getActiveTrace();
            if (trace == null) {
                return;
            }
            JsonArray views = UnifiedExplainer.arr(viewPlan, "views");
            boolean criticalPath = false;
            for (JsonElement element : views) {
                criticalPath |= VIEW_CRITICAL_PATH.equals(UnifiedExplainer.str(element.getAsJsonObject(), "id"));
            }
            IWorkbenchWindow workbench = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
            IWorkbenchPage page = workbench == null ? null : workbench.getActivePage();
            if (criticalPath && viewPlan.has("follow_tid")) {
                showCriticalPath(viewPlan, trace, viewPlan.get("follow_tid").getAsInt());
            }
            for (int i = views.size() - 1; i >= 0; i--) {
                String viewId = UnifiedExplainer.str(views.get(i).getAsJsonObject(), "id");
                if (criticalPath && VIEW_CRITICAL_PATH.equals(viewId) && viewPlan.has("follow_tid")) {
                    continue;
                }
                try {
                    openWorkbenchView(viewId);
                } catch (PartInitException exception) {
                    System.err.println("Could not open view: " + exception.getMessage());
                }
            }
            if (viewPlan.has("follow_tid") && !criticalPath) {
                TmfSignalManager.dispatchSignal(new TmfThreadSelectedSignal(this, viewPlan.get("follow_tid").getAsInt(), trace));
            }
            if (viewPlan.has("cpu")) {
                TmfSignalManager.dispatchSignal(new TmfCpuSelectedSignal(this, viewPlan.get("cpu").getAsInt(), trace));
            }
            focusRange(viewPlan, trace);
            if (viewPlan.has("select_tid")) {
                Multimap<String, Object> metadata = HashMultimap.create();
                metadata.put(OsStrings.tid(), Integer.valueOf(viewPlan.get("select_tid").getAsInt()));
                TmfSignalManager.dispatchSignal(new TmfDataModelSelectedSignal(this, metadata));
            }
            List<Integer> plot = new ArrayList<>();
            UnifiedExplainer.arr(viewPlan, "plot_tids").forEach(element -> plot.add(element.getAsInt()));
            if (!plot.isEmpty()) {
                // The thread list fills in once the CPU usage analysis is done:
                // seconds when cached, longer on a freshly started session.
                plotInCpuUsage(plot, 120);
            }
            // A latency scatter plots nothing until a series is ticked; its list fills in
            // once the latency analysis (a pass over all events) is done, which can take minutes.
            List<String> series = new ArrayList<>();
            UnifiedExplainer.arr(viewPlan, "plot_series").forEach(element -> series.add(element.getAsString()));
            for (JsonElement element : views) {
                String viewId = UnifiedExplainer.str(element.getAsJsonObject(), "id");
                if (VIEW_SYSCALL_LATENCY_SCATTER.equals(viewId) || VIEW_SCHED_LATENCY_SCATTER.equals(viewId)) {
                    tickInChartList(viewId, series, 600);
                }
            }
            // Views opened just now load their data asynchronously and may reset
            // their range; set it again once they have started.
            Display.getDefault().timerExec(1500, () -> focusRange(viewPlan, trace));
        });
    }

    static OSCriticalPathModule registeredCriticalPath(ITmfTrace trace) {
        return TmfTraceUtils.getAnalysisModuleOfClass(trace, OSCriticalPathModule.class, CRITICAL_PATH_ANALYSIS_ID);
    }

    /**
     * Shows the thread's critical path over the zoomed range in the Critical
     * Path view. The view's data comes from the critical-path analysis that
     * last started on the trace, and it rebuilds when one starts; so: drop
     * its cached data provider, then start a critical-path analysis for this
     * thread and range (the same kind the pipeline uses for its examples,
     * which computes reliably) and keep it alive while it is shown. Off the
     * UI thread: the execution graph may still be building.
     */
    private void showCriticalPath(JsonObject viewPlan, ITmfTrace trace, int tid) {
        // The path covers exactly the selected range; the padding is only for the zoom.
        JsonObject selection = UnifiedExplainer.obj(viewPlan, "selection");
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        long start = selection == null ? traceStart : UnifiedExplainer.num(selection, "start_ns", traceStart);
        long end = selection == null ? traceEnd : UnifiedExplainer.num(selection, "end_ns", traceEnd);
        CompletableFuture.runAsync(() -> {
            OsExecutionGraph graphModule = TmfTraceUtils.getAnalysisModuleOfClass(
                    trace, OsExecutionGraph.class, OsExecutionGraph.ANALYSIS_ID);
            if (graphModule == null) {
                return;
            }
            graphModule.schedule();
            graphModule.waitForCompletion();
            ITmfGraph graph = graphModule.getTmfGraph();
            OsWorker worker = graph == null ? null : findOsWorker(graph, tid);
            if (worker == null) {
                System.err.println("Critical Path view: TID " + tid + " is not in the execution graph.");
                return;
            }
            OSCriticalPathModule previous = sViewCriticalPath;
            OSCriticalPathModule module = new OSCriticalPathModule(graphModule, worker);
            if (start > traceStart || end < traceEnd) {
                module.setParameter(AbstractCriticalPathModule.PARAM_WINDOW_START, start);
                module.setParameter(AbstractCriticalPathModule.PARAM_WINDOW_END, end + 2);
            }
            try {
                module.setTrace(trace);
            } catch (TmfAnalysisException exception) {
                System.err.println("Critical Path view: " + exception.getMessage());
                return;
            }
            org.eclipse.tracecompass.tmf.core.dataprovider.DataProviderManager.getInstance()
                    .removeDataProvider(trace, CRITICAL_PATH_PROVIDER_ID);
            sViewCriticalPath = module;
            // Starting it announces it to the view's data provider factory.
            module.schedule();
            module.waitForCompletion();
            /*
             * Not disposed: disposing clears its graph, and a view build job
             * still bound to it would then poll forever ("Building Entries...").
             * Each covers one short range, so keeping them is cheap.
             */
            if (previous != null) {
                sRetiredViewCriticalPaths.add(previous);
            }
            // A fresh view binds to it; closing an open one also stops build jobs
            // still polling an older binding ("Building Entries..." that never ends).
            Display.getDefault().asyncExec(() -> {
                IWorkbenchWindow window = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
                IWorkbenchPage page = window == null ? null : window.getActivePage();
                if (page == null) {
                    return;
                }
                IViewPart open = page.findView(VIEW_CRITICAL_PATH);
                if (open != null) {
                    page.hideView(open);
                }
                try {
                    openWorkbenchView(VIEW_CRITICAL_PATH);
                } catch (PartInitException exception) {
                    System.err.println("Could not open the Critical Path view: " + exception.getMessage());
                }
                focusRange(viewPlan, trace);
            });
        });
    }

    /**
     * A thread followed by someone else (e.g. Control Flow's "Follow
     * thread"): the Critical Path view goes back to the trace's own analysis.
     */
    @org.eclipse.tracecompass.tmf.core.signal.TmfSignalHandler
    public void threadFollowed(TmfThreadSelectedSignal signal) {
        if (signal.getSource() == this) {
            return;
        }
        ITmfTrace trace = TmfTraceManager.getInstance().getActiveTrace();
        OSCriticalPathModule mine = sViewCriticalPath;
        if (trace == null || mine == null) {
            return;
        }
        // Someone followed a thread: the trace's own analysis computes it and the view rebuilds from it.
        sViewCriticalPath = null;
        sRetiredViewCriticalPaths.add(mine);
        org.eclipse.tracecompass.tmf.core.dataprovider.DataProviderManager.getInstance()
                .removeDataProvider(trace, CRITICAL_PATH_PROVIDER_ID);
    }

    private void focusRange(JsonObject viewPlan, ITmfTrace trace) {
        JsonObject zoom = UnifiedExplainer.obj(viewPlan, "zoom");
        JsonObject selection = UnifiedExplainer.obj(viewPlan, "selection");
        if (zoom != null) {
            TmfSignalManager.dispatchSignal(new TmfWindowRangeUpdatedSignal(this,
                    new TmfTimeRange(TmfTimestamp.fromNanos(UnifiedExplainer.num(zoom, "start_ns", 0L)),
                            TmfTimestamp.fromNanos(UnifiedExplainer.num(zoom, "end_ns", 0L))), trace));
        }
        if (selection != null) {
            TmfSignalManager.dispatchSignal(new TmfSelectionRangeUpdatedSignal(this,
                    TmfTimestamp.fromNanos(UnifiedExplainer.num(selection, "start_ns", 0L)),
                    TmfTimestamp.fromNanos(UnifiedExplainer.num(selection, "end_ns", 0L)), trace));
        }
    }

    /** Ticks the threads' entries in the CPU Usage view's thread list (labelled by TID). */
    private void plotInCpuUsage(List<Integer> tids, int attemptsLeft) {
        tickInChartList(VIEW_CPU_USAGE, tids.stream().map(String::valueOf).collect(Collectors.toList()), attemptsLeft);
    }

    /**
     * Ticks the entries with one of the labels in a chart view's series list
     * (CPU Usage's threads, a latency scatter's call or thread names) and
     * tells its chart, as a user's click would; with no labels, every entry
     * below the trace. The list fills in asynchronously after the view
     * opens, so this retries once a second for a while.
     */
    private void tickInChartList(String viewId, List<String> labels, int attemptsLeft) {
        String viewName = displayNameForViewId(viewId);
        IWorkbenchWindow window = PlatformUI.getWorkbench().getActiveWorkbenchWindow();
        IWorkbenchPage page = window == null ? null : window.getActivePage();
        IViewPart part = page == null ? null : page.findView(viewId);
        if (!(part instanceof org.eclipse.tracecompass.tmf.ui.views.xychart.TmfChartView)) {
            driverLog(viewName + ": view " + (part == null ? "not open" : "of unexpected type " + part.getClass().getName())
                    + "; attempts left " + attemptsLeft);
            if (part == null && attemptsLeft > 0) {
                Display.getDefault().timerExec(1000, () -> tickInChartList(viewId, labels, attemptsLeft - 1));
            }
            return;
        }
        org.eclipse.tracecompass.tmf.ui.views.xychart.TmfChartView chartView =
                (org.eclipse.tracecompass.tmf.ui.views.xychart.TmfChartView) part;
        if (!(chartView.getLeftChildViewer() instanceof org.eclipse.tracecompass.tmf.ui.viewers.tree.AbstractSelectTreeViewer2)) {
            driverLog(viewName + ": series list is " + chartView.getLeftChildViewer());
            return;
        }
        org.eclipse.tracecompass.tmf.ui.viewers.tree.AbstractSelectTreeViewer2 tree =
                (org.eclipse.tracecompass.tmf.ui.viewers.tree.AbstractSelectTreeViewer2) chartView.getLeftChildViewer();
        org.eclipse.jface.viewers.CheckboxTreeViewer viewer = tree.getTriStateFilteredCheckboxTree().getCheckboxTreeViewer();
        List<Object> found = new ArrayList<>();
        Object input = viewer.getInput();
        if (input instanceof org.eclipse.tracecompass.tmf.ui.viewers.tree.ITmfTreeViewerEntry) {
            collectEntries((org.eclipse.tracecompass.tmf.ui.viewers.tree.ITmfTreeViewerEntry) input, labels, 0, found);
        }
        driverLog(viewName + ": list input " + (input == null ? "null" : input.getClass().getSimpleName())
                + ", entries matching " + (labels.isEmpty() ? "(all)" : labels) + ": " + found.size()
                + ", attempts left " + attemptsLeft);
        if (found.isEmpty()) {
            if (attemptsLeft > 0) {
                Display.getDefault().timerExec(1000, () -> tickInChartList(viewId, labels, attemptsLeft - 1));
            }
            return;
        }
        /*
         * Tick each entry the way a click does: set it, then fire the tree's
         * check-state event. The tree's own listener then saves its checked
         * state (otherwise its next refresh restores the old one and drops
         * the tick) and updates the chart.
         */
        for (Object entry : found) {
            if (viewer.getChecked(entry)) {
                continue;
            }
            tree.getTriStateFilteredCheckboxTree().setChecked(entry, true);
            try {
                java.lang.reflect.Method fire = org.eclipse.jface.viewers.CheckboxTreeViewer.class.getDeclaredMethod(
                        "fireCheckStateChanged", org.eclipse.jface.viewers.CheckStateChangedEvent.class);
                fire.setAccessible(true);
                fire.invoke(viewer, new org.eclipse.jface.viewers.CheckStateChangedEvent(viewer, entry, true));
            } catch (ReflectiveOperationException | RuntimeException exception) {
                driverLog(viewName + ": could not fire the check event: " + exception);
            }
        }
        viewer.setSelection(new org.eclipse.jface.viewers.StructuredSelection(found.get(0)), true);
        driverLog(viewName + ": ticked " + found.size() + " entr(ies); now checked: "
                + found.stream().map(viewer::getChecked).collect(Collectors.toList()));
    }

    /** Appends a line to /tmp/tracecompass_view_driver.log (what the view driver saw and did). */
    private static void driverLog(String message) {
        try {
            java.nio.file.Files.writeString(java.nio.file.Path.of("/tmp/tracecompass_view_driver.log"),
                    java.time.LocalTime.now() + " " + message + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (java.io.IOException exception) {
            // diagnostics only
        }
    }

    /** Entries whose labels include one of the labels; with none, every entry below the trace's own (depth > 1). */
    private static void collectEntries(org.eclipse.tracecompass.tmf.ui.viewers.tree.ITmfTreeViewerEntry entry,
            List<String> labels, int depth, List<Object> found) {
        if (entry instanceof org.eclipse.tracecompass.tmf.ui.viewers.tree.TmfGenericTreeEntry) {
            Object model = ((org.eclipse.tracecompass.tmf.ui.viewers.tree.TmfGenericTreeEntry<?>) entry).getModel();
            if (model instanceof org.eclipse.tracecompass.tmf.core.model.tree.ITmfTreeDataModel) {
                List<String> entryLabels = ((org.eclipse.tracecompass.tmf.core.model.tree.ITmfTreeDataModel) model).getLabels();
                if (labels.isEmpty() ? depth > 1 : labels.stream().anyMatch(entryLabels::contains)) {
                    found.add(entry);
                }
            }
        }
        for (org.eclipse.tracecompass.tmf.ui.viewers.tree.ITmfTreeViewerEntry child : entry.getChildren()) {
            collectEntries(child, labels, depth + 1, found);
        }
    }

    /**
     * "show cpu usage of thread 159975 between 13.9 s and 14.0 s": opens the
     * view focused on that thread and range, without asking the LLM.
     * Returns null when the message is not such a command.
     */
    private String tryHandleViewFocusCommand(String userMessage, Integer tid) {
        String normalized = normalizeCommandText(userMessage);
        if (!looksLikeViewCommand(normalized)) {
            return null;
        }
        String viewId = resolveViewId(normalized);
        ITmfTrace trace = TmfTraceManager.getInstance().getActiveTrace();
        if (viewId == null || trace == null) {
            return null;
        }
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        TimeWindow window = parseTimeWindow(userMessage, traceStart, traceEnd);
        if (tid == null && window == null) {
            return null;
        }
        long start = window != null ? window.startNs : traceStart;
        long end = window != null ? window.endNs : traceEnd;
        long pad = Math.max((end - start) / 10, 1_000L);
        JsonObject viewPlan = new JsonObject();
        JsonArray views = new JsonArray();
        JsonObject view = new JsonObject();
        view.addProperty("id", viewId);
        view.addProperty("name", displayNameForViewId(viewId));
        views.add(view);
        viewPlan.add("views", views);
        JsonObject selection = new JsonObject();
        selection.addProperty("start_ns", start);
        selection.addProperty("end_ns", end);
        viewPlan.add("selection", selection);
        JsonObject zoom = new JsonObject();
        zoom.addProperty("start_ns", Math.max(traceStart, start - pad));
        zoom.addProperty("end_ns", Math.min(traceEnd, end + pad));
        viewPlan.add("zoom", zoom);
        JsonArray plot = new JsonArray();
        if (tid != null) {
            viewPlan.addProperty("select_tid", tid);
            if (VIEW_CRITICAL_PATH.equals(viewId) || VIEW_RESOURCES.equals(viewId)) {
                viewPlan.addProperty("follow_tid", tid);
            }
            if (VIEW_CPU_USAGE.equals(viewId)) {
                plot.add(tid);
            }
        }
        viewPlan.add("plot_tids", plot);
        showViewPlan(viewPlan);
        return String.format(Locale.ROOT, "Showing %s, %,.3f–%,.3f ms%s.", displayNameForViewId(viewId),
                (start - traceStart) / 1_000_000.0, (end - traceStart) / 1_000_000.0,
                tid == null ? "" : ", focused on TID " + tid);
    }

    private static String tryHandleViewCommand(
            String userMessage) {

        String normalized =
                normalizeCommandText(
                        userMessage);

        if (!looksLikeViewCommand(normalized)) {
            return null;
        }

        String viewId =
                resolveViewId(
                        normalized);

        if (viewId == null) {
            /* "show me thread X's activity ..." is a question for the pipeline, not a view command. */
            return null;
        }

        try {
            openWorkbenchView(
                    viewId);
            return "Opened view: " +
                    displayNameForViewId(
                            viewId);
        } catch (PartInitException exception) {
            return "I found the view, but Eclipse could not open it: " +
                    exception.getMessage();
        }
    }

    private static boolean looksLikeViewCommand(
            String normalized) {

        return normalized.contains("open ") ||
                normalized.contains("show ") ||
                normalized.contains("display ") ||
                normalized.contains("bring up ") ||
                normalized.contains("switch to ");
    }

    private static String resolveViewId(
            String normalized) {

        Matcher explicitViewId =
                Pattern
                        .compile(
                                "\\borg\\.eclipse\\.[a-z0-9_.:-]+")
                        .matcher(
                                normalized);

        if (explicitViewId.find()) {
            return explicitViewId.group();
        }

        for (Map.Entry<String, String> entry : VIEW_ALIASES.entrySet()) {
            if (normalized.contains(entry.getKey())) {
                return entry.getValue();
            }
        }

        return null;
    }

    private static void openWorkbenchView(
            String viewId) throws PartInitException {

        IWorkbenchWindow window =
                PlatformUI
                        .getWorkbench()
                        .getActiveWorkbenchWindow();

        if (window == null) {
            throw new PartInitException(
                    "No active workbench window is available.");
        }

        IWorkbenchPage page =
                window
                        .getActivePage();

        if (page == null) {
            throw new PartInitException(
                    "No active workbench page is available.");
        }

        int colon = viewId.indexOf(':');
        if (colon > 0) {
            page.showView(viewId.substring(0, colon), viewId.substring(colon + 1), IWorkbenchPage.VIEW_ACTIVATE);
        } else {
            page.showView(viewId);
        }
    }

    /**
     * Sends the text from the message box to OpenAI.
     */
    private void sendMessage() {
        String userMessage =
                messageBox.getText().trim();

        if (userMessage.isEmpty()) {
            return;
        }

        List<String> questions = splitQuestions(userMessage);
        if (questions.size() > 1) {
            sendBatch(questions);
            return;
        }

        Integer requestedTid =
                extractTid(userMessage);

        boolean ragEnabled =
                ragToggle.getSelection();

        conversation.append(
                "\nYou:\n" +
                userMessage +
                "\n");

        String showBatchResult = tryHandleShowBatchViews(userMessage);
        if (showBatchResult != null) {
            conversation.append("\nAssistant:\n" + showBatchResult + "\n");
            messageBox.setText("");
            conversation.setSelection(conversation.getCharCount());
            messageBox.setFocus();
            return;
        }

        String highlightCommandResult =
                tryHandleHighlightThreadCommand(
                        userMessage,
                        requestedTid);

        if (highlightCommandResult != null) {
            conversation.append(
                    "\nAssistant:\n" +
                    highlightCommandResult +
                    "\n");

            messageBox.setText("");
            conversation.setSelection(
                    conversation.getCharCount());
            messageBox.setFocus();
            return;
        }

        /*
         * tryHandleCriticalPathCommand() can run OSCriticalPathModule
         * unbounded, which has been measured taking 40+ seconds on a
         * worker with a large recorded history (critical_path_improvements.md).
         * Calling it directly here, on the SWT UI thread sendMessage()
         * itself runs on, froze the whole application for that entire
         * duration -- this is what "Trace Compass becomes frozen" was.
         * Fixed by running it the same way the main LLM pipeline already
         * runs below: off the UI thread, with a "Thinking..." placeholder
         * and the result appended asynchronously once it completes.
         */
        boolean isCriticalPathCommand =
                requestedTid != null &&
                CRITICAL_PATH_COMMAND_PATTERN
                        .matcher(userMessage)
                        .find();

        if (isCriticalPathCommand) {
            conversation.append(
                    "\nAssistant:\nThinking...\n");

            messageBox.setText("");
            sendButton.setEnabled(false);

            CompletableFuture
                    .supplyAsync(() ->
                            tryHandleCriticalPathCommand(
                                    userMessage,
                                    requestedTid))
                    .whenComplete((criticalPathCommandResult, error) -> {
                        Display.getDefault().asyncExec(() -> {
                            if (conversation == null ||
                                    conversation.isDisposed()) {
                                return;
                            }

                            removeThinkingMessage();

                            if (error != null) {
                                Throwable cause =
                                        error.getCause() != null ?
                                                error.getCause() :
                                                error;

                                String errorMessage =
                                        cause.getMessage() != null ?
                                                cause.getMessage() :
                                                cause.toString();

                                conversation.append(
                                        "\nError:\n" +
                                        errorMessage +
                                        "\n");
                            } else {
                                conversation.append(
                                        "\nAssistant:\n" +
                                        criticalPathCommandResult +
                                        "\n");
                            }

                            conversation.setSelection(
                                    conversation.getCharCount());

                            sendButton.setEnabled(true);
                            messageBox.setFocus();
                        });
                    });

            return;
        }

        String focusCommandResult = tryHandleViewFocusCommand(userMessage, requestedTid);
        String viewCommandResult = focusCommandResult != null ? focusCommandResult
                : tryHandleViewCommand(
                        userMessage);

        if (viewCommandResult != null) {
            conversation.append(
                    "\nAssistant:\n" +
                    viewCommandResult +
                    "\n");

            messageBox.setText("");
            conversation.setSelection(
                    conversation.getCharCount());
            messageBox.setFocus();
            return;
        }

        conversation.append(
                "\nAssistant:\nThinking...\n");

        messageBox.setText("");
        sendButton.setEnabled(false);

        /*
         * Run the Trace Compass analysis and network request outside
         * Eclipse's UI thread.
         */
        CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return answerQuestion(userMessage, requestedTid, ragEnabled, true);
                    } catch (Exception exception) {
                        throw new CompletionException(exception);
                    }
                })
                .whenComplete((answer, error) -> {
                    Display.getDefault().asyncExec(() -> {
                        if (conversation == null ||
                                conversation.isDisposed()) {
                            return;
                        }

                        removeThinkingMessage();

                        if (error != null) {
                            Throwable cause =
                                    error.getCause() != null
                                            ? error.getCause()
                                            : error;

                            String errorMessage =
                                    cause.getMessage() != null
                                            ? cause.getMessage()
                                            : cause.toString();

                            conversation.append(
                                    "\nError:\n" +
                                    errorMessage +
                                    "\n");
                        } else {
                            conversation.append(
                                    "\nAssistant:\n");

                            appendMarkdown(answer);

                            conversation.append("\n");
                        }

                        conversation.setSelection(
                                conversation.getCharCount());

                        sendButton.setEnabled(true);
                        messageBox.setFocus();
                    });
                });
    }

    /**
     * Answers one question end to end (pipeline, LLM, answer log) and
     * returns the answer with its timing breakdown. Runs off the UI thread;
     * carries the conversation (previous answer, previous subject) forward.
     */
    private String answerQuestion(String userMessage, Integer requestedTid, boolean ragEnabled) throws Exception {
        return answerQuestion(userMessage, requestedTid, ragEnabled, false);
    }

    /**
     * @param showViews
     *            open and focus the views that show the answer (single
     *            questions; a batch would replace them on every answer)
     */
    private String answerQuestion(String userMessage, Integer requestedTid, boolean ragEnabled, boolean showViews)
            throws Exception {
        long pipelineStartNanos = System.nanoTime();
        Map<String, Long> stageDurationsNs =
                new LinkedHashMap<>();
        JsonObject serverReportedTiming = null;
        PipelineContext built = null;
        String previousIdUsed = previousResponseId;
        lastViewPlan = null;

        try {
            built =
                    pipeline.buildAnswerContext(
                            userMessage,
                            requestedTid,
                            ragEnabled,
                            stageDurationsNs,
                            lastTarget);
            lastTarget = built.target;
            lastViewPlan = built.viewPlan;
            JsonObject combinedContext = built.context;
            serverReportedTiming = built.serverReportedTiming;

            dumpLastContext(combinedContext);

            String answer =
                    timed(
                            stageDurationsNs,
                            "llm_call",
                            () -> callOpenAI(
                                    userMessage,
                                    combinedContext.toString()));

            long totalPipelineNanos =
                    System.nanoTime() - pipelineStartNanos;

            AnswerLog.record(userMessage, requestedTid, ragEnabled, built,
                    answer, null, lastResponseMeta, previousIdUsed,
                    stageDurationsNs, totalPipelineNanos);

            /* TraceAssist picked the thread (no TID): the code-written reason opens the answer. */
            String why = ThreadSearch.whySection(UnifiedExplainer.obj(built.plan, "thread_finder"));
            if (why != null) {
                answer = why + "\n\n" + answer;
            }
            String shown = "";
            if (showViews && built.viewPlan != null) {
                showViewPlan(built.viewPlan);
                shown = "\n\nShown in Trace Compass: " + UnifiedExplainer.str(built.viewPlan, "summary");
            }
            return answer + shown +
                    formatTimingBreakdown(
                            stageDurationsNs,
                            serverReportedTiming,
                            totalPipelineNanos);
        } catch (Exception exception) {
            AnswerLog.record(userMessage, requestedTid, ragEnabled, built,
                    null, exception.toString(), null, previousIdUsed,
                    stageDurationsNs, System.nanoTime() - pipelineStartNanos);
            throw exception;
        }
    }

    /** "show Q3", "show views for Q3", "open q3", "show Q3 views". */
    private static final Pattern SHOW_BATCH_VIEWS_PATTERN = Pattern.compile(
            "(?i)^\\s*(?:show|open|view|display)\\s+(?:me\\s+)?(?:the\\s+)?(?:views?\\s+(?:for|of)\\s+)?"
                    + "q(?:uestion)?\\s*(\\d+)(?:'s)?(?:\\s+(?:views?|in\\s+trace\\s+compass))?\\s*[.!?]?\\s*$");

    /**
     * "show Q3": opens the views for the last batch's third answer, on the
     * trace it was answered on. Returns null when the message is not such a
     * command.
     */
    private String tryHandleShowBatchViews(String message) {
        Matcher matcher = SHOW_BATCH_VIEWS_PATTERN.matcher(message);
        if (!matcher.matches()) {
            return null;
        }
        int number = Integer.parseInt(matcher.group(1));
        JsonObject viewPlan = batchViewPlans.get(number);
        if (viewPlan == null) {
            return batchViewPlans.isEmpty()
                    ? "There is no batch to show views for: paste several questions (one per line) first."
                    : "Q" + number + " has no views to show. Answers with views: "
                            + batchViewPlans.keySet().stream().sorted().map(n -> "Q" + n).collect(Collectors.joining(", ")) + ".";
        }
        ITmfTrace trace = batchViewTraces.get(number);
        if (trace == null || !TmfTraceManager.getInstance().getOpenedTraces().contains(trace)) {
            return "The trace Q" + number + " was answered on is no longer open; open it again and re-ask the question.";
        }
        showViewPlan(viewPlan, trace);
        return "Shown in Trace Compass (Q" + number + "): " + UnifiedExplainer.str(viewPlan, "summary");
    }

    /** Puts text before the answer's timing breakdown, or at the end. */
    private static String insertBeforeTiming(String answer, String text) {
        int timing = answer.indexOf("\n\n---\n**Timing breakdown**");
        return timing < 0 ? answer + text : answer.substring(0, timing) + text + answer.substring(timing);
    }

    /** Leading "1.", "Q1:", "1)", "-" or "*" on a pasted question. */
    private static final Pattern QUESTION_NUMBERING =
            Pattern.compile("(?i)^(?:q\\s*\\d+|\\d+)\\s*[.:)\\-]\\s*|^[-*\\u2022]\\s+");

    /** The questions in a message: one per non-empty line, numbering stripped. */
    static List<String> splitQuestions(String message) {
        List<String> questions = new ArrayList<>();
        for (String line : message.split("\\r?\\n")) {
            String question = QUESTION_NUMBERING.matcher(line.trim()).replaceFirst("").trim();
            if (!question.isEmpty()) {
                questions.add(question);
            }
        }
        return questions;
    }

    /**
     * Several questions pasted at once (one per line): answers them one at a
     * time, in order, in the same conversation, posting each answer as
     * "Qn: question / Ans: answer" as soon as it is ready. A follow-up
     * question continues from the one before it, as in the normal chat.
     */
    private void sendBatch(List<String> questions) {
        boolean ragEnabled = ragToggle.getSelection();
        StringBuilder asked = new StringBuilder();
        for (int i = 0; i < questions.size(); i++) {
            asked.append("Q").append(i + 1).append(": ").append(questions.get(i)).append("\n");
        }
        conversation.append("\nYou:\n" + asked);
        batchViewPlans.clear();
        batchViewTraces.clear();
        ITmfTrace batchTrace = TmfTraceManager.getInstance().getActiveTrace();
        String traceLine = batchTrace == null ? "no trace is open"
                : String.format(Locale.ROOT, "%s (0 to %,.3f ms)", batchTrace.getName(),
                        (batchTrace.getEndTime().toNanos() - batchTrace.getStartTime().toNanos()) / 1_000_000.0);
        conversation.append("\nAssistant:\nAnswering " + questions.size()
                + " questions one at a time, in order; each answer appears when it is ready.\nTrace: " + traceLine
                + " (the selected trace; keep it selected until the batch finishes)\n");
        messageBox.setText("");
        sendButton.setEnabled(false);
        CompletableFuture.runAsync(() -> {
            for (int i = 0; i < questions.size(); i++) {
                String question = questions.get(i);
                int number = i + 1;
                Display.getDefault().syncExec(() -> {
                    if (conversation != null && !conversation.isDisposed()) {
                        conversation.append("\n[Working on Q" + number + " of " + questions.size() + "...]\n");
                        conversation.setSelection(conversation.getCharCount());
                    }
                });
                String answer;
                try {
                    answer = answerQuestion(question, extractTid(question), ragEnabled);
                    // Views are not opened during a batch (each answer would replace the last); "show Qn" opens them.
                    JsonObject viewPlan = lastViewPlan;
                    if (viewPlan != null && batchTrace != null) {
                        batchViewPlans.put(number, viewPlan);
                        batchViewTraces.put(number, batchTrace);
                        answer = insertBeforeTiming(answer, "\n\nViews for this answer (type \"show Q" + number
                                + "\" to open them): " + UnifiedExplainer.str(viewPlan, "summary"));
                    }
                } catch (Exception exception) {
                    Throwable cause = exception.getCause() != null ? exception.getCause() : exception;
                    answer = "Error: " + (cause.getMessage() != null ? cause.getMessage() : cause.toString());
                }
                String finalAnswer = answer;
                Display.getDefault().syncExec(() -> {
                    if (conversation == null || conversation.isDisposed()) {
                        return;
                    }
                    conversation.append("\nQ" + number + ": " + question + "\nAns: ");
                    appendMarkdown(finalAnswer);
                    conversation.append("\n");
                    conversation.setSelection(conversation.getCharCount());
                });
            }
        }).whenComplete((ignored, error) -> Display.getDefault().asyncExec(() -> {
            if (conversation == null || conversation.isDisposed()) {
                return;
            }
            String showHint = batchViewPlans.isEmpty() ? ""
                    : " To see an answer in Trace Compass, type \"show Q<n>\" (e.g. \"show Q"
                            + batchViewPlans.keySet().stream().sorted().findFirst().get() + "\").";
            conversation.append(error == null
                    ? "\nAll " + questions.size() + " questions answered." + showHint + "\n"
                    : "\nBatch stopped: " + error + "\n");
            conversation.setSelection(conversation.getCharCount());
            sendButton.setEnabled(true);
            messageBox.setFocus();
        }));
    }

    /**
     * Human-readable label for each stage key used with {@link #timed}.
     */
    private static String stageLabel(String stageName) {
        switch (stageName) {
            case "trace_overview":
                return "Trace overview (Java)";
            case "window_finder":
                return "Late-cycle window finder (TMLL, planner-gated)";
            case "unified_explainer":
                return "Unified explainer (Java: state split + per-state explainers)";
            case "target_resolver":
                return "Process/thread name resolver (Java)";
            case "thread_finder":
                return "Thread finder (AI skill: trace inventory + which thread, process or trace the question is about)";
            case "view_picker":
                return "View picker (AI skill: which views, moment, focus and what to look at; code zooms)";
            case "thread_search":
                return "Thread search (Java: the suspects' analyses, level by level, within the event budget)";
            case "process_explainer":
                return "Process explainer (Java: per-thread split + who woke whom)";
            case "process_context":
                return "Process context (Java: the thread's part in its process's wait chain; cached per process)";
            case "tmll_series":
                return "TMLL z-score over the main thread's waits (Python)";
            case "trace_explainer":
                return "Trace explainer (Java: events recorded, processes, workload)";
            case "tmll_analysis":
                return "TMLL evidence (Python, syscall mix + cross-host)";
            case "rag_retrieval":
                return "RAG retrieval (Python, documents for the findings' concepts)";
            case "llm_call":
                return "LLM call";
            default:
                return stageName;
        }
    }

    private static String formatSeconds(long nanos) {
        return String.format("%.3fs", nanos / 1_000_000_000.0);
    }

    private static String formatMillisAsSeconds(double millis) {
        return String.format("%.3fs", millis / 1000.0);
    }

    /**
     * Builds a human-readable timing breakdown to append after the
     * assistant's answer.
     *
     * {@code stageDurationsNs} holds one entry per top-level stage actually
     * run for this question (a stage is absent, not zero, when it was
     * skipped -- e.g. no TID in the question, or the RAG toggle is off).
     * {@code serverReportedTiming}, when present, is the "timing_ms" object
     * the TMLL/RAG Python service reports on its own response, which splits
     * what Java only sees as one combined network call
     * ("tmll_rag_service_call") into the service's own internally-measured
     * TMLL-analysis time and RAG-retrieval time. The remainder --
     * measured round-trip minus what the service reports doing -- is
     * network transfer and JSON (de)serialization overhead, shown
     * separately rather than folded silently into either side.
     */
    private static String formatTimingBreakdown(
            Map<String, Long> stageDurationsNs,
            JsonObject tmllTiming,
            long totalPipelineNanos) {

        StringBuilder builder = new StringBuilder();
        builder.append("\n\n---\n**Timing breakdown**\n");

        for (Map.Entry<String, Long> stage : stageDurationsNs.entrySet()) {
            builder.append("- ")
                    .append(stageLabel(stage.getKey()))
                    .append(": ")
                    .append(formatSeconds(stage.getValue()))
                    .append("\n");

            if ("tmll_analysis".equals(stage.getKey()) && tmllTiming != null) {
                if (tmllTiming.has("tmll_analysis_ms")) {
                    builder.append("    - TMLL analysis (server-reported): ")
                            .append(formatMillisAsSeconds(tmllTiming.get("tmll_analysis_ms").getAsDouble()))
                            .append("\n");
                }
                if (tmllTiming.has("cache")) {
                    builder.append("    - TMLL cache: ")
                            .append(tmllTiming.get("cache").getAsString())
                            .append("\n");
                }
            }
        }

        builder.append("- **Total: ")
                .append(formatSeconds(totalPipelineNanos))
                .append("**\n");

        return builder.toString();
    }

    /**
     * Removes the temporary "Thinking..." message.
     */
    private void removeThinkingMessage() {
        String currentText = conversation.getText();

        String thinking =
                "\nAssistant:\nThinking...\n";

        if (currentText.endsWith(thinking)) {
            int start =
                    currentText.length() -
                    thinking.length();

            conversation.replaceTextRange(
                    start,
                    thinking.length(),
                    "");
        }
    }

    /**
     * Appends assistant text and renders Markdown double-asterisk spans
     * using SWT bold styling.
     *
     * For example, "**blocked**" is displayed as "blocked" in bold.
     */
    private void appendMarkdown(String markdown) {
        Pattern boldPattern =
                Pattern.compile(
                        "\\*\\*(.+?)\\*\\*",
                        Pattern.DOTALL);

        Matcher matcher =
                boldPattern.matcher(markdown);

        int previousEnd = 0;

        while (matcher.find()) {
            conversation.append(
                    markdown.substring(
                            previousEnd,
                            matcher.start()));

            int boldStart =
                    conversation.getCharCount();

            String boldText = matcher.group(1);
            conversation.append(boldText);

            StyleRange boldStyle =
                    new StyleRange();

            boldStyle.start = boldStart;
            boldStyle.length = boldText.length();
            boldStyle.fontStyle = SWT.BOLD;

            conversation.setStyleRange(boldStyle);

            previousEnd = matcher.end();
        }

        conversation.append(
                markdown.substring(previousEnd));
    }

    /**
     * Adds two non-negative durations without overflowing.
     */
    private static long safeAdd(
            long first,
            long second) {

        if (Long.MAX_VALUE - first < second) {
            return Long.MAX_VALUE;
        }

        return first + second;
    }

    /**
     * Writes the exact context handed to the LLM to
     * {@code <java.io.tmpdir>/tracecompass_last_context.json}, so an answer
     * can be checked against what the model was actually given.
     */
    private static void dumpLastContext(JsonObject combinedContext) {
        try {
            Files.writeString(
                    Path.of(
                            System.getProperty("java.io.tmpdir"),
                            "tracecompass_last_context.json"),
                    combinedContext.toString());
        } catch (IOException exception) {
            System.err.println(
                    "Could not write last LLM context: " +
                    exception.getMessage());
        }
    }

    /**
     * Appends every chat answer to a CSV file for the CASCON experiment, and
     * saves the exact context the LLM received in a contexts/ folder next to
     * it, so each answer can be graded against what the framework computed.
     *
     * The file is {@code $TRACECOMPASS_RESULTS_CSV} if set, otherwise
     * ~/research/TraceCompass AI Agent/CASCON/Experiment/framework_results/answers.csv.
     * Logging never fails an answer: errors are only printed.
     */
    static final class AnswerLog {

        private static final String[] COLUMNS = {
                "time", "trace", "trace_path", "question", "answer", "status", "error",
                "requested_tid", "rag_enabled", "previous_response_id", "response_model",
                "response_id", "finding_ids", "document_titles", "input_tokens",
                "cached_tokens", "output_tokens", "reasoning_tokens", "stage_durations_s",
                "total_s", "context_file" };

        /** "2m", "10m" or "30m" from a run folder such as batch-server-2m-20261013-190630. */
        private static final Pattern TRACE_LABEL = Pattern.compile("batch-server-(\\d+m)-");

        static Path csvPath() {
            String override = System.getenv("TRACECOMPASS_RESULTS_CSV");
            if (override != null && !override.isBlank()) {
                return Path.of(override);
            }
            return Path.of(System.getProperty("user.home"), "research", "TraceCompass AI Agent",
                    "CASCON", "Experiment", "framework_results", "answers.csv");
        }

        static synchronized void record(String question, @Nullable Integer requestedTid,
                boolean ragEnabled, @Nullable PipelineContext built, @Nullable String answer,
                @Nullable String error, @Nullable JsonObject responseMeta,
                @Nullable String previousResponseId, Map<String, Long> stageDurationsNs,
                long totalNanos) {
            try {
                Path csv = csvPath();
                Path contexts = csv.resolveSibling("contexts");
                Files.createDirectories(contexts);

                String time = java.time.OffsetDateTime.now()
                        .truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
                String tracePath = activeTracePath();
                Matcher label = TRACE_LABEL.matcher(tracePath == null ? "" : tracePath);

                String contextFile = "";
                List<String> findingIds = new ArrayList<>();
                List<String> documentTitles = new ArrayList<>();
                if (built != null) {
                    contextFile = time.replace(':', '-') + "_"
                            + Integer.toHexString(question.hashCode()) + ".json";
                    Files.writeString(contexts.resolve(contextFile), built.context.toString());
                    for (JsonElement finding : built.findings) {
                        findingIds.add(String.valueOf(
                                UnifiedExplainer.str(finding.getAsJsonObject(), "id")));
                    }
                    for (JsonElement document : UnifiedExplainer.arr(built.context, "documents")) {
                        documentTitles.add(String.valueOf(
                                UnifiedExplainer.str(document.getAsJsonObject(), "title")));
                    }
                }

                JsonObject usage = UnifiedExplainer.obj(responseMeta, "usage");
                String stages = stageDurationsNs.entrySet().stream()
                        .map(stage -> stage.getKey() + "=" + formatSeconds(stage.getValue()))
                        .collect(Collectors.joining("; "));

                List<String> row = new ArrayList<>();
                row.add(time);
                row.add(label.find() ? label.group(1) : "");
                row.add(tracePath);
                row.add(question);
                row.add(answer);
                row.add(error == null ? "ok" : "error");
                row.add(error);
                row.add(requestedTid == null ? null : requestedTid.toString());
                row.add(Boolean.toString(ragEnabled));
                row.add(previousResponseId);
                row.add(UnifiedExplainer.str(responseMeta, "model"));
                row.add(UnifiedExplainer.str(responseMeta, "id"));
                row.add(String.join(" ", findingIds));
                row.add(String.join(" | ", documentTitles));
                row.add(tokenCount(usage, null, "input_tokens"));
                row.add(tokenCount(usage, "input_tokens_details", "cached_tokens"));
                row.add(tokenCount(usage, null, "output_tokens"));
                row.add(tokenCount(usage, "output_tokens_details", "reasoning_tokens"));
                row.add(stages);
                row.add(String.format(Locale.ROOT, "%.3f", totalNanos / 1_000_000_000.0));
                row.add(contextFile);

                StringBuilder lines = new StringBuilder();
                if (!Files.exists(csv)) {
                    lines.append(csvLine(java.util.Arrays.asList(COLUMNS)));
                }
                lines.append(csvLine(row));
                Files.writeString(csv, lines, StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception exception) {
                System.err.println("Could not record answer to CSV: " + exception);
            }
        }

        private static @Nullable String tokenCount(@Nullable JsonObject usage,
                @Nullable String detailsKey, String key) {
            JsonObject parent = detailsKey == null ? usage : UnifiedExplainer.obj(usage, detailsKey);
            long value = UnifiedExplainer.num(parent, key, -1L);
            return value < 0 ? null : Long.toString(value);
        }

        /** One RFC 4180 line: every field quoted, quotes doubled, null as empty. */
        private static String csvLine(List<String> fields) {
            return fields.stream()
                    .map(field -> field == null ? "" : field)
                    .map(field -> "\"" + field.replace("\"", "\"\"") + "\"")
                    .collect(Collectors.joining(",")) + "\n";
        }
    }

    /**
     * Sends the user's question and Trace Compass context to OpenAI
     * ({@link AnswerWriter}), continuing the conversation, and records the
     * response's id, model and usage for the answer log.
     */
    private String callOpenAI(
            String userMessage,
            String traceContext) throws Exception {
        AnswerWriter.Answer answer = AnswerWriter.write(userMessage, traceContext, previousResponseId, null);
        lastResponseMeta = answer.meta();
        if (answer.responseId() != null) {
            previousResponseId = answer.responseId();
        }
        return answer.text();
    }

    @Override
    public void setFocus() {
        if (messageBox != null &&
                !messageBox.isDisposed()) {
            messageBox.setFocus();
        }
    }

    @Override
    public void dispose() {
        TmfSignalManager.deregister(this);
        if (testServer != null) {
            testServer.stop();
            testServer = null;
        }
        super.dispose();
    }
}
