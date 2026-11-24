package org.eclipse.tracecompass.helloworld.ui.views;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.analysis.os.linux.core.model.ProcessStatus;
import org.eclipse.tracecompass.statesystem.core.interval.ITmfStateInterval;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PartInitException;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.part.ViewPart;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class HelloWorldRagView extends ViewPart {

    public static final String ID =
            "org.eclipse.tracecompass.helloworld.ui.views.HelloWorldRagView";

    /*
     * Maximum number of detailed thread records sent to OpenAI.
     */
    private static final int MAX_THREAD_DETAILS = 100;

    /*
     * Maximum number of individual Control Flow intervals included
     * in the API request.
     *
     * Summary totals are still calculated using every interval.
     */
    private static final int MAX_CONTROL_FLOW_INTERVALS = 250;

    /*
     * Trace Server experiment used by the local TMLL service.
     *
     * This is the Noferesti ELK-stack kernel trace (TraceLens dataset).
     */
    private static final String DEFAULT_TMLL_EXPERIMENT_ID =
            "c292526d-438e-3002-9058-6f56a57a6446";

    private static final String TMLL_THREAD_ANALYSIS_URL =
            "http://127.0.0.1:8000/analyze/thread";

    private static final String TMLL_THREAD_RAG_URL =
            "http://127.0.0.1:8000/answer/thread";

    private static final Map<String, String> VIEW_ALIASES =
            createViewAliases();

    private final HttpClient httpClient =
            HttpClient.newHttpClient();

    private StyledText conversation;
    private Text messageBox;
    private Button sendButton;
    private Font chatFont;

    /*
     * Used to continue the previous OpenAI conversation.
     */
    private String previousResponseId;

    private static Map<String, String> createViewAliases() {
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
                ID);
        aliases.put(
                "rag",
                ID);
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

    @Override
    public void createPartControl(Composite parent) {
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

    private static Integer extractTid(String question) {
        Pattern pattern = Pattern.compile(
                "(?i)\\b(?:tid|thread)\\s*[:#]?\\s*(\\d+)\\b");

        Matcher matcher = pattern.matcher(question);

        if (matcher.find()) {
            return Integer.valueOf(matcher.group(1));
        }

        return null;
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
            return "I can open Trace Compass views, but I do not recognize " +
                    "that view yet. Try Control Flow, Resources, CPU Usage, " +
                    "System Call Latency, Statistics, Histogram, Event Density, " +
                    "Critical Path, Filters, Colors, Time Chart, TraceAssist, " +
                    "or TraceAssist RAG.";
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

    private static String normalizeCommandText(
            String text) {

        return text
                .toLowerCase()
                .replaceAll("[^a-z0-9_.:-]+", " ")
                .trim();
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

        page.showView(
                viewId);
    }

    private static String displayNameForViewId(
            String viewId) {

        for (Map.Entry<String, String> entry : VIEW_ALIASES.entrySet()) {
            if (entry.getValue().equals(viewId)) {
                return entry.getKey();
            }
        }

        return viewId;
    }

    /**
     * Returns the Trace Server experiment UUID used by the local Python/TMLL
     * service. This can change when Trace Server is restarted, so allow the
     * launch configuration to override the fallback value.
     */
    private static String configuredTmllExperimentId() {
        String propertyValue =
                System.getProperty(
                        "tmll.experiment.id");

        if (propertyValue != null &&
                !propertyValue.isBlank()) {
            return propertyValue.trim();
        }

        String environmentValue =
                System.getenv(
                        "TMLL_EXPERIMENT_ID");

        if (environmentValue != null &&
                !environmentValue.isBlank()) {
            return environmentValue.trim();
        }

        return DEFAULT_TMLL_EXPERIMENT_ID;
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

        Integer requestedTid =
                extractTid(userMessage);

        conversation.append(
                "\nYou:\n" +
                userMessage +
                "\n");

        String viewCommandResult =
                tryHandleViewCommand(
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
                        String traceContext =
                                collectActiveTraceContext(
                                        requestedTid);

                        JsonObject combinedContext =
                                JsonParser
                                        .parseString(
                                                traceContext)
                                        .getAsJsonObject();

                        /*
                         * Add sampled TMLL/RAG evidence when the question names
                         * a thread. TMLL is supplemental, so a service error
                         * must not discard the exact Java analysis.
                         */
                        if (requestedTid != null) {
                            try {
                                String ragResult =
                                        callTmllThreadRag(
                                                configuredTmllExperimentId(),
                                                requestedTid,
                                                userMessage);

                                JsonObject ragJson =
                                        JsonParser
                                                .parseString(
                                                        ragResult)
                                                .getAsJsonObject();

                                combinedContext.add(
                                        "tmll_thread_analysis",
                                        ragJson.get(
                                                "analysis"));

                                combinedContext.add(
                                        "tmll_rag_context",
                                        ragJson.get(
                                                "rag"));

                                System.out.println(
                                        "TMLL RAG result:\n" +
                                        ragResult);
                            } catch (Exception exception) {
                                JsonObject unavailable =
                                        new JsonObject();

                                unavailable.addProperty(
                                        "available",
                                        false);

                                unavailable.addProperty(
                                        "error",
                                        exception.getMessage() != null
                                                ? exception.getMessage()
                                                : exception.toString());

                                combinedContext.add(
                                        "tmll_thread_analysis",
                                        unavailable);

                                combinedContext.add(
                                        "tmll_rag_context",
                                        unavailable);
                            }
                        }

                        return callOpenAI(
                                userMessage,
                                combinedContext.toString());
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
     * Collects information from the currently active Trace Compass trace.
     *
     * @return trace information represented as JSON
     */
    private String collectActiveTraceContext(
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
         * Collect Control Flow state information only when the
         * user's question explicitly contains a thread ID.
         */
        if (requestedTid != null) {
            JsonObject controlFlow =
                    collectThreadControlFlow(
                            kernelModule,
                            requestedTid,
                            start,
                            end,
                            start);

            context.addProperty(
                    "requested_tid",
                    requestedTid);

            context.add(
                    "requested_thread_control_flow",
                    controlFlow);
        } else {
            context.addProperty(
                    "requested_tid_supplied",
                    false);
        }

        /*
         * Collect all active threads over the trace range.
         */
        Set<Integer> activeThreads =
                KernelThreadInformationProvider
                        .getActiveThreadsForRange(
                                kernelModule,
                                start,
                                end);

        context.addProperty(
                "total_active_threads",
                activeThreads.size());

        JsonArray threads = new JsonArray();

        /*
         * A sorted set removes duplicate executable names.
         */
        Set<String> executableNames =
                new TreeSet<>();

        int includedThreadDetails = 0;

        for (Integer tid : activeThreads) {
            String executable =
                    KernelThreadInformationProvider
                            .getExecutableName(
                                    kernelModule,
                                    tid,
                                    end);

            if (executable != null &&
                    !executable.isBlank()) {
                executableNames.add(executable);
            }

            /*
             * Limit detailed thread records to control API cost.
             */
            if (includedThreadDetails >=
                    MAX_THREAD_DETAILS) {
                continue;
            }

            JsonObject thread = new JsonObject();

            thread.addProperty(
                    "tid",
                    tid);

            if (executable != null) {
                thread.addProperty(
                        "executable",
                        executable);
            }

            Integer pid =
                    KernelThreadInformationProvider
                            .getProcessId(
                                    kernelModule,
                                    tid,
                                    end);

            if (pid != null) {
                thread.addProperty(
                        "pid",
                        pid);
            }

            Integer parentPid =
                    KernelThreadInformationProvider
                            .getParentPid(
                                    kernelModule,
                                    tid,
                                    end);

            if (parentPid != null) {
                thread.addProperty(
                        "parent_pid",
                        parentPid);
            }

            threads.add(thread);
            includedThreadDetails++;
        }

        JsonArray executables = new JsonArray();

        for (String executableName : executableNames) {
            executables.add(executableName);
        }

        context.addProperty(
                "included_thread_details",
                includedThreadDetails);

        context.addProperty(
                "thread_details_truncated",
                activeThreads.size() >
                        includedThreadDetails);

        context.add(
                "active_executable_names",
                executables);

        context.add(
                "active_threads",
                threads);

        return context.toString();
    }

    /**
     * Retrieves the Control Flow state intervals for one thread.
     *
     * Trace Compass state-system intervals use inclusive start and
     * end timestamps.
     *
     * @param kernelModule
     *            completed Linux Kernel Analysis module
     * @param tid
     *            thread ID
     * @param requestedStart
     *            requested start timestamp
     * @param requestedEndInclusive
     *            requested inclusive end timestamp
     * @param traceStart
     *            beginning of the trace
     * @return structured Control Flow information
     */
    private static JsonObject collectThreadControlFlow(
            KernelAnalysisModule kernelModule,
            int tid,
            long requestedStart,
            long requestedEndInclusive,
            long traceStart) {

        JsonObject result = new JsonObject();

        result.addProperty(
                "tid",
                tid);

        result.addProperty(
                "requested_start_timestamp_ns",
                requestedStart);

        result.addProperty(
                "requested_end_timestamp_inclusive_ns",
                requestedEndInclusive);

        result.addProperty(
                "requested_start_offset_ns",
                requestedStart - traceStart);

        result.addProperty(
                "requested_end_offset_ns",
                requestedEndInclusive - traceStart);

        String executable =
                KernelThreadInformationProvider
                        .getExecutableName(
                                kernelModule,
                                tid,
                                requestedEndInclusive);

        if (executable != null) {
            result.addProperty(
                    "executable",
                    executable);
        }

        /*
         * A resolution of 1 requests all available status intervals.
         */
        Iterator<ITmfStateInterval> statusIntervals =
                KernelThreadInformationProvider
                        .getStatusIntervalsForThread(
                                kernelModule,
                                tid,
                                requestedStart,
                                requestedEndInclusive,
                                1L);

        JsonArray intervalsJson =
                new JsonArray();

        /*
         * Keep the total duration for each user-friendly state.
         */
        Map<String, Long> durationByState =
                new LinkedHashMap<>();

        int totalIntervalCount = 0;
        int includedIntervalCount = 0;

        while (statusIntervals.hasNext()) {
            ITmfStateInterval interval =
                    statusIntervals.next();

            /*
             * Clip the returned interval to the requested range.
             */
            long intervalStart =
                    Math.max(
                            interval.getStartTime(),
                            requestedStart);

            long intervalEndInclusive =
                    Math.min(
                            interval.getEndTime(),
                            requestedEndInclusive);

            if (intervalEndInclusive <
                    intervalStart) {
                continue;
            }

            /*
             * State-system interval endpoints are inclusive.
             */
            long duration =
                    inclusiveDuration(
                            intervalStart,
                            intervalEndInclusive);

            ProcessStatus processStatus =
                    ProcessStatus
                            .getStatusFromStateValue(
                                    interval.getStateValue());

            String state =
                    controlFlowStateName(
                            processStatus);

            durationByState.merge(
                    state,
                    duration,
                    Long::sum);

            /*
             * Limit only the detailed interval list.
             *
             * The loop continues through every interval so that
             * summary totals remain complete.
             */
            if (includedIntervalCount <
                    MAX_CONTROL_FLOW_INTERVALS) {

                JsonObject intervalJson =
                        new JsonObject();

                intervalJson.addProperty(
                        "state",
                        state);

                intervalJson.addProperty(
                        "trace_compass_status",
                        processStatus.name());

                intervalJson.addProperty(
                        "start_timestamp_ns",
                        intervalStart);

                intervalJson.addProperty(
                        "end_timestamp_inclusive_ns",
                        intervalEndInclusive);

                intervalJson.addProperty(
                        "start_offset_ns",
                        intervalStart - traceStart);

                intervalJson.addProperty(
                        "end_offset_ns",
                        intervalEndInclusive - traceStart);

                intervalJson.addProperty(
                        "duration_ns",
                        duration);

                intervalsJson.add(intervalJson);
                includedIntervalCount++;
            }

            totalIntervalCount++;
        }

        long totalObservedDuration = 0;

        for (Long duration : durationByState.values()) {
            totalObservedDuration =
                    safeAdd(
                            totalObservedDuration,
                            duration);
        }

        JsonArray summaryJson =
                new JsonArray();

        for (Map.Entry<String, Long> entry :
                durationByState.entrySet()) {

            JsonObject stateSummary =
                    new JsonObject();

            stateSummary.addProperty(
                    "state",
                    entry.getKey());

            stateSummary.addProperty(
                    "duration_ns",
                    entry.getValue());

            double percentage =
                    totalObservedDuration == 0
                            ? 0.0
                            : entry.getValue() * 100.0 /
                                    totalObservedDuration;

            stateSummary.addProperty(
                    "percentage",
                    percentage);

            summaryJson.add(stateSummary);
        }

        result.addProperty(
                "control_flow_data_available",
                totalIntervalCount > 0);

        if (totalIntervalCount == 0) {
            result.addProperty(
                    "message",
                    "No Control Flow state intervals were found " +
                    "for this TID in the requested range.");
        }

        result.addProperty(
                "total_observed_duration_ns",
                totalObservedDuration);

        result.addProperty(
                "total_interval_count",
                totalIntervalCount);

        result.addProperty(
                "included_interval_count",
                includedIntervalCount);

        result.addProperty(
                "intervals_truncated",
                totalIntervalCount >
                        includedIntervalCount);

        result.add(
                "state_summary",
                summaryJson);

        result.add(
                "intervals",
                intervalsJson);

        return result;
    }

    /**
     * Converts Trace Compass ProcessStatus values into clearer names
     * for the language model.
     */
    private static String controlFlowStateName(
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
    private static long inclusiveDuration(
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
     * Requests sampled thread-state analysis from the local Python/TMLL
     * service.
     *
     * @param experimentId
     *            Trace Server experiment UUID
     * @param tid
     *            thread ID requested by the user
     * @return JSON returned by the TMLL service
     * @throws Exception
     *             if the service cannot be reached or returns an error
     */
    private String callTmllThreadAnalysis(
            String experimentId,
            int tid) throws Exception {

        JsonObject body = new JsonObject();

        body.addProperty(
                "experiment_id",
                experimentId);

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

    /**
     * Requests sampled thread analysis plus RAG prompt context from the
     * local Python/TMLL service.
     *
     * @param experimentId
     *            Trace Server experiment UUID
     * @param tid
     *            thread ID requested by the user
     * @param question
     *            user's natural-language question
     * @return JSON returned by the TMLL service
     * @throws Exception
     *             if the service cannot be reached or returns an error
     */
    private String callTmllThreadRag(
            String experimentId,
            int tid,
            String question) throws Exception {

        JsonObject body = new JsonObject();

        body.addProperty(
                "experiment_id",
                experimentId);

        body.addProperty(
                "tid",
                tid);

        body.addProperty(
                "question",
                question);

        body.addProperty(
                "resolution",
                "100us");

        body.addProperty(
                "rag_limit",
                6);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        TMLL_THREAD_RAG_URL))
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
                    "TMLL RAG failed: HTTP " +
                    response.statusCode() +
                    "\n" +
                    response.body());
        }

        return response.body();
    }

    /**
     * Sends the user's question and Trace Compass context to OpenAI.
     */
    private String callOpenAI(
            String userMessage,
            String traceContext) throws Exception {

        String apiKey =
                System.getenv("OPENAI_API_KEY");

        if (apiKey == null ||
                apiKey.isBlank()) {
            throw new IllegalStateException(
                    "OPENAI_API_KEY is not configured.");
        }

        JsonObject requestJson =
                new JsonObject();

        requestJson.addProperty(
                "model",
                AnswerWriter.MODEL);

        requestJson.addProperty(
                "store",
                true);

        requestJson.addProperty(
                "instructions",
                """
                You are an assistant integrated directly into Trace Compass.

                The application automatically supplies information retrieved
                from the currently active Trace Compass trace.

                Treat the supplied Trace Compass context as authoritative
                evidence. Use it to identify the trace type and explain the
                available processes, threads, scheduling states, and Linux
                kernel analysis.

                When trace_open is true, do not ask the user to upload the
                trace or provide a screenshot.

                When kernel_analysis_available is true, explain that a Linux
                Kernel Analysis module was found.

                When requested_thread_control_flow is present, it contains
                Control Flow state information for the thread explicitly
                requested in the user's question. The requested_tid field
                identifies that thread.

                The state_summary field reports the total time and percentage
                spent in states such as running in user mode, running in a
                system call, runnable but waiting for CPU, blocked,
                interrupted, or unknown.

                The intervals field contains individual state intervals. Use
                start_offset_ns and end_offset_ns when describing locations
                relative to the beginning of the trace.

                If intervals_truncated is true, only the first intervals are
                included, but state_summary was calculated using all returned
                intervals.

                Treat requested_thread_control_flow.state_summary as
                authoritative calculated evidence. Do not recalculate
                durations or percentages from the intervals list.

                When tmll_thread_analysis is present, it contains sampled
                analysis returned by the local Python/TMLL service. When
                tmll_rag_context is present, it contains retrieved documents
                and a RAG prompt prepared by that service.

                The Java requested_thread_control_flow calculation is the
                authoritative source for exact scheduling-state durations.
                The TMLL result is sampled supporting evidence and may differ
                slightly from the Java result.

                The Java percentages use the full observed trace range,
                including NOT_ALIVE. The TMLL percentages use only known
                active time. Do not compare those percentages without
                explaining their different denominators.
	
	            When tmll_thread_analysis.syscall_latency_correlation
	            is present and available is true, use it as syscall-latency
	            evidence. If a syscall overlaps a BLOCKED interval, report the
	            system call, overlap coverage, and what type of wait it indicates.
	             
				A same-thread syscall with 100 percent coverage of a BLOCKED
	            interval is strong evidence that the thread blocked while executing
				that syscall. This identifies the type of wait, but does not by
				itself identify the remote endpoint, resource, process, or thread
				responsible for waking it.

                Do not invent events, thread states, causes, durations, or
                dependencies that are absent from the supplied context.

                A BLOCKED interval alone does not identify its cause. However, when
                syscall_latency_correlation is available, use the overlapping
                syscall to identify the type of wait. Do not claim the responsible
                endpoint, service, process, or thread unless wake-up or socket
                correlation is supplied.

                Critical Flow dependencies and nearby raw events are not yet
                supplied. Clearly explain this limitation when the user asks
                why a thread was blocked or which thread delayed it.
                """);

        String completeInput =
                buildOpenAIInput(
                        userMessage,
                        traceContext);

        requestJson.addProperty(
                "input",
                completeInput);

        if (previousResponseId != null) {
            requestJson.addProperty(
                    "previous_response_id",
                    previousResponseId);
        }

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        "https://api.openai.com/v1/responses"))
                        .header(
                                "Authorization",
                                "Bearer " + apiKey)
                        .header(
                                "Content-Type",
                                "application/json")
                        .POST(
                                HttpRequest.BodyPublishers
                                        .ofString(
                                                requestJson.toString()))
                        .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 ||
                response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "OpenAI API returned HTTP " +
                    response.statusCode() +
                    ":\n" +
                    response.body());
        }

        JsonObject responseJson =
                JsonParser
                        .parseString(
                                response.body())
                        .getAsJsonObject();

        if (responseJson.has("id")) {
            previousResponseId =
                    responseJson
                            .get("id")
                            .getAsString();
        }

        return extractAnswer(
                responseJson);
    }

    /**
     * Builds the OpenAI input. If the Python/TMLL service returned a RAG
     * prompt, prefer it as the primary task prompt and include the full Trace
     * Compass context as supporting evidence.
     */
    private static String buildOpenAIInput(
            String userMessage,
            String traceContext) {

        String ragPrompt =
                extractRagPrompt(traceContext);

        if (ragPrompt != null &&
                !ragPrompt.isBlank()) {
            return """
                    The local TMLL RAG service prepared the grounded prompt
                    below from Trace Compass/TMLL evidence and retrieved
                    documentation. Answer the user by following that prompt.

                    TMLL RAG PROMPT:
                    %s

                    FULL TRACE COMPASS CONTEXT JSON:
                    %s
                    """.formatted(
                            ragPrompt,
                            traceContext);
        }

        return """
                The following JSON was retrieved automatically from
                the currently active Trace Compass trace.

                TRACE COMPASS CONTEXT:
                %s

                USER QUESTION:
                %s
                """.formatted(
                        traceContext,
                        userMessage);
    }

    /**
     * Extracts tmll_rag_context.prompt from the combined context JSON.
     */
    private static String extractRagPrompt(
            String traceContext) {

        try {
            JsonObject context =
                    JsonParser
                            .parseString(
                                    traceContext)
                            .getAsJsonObject();

            if (!context.has("tmll_rag_context") ||
                    !context
                            .get("tmll_rag_context")
                            .isJsonObject()) {
                return null;
            }

            JsonObject rag =
                    context
                            .getAsJsonObject(
                                    "tmll_rag_context");

            if (!rag.has("prompt") ||
                    rag.get("prompt").isJsonNull()) {
                return null;
            }

            return rag
                    .get("prompt")
                    .getAsString();
        } catch (RuntimeException exception) {
            return null;
        }
    }

    /**
     * Extracts text output from an OpenAI Responses API response.
     */
    private static String extractAnswer(
            JsonObject responseJson) {

        StringBuilder answer =
                new StringBuilder();

        if (!responseJson.has("output") ||
                !responseJson
                        .get("output")
                        .isJsonArray()) {
            return "The API returned no output.";
        }

        JsonArray output =
                responseJson
                        .getAsJsonArray("output");

        for (JsonElement outputElement : output) {
            if (!outputElement.isJsonObject()) {
                continue;
            }

            JsonObject outputItem =
                    outputElement
                            .getAsJsonObject();

            if (!outputItem.has("content") ||
                    !outputItem
                            .get("content")
                            .isJsonArray()) {
                continue;
            }

            JsonArray content =
                    outputItem
                            .getAsJsonArray("content");

            for (JsonElement contentElement :
                    content) {

                if (!contentElement.isJsonObject()) {
                    continue;
                }

                JsonObject contentItem =
                        contentElement
                                .getAsJsonObject();

                if (!contentItem.has("type")) {
                    continue;
                }

                String type =
                        contentItem
                                .get("type")
                                .getAsString();

                if ("output_text".equals(type) &&
                        contentItem.has("text")) {

                    answer.append(
                            contentItem
                                    .get("text")
                                    .getAsString());
                }
            }
        }

        if (answer.length() == 0) {
            return "The API returned no text response.";
        }

        return answer.toString();
    }

    @Override
    public void setFocus() {
        if (messageBox != null &&
                !messageBox.isDisposed()) {
            messageBox.setFocus();
        }
    }
}
