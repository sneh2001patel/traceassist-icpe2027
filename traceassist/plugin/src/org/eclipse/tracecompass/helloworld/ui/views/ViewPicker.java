package org.eclipse.tracecompass.helloworld.ui.views;

import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.arr;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.dbl;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.num;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.obj;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.str;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelAnalysisModule;
import org.eclipse.tracecompass.analysis.os.linux.core.kernel.KernelThreadInformationProvider;
import org.eclipse.tracecompass.tmf.core.event.ITmfEventType;
import org.eclipse.tracecompass.tmf.core.timestamp.TmfTimestamp;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTraceWithPreDefinedEvents;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Picks the views that show an answer's evidence (the {@code view_picker} AI
 * skill), from one card per view in {@code skills/views/<key>/VIEW.md}.
 * <p>
 * The split: the skill picks the views (1 to 3), the evidence moment they
 * show, each view's focus (a thread, a CPU, threads to plot, series to tick)
 * and what to look at; code builds the moments and focus options from the
 * findings, checks every choice against them, and computes the zoom and the
 * selection exactly, from the moment and the first view's zoom rule. The
 * result is the same view plan {@code showViewPlan} applies; when the skill
 * fails or its answer is unusable, the rule-based plan stands.
 */
final class ViewPicker {

    static final String SKILL = "view_picker";

    /** The views TraceAssist can open and drive, by card key. */
    static final Map<String, String> VIEWS = new LinkedHashMap<>();
    static {
        VIEWS.put("control_flow", AnswerPipeline.VIEW_CONTROL_FLOW);
        VIEWS.put("resources", AnswerPipeline.VIEW_RESOURCES);
        VIEWS.put("cpu_usage", AnswerPipeline.VIEW_CPU_USAGE);
        VIEWS.put("critical_path", AnswerPipeline.VIEW_CRITICAL_PATH);
        VIEWS.put("statistics", AnswerPipeline.VIEW_STATISTICS);
        VIEWS.put("histogram", AnswerPipeline.VIEW_HISTOGRAM);
        VIEWS.put("event_density", AnswerPipeline.VIEW_EVENT_DENSITY);
        VIEWS.put("syscall_latency_scatter", AnswerPipeline.VIEW_SYSCALL_LATENCY_SCATTER);
        VIEWS.put("syscall_latency_table", AnswerPipeline.VIEW_SYSCALL_LATENCY_TABLE);
        VIEWS.put("sched_latency_scatter", AnswerPipeline.VIEW_SCHED_LATENCY_SCATTER);
        VIEWS.put("sched_latency_table", AnswerPipeline.VIEW_SCHED_LATENCY_TABLE);
        VIEWS.put("disk_io", AnswerPipeline.VIEW_DISK_IO);
        VIEWS.put("kernel_memory", AnswerPipeline.VIEW_KERNEL_MEMORY);
    }

    /** Keys in a finding's data that name a thread involved in the evidence, and what that makes it. */
    private static final Map<String, String> THREAD_KEYS = Map.of(
            "holder_tid", "held the CPU it waited for",
            "woken_by_tid", "woke it",
            "likely_cause_tid", "most likely cause of its wait",
            "main_tid", "the process's main thread",
            "bottleneck_tid", "the process's bottleneck",
            "root_tid", "the root of the wait chain",
            "waiter_tid", "the waiting thread");
    private static final int MAX_THREADS = 12;
    private static final int MAX_FINDINGS = 25;

    private ViewPicker() {
    }

    /** One view's card: the front matter code uses, and the text the skill reads. */
    record Card(String key, String viewId, String name, String focus, double zoomPad, double zoomMinSpanMs,
            List<String> needsEvents, @Nullable String tspOutput, String text) {
    }

    /** One stretch of time the evidence is about. */
    private record Moment(String id, String label, String finding, long start, long end) {
    }

    /** The cards, re-read on every call like the skills, so an edited card applies to the next question. */
    static List<Card> cards() throws IOException {
        List<Card> cards = new ArrayList<>();
        for (Map.Entry<String, String> view : VIEWS.entrySet()) {
            String text = AiSkill.read("skills/views/" + view.getKey() + "/VIEW.md");
            Map<String, String> front = AiSkill.frontMatter(text);
            if (!view.getValue().equals(front.get("view_id"))) {
                throw new IOException("View card " + view.getKey() + " names view " + front.get("view_id")
                        + ", expected " + view.getValue());
            }
            int body = text.indexOf("\n---", 3);
            String needs = front.getOrDefault("needs_events", "").trim();
            cards.add(new Card(view.getKey(), view.getValue(), front.getOrDefault("name", view.getKey()),
                    front.getOrDefault("focus", "none"), Double.parseDouble(front.getOrDefault("zoom_pad", "0.1")),
                    Double.parseDouble(front.getOrDefault("zoom_min_span_ms", "0")),
                    needs.isEmpty() ? List.of() : List.of(needs.split("\\s*,\\s*")),
                    tspOutput(front.get("tsp_output")),
                    body < 0 ? text : text.substring(body + 4).trim()));
        }
        return cards;
    }

    /** A card's {@code tsp_output}: null when absent or {@code none} (no Trace Server output). */
    private static @Nullable String tspOutput(@Nullable String value) {
        return value == null || value.isBlank() || "none".equalsIgnoreCase(value.trim()) ? null : value.trim();
    }

    /**
     * Adds each view's card key and Trace Server output ({@code tsp_output}, from its card) to a
     * view plan, so a client of the Trace Server (the VS Code trace viewer) can open the same
     * views; a view the server has no output for gets {@code tsp_output: null}. Works on both
     * the view picker's and the rule-based plans. Never fails the answer.
     */
    static void addServerOutputs(@Nullable JsonObject viewPlan) {
        if (viewPlan == null || !viewPlan.has("views")) {
            return;
        }
        Map<String, Card> byViewId = new HashMap<>();
        try {
            for (Card card : cards()) {
                byViewId.put(card.viewId(), card);
            }
        } catch (IOException exception) {
            System.err.println("View cards unreadable, no Trace Server outputs in the view plan: " + exception);
            return;
        }
        for (JsonElement element : viewPlan.getAsJsonArray("views")) {
            JsonObject view = element.getAsJsonObject();
            Card card = byViewId.get(str(view, "id"));
            if (card == null) {
                continue;
            }
            if (!view.has("key")) {
                view.addProperty("key", card.key());
            }
            view.addProperty("tsp_output", card.tspOutput());
        }
    }

    /**
     * The view plan the skill picks, in {@code showViewPlan}'s format, with
     * {@code source: view_picker}, each view's {@code look_at}, and the
     * rule-based plan's views for comparison. Throws when the skill fails or
     * picks nothing usable; the caller keeps the rule-based plan.
     */
    static JsonObject plan(String question, JsonObject plan, JsonArray findings, ITmfTrace trace, JsonObject rules)
            throws Exception {
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        // A view that needs events the trace does not have (block I/O, kernel memory) would be empty: not offered.
        List<Card> cards = new ArrayList<>();
        JsonArray notOffered = new JsonArray();
        Set<String> events = eventNames(trace);
        for (Card card : cards()) {
            boolean has = card.needsEvents().isEmpty() || events == null
                    || events.stream().anyMatch(name -> card.needsEvents().stream().anyMatch(name::startsWith));
            if (has) {
                cards.add(card);
            } else {
                notOffered.add(card.key() + " (no " + String.join("/", card.needsEvents()) + "* events in the trace)");
            }
        }
        Map<String, Card> byKey = new LinkedHashMap<>();
        cards.forEach(card -> byKey.put(card.key(), card));

        Map<String, Moment> moments = moments(findings, traceStart, traceEnd);
        Integer target = plan.has("tid") && !plan.get("tid").isJsonNull() ? plan.get("tid").getAsInt() : null;
        Map<Integer, String> threads = threads(findings, plan, trace);
        Set<Integer> cpus = cpus(findings);
        Set<String> syscallSeries = syscallSeries(findings);
        Set<String> threadSeries = new LinkedHashSet<>();
        threads.forEach((tid, why) -> {
            String name = threadName(trace, tid);
            if (name != null) {
                threadSeries.add(name);
            }
        });

        JsonObject input = new JsonObject();
        // The cards first: the instructions and cards are then the same prefix on every call, which the API caches.
        JsonArray cardList = new JsonArray();
        for (Card card : cards) {
            JsonObject row = new JsonObject();
            row.addProperty("key", card.key());
            row.addProperty("focus", card.focus());
            row.addProperty("card", card.text());
            cardList.add(row);
        }
        input.add("views", cardList);
        input.addProperty("question", question);
        JsonObject about = new JsonObject();
        for (String key : new String[] {"scope", "intent", "tid", "pid"}) {
            if (plan.has(key)) {
                about.add(key, plan.get(key));
            }
        }
        Integer named = target != null ? target : plan.has("pid") ? (Integer) plan.get("pid").getAsInt() : null;
        if (named != null && threadName(trace, named) != null) {
            about.addProperty("name", threadName(trace, named));
        }
        input.add("plan", about);
        JsonArray claims = new JsonArray();
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            if (claims.size() < MAX_FINDINGS && str(finding, "claim") != null) {
                String claim = str(finding, "claim");
                claims.add(str(finding, "id") + " (" + str(finding, "about") + "): "
                        + (claim.length() > 400 ? claim.substring(0, 400) + " [...]" : claim));
            }
        }
        input.add("findings", claims);
        JsonArray momentList = new JsonArray();
        for (Moment moment : moments.values()) {
            JsonObject row = new JsonObject();
            row.addProperty("id", moment.id());
            row.addProperty("label", moment.label());
            row.addProperty("finding", moment.finding());
            row.addProperty("start_offset_ms", round3((moment.start() - traceStart) / 1_000_000.0));
            row.addProperty("end_offset_ms", round3((moment.end() - traceStart) / 1_000_000.0));
            row.addProperty("length_ms", round3((moment.end() - moment.start()) / 1_000_000.0));
            momentList.add(row);
        }
        input.add("moments", momentList);
        JsonObject options = new JsonObject();
        JsonArray threadList = new JsonArray();
        threads.forEach((tid, why) -> {
            JsonObject row = new JsonObject();
            row.addProperty("tid", tid);
            row.addProperty("name", threadName(trace, tid));
            row.addProperty("involved_as", why);
            threadList.add(row);
        });
        options.add("threads", threadList);
        options.add("cpus", toArray(cpus));
        options.add("syscall_series", toArray(syscallSeries));
        options.add("thread_series", toArray(threadSeries));
        input.add("focus_options", options);

        JsonObject answer = AiSkill.load(SKILL).run(input);

        // Check every choice against what was offered.
        Moment moment = moments.get(str(answer, "moment"));
        JsonArray rejected = new JsonArray();
        if (moment == null) {
            rejected.add("moment " + str(answer, "moment") + " (not offered): whole_trace used");
            moment = moments.get("whole_trace");
        }
        List<Card> picked = new ArrayList<>();
        Map<String, JsonObject> choices = new LinkedHashMap<>();
        for (JsonElement element : arr(answer, "views")) {
            JsonObject choice = element.getAsJsonObject();
            Card card = byKey.get(str(choice, "view"));
            if (card == null || choices.containsKey(card.key()) || picked.size() == 3) {
                rejected.add("view " + str(choice, "view"));
                continue;
            }
            picked.add(card);
            choices.put(card.key(), choice);
        }
        if (picked.isEmpty()) {
            throw new IllegalStateException("the view picker chose no usable view: " + str(answer, "reasoning"));
        }

        Integer follow = null;
        Integer select = null;
        Integer cpu = null;
        List<Integer> plot = new ArrayList<>();
        List<String> series = new ArrayList<>();
        JsonArray viewList = new JsonArray();
        List<String> names = new ArrayList<>();
        List<String> lookAt = new ArrayList<>();
        for (Card card : picked) {
            JsonObject choice = choices.get(card.key());
            Integer tid = choice.has("tid") && !choice.get("tid").isJsonNull() ? choice.get("tid").getAsInt() : null;
            switch (card.focus()) {
            case "thread":
                if (tid == null || !threads.containsKey(tid)) {
                    if (tid != null) {
                        rejected.add(card.key() + " tid " + tid + " (not offered)");
                    }
                    tid = target; // the thread the answer is about
                }
                if ("critical_path".equals(card.key())) {
                    follow = tid;
                } else {
                    select = tid;
                }
                break;
            case "cpu":
                Integer chosenCpu = choice.has("cpu") && !choice.get("cpu").isJsonNull() ? choice.get("cpu").getAsInt() : null;
                if (chosenCpu != null && cpus.contains(chosenCpu)) {
                    cpu = chosenCpu;
                } else if (chosenCpu != null) {
                    rejected.add(card.key() + " cpu " + chosenCpu + " (not offered)");
                }
                break;
            case "plot_threads":
                for (JsonElement plotted : arr(choice, "tids")) {
                    int plotTid = plotted.getAsInt();
                    if (threads.containsKey(plotTid) && !plot.contains(plotTid)) {
                        plot.add(plotTid);
                    } else if (!threads.containsKey(plotTid)) {
                        rejected.add(card.key() + " tid " + plotTid + " (not offered)");
                    }
                }
                if (plot.isEmpty() && target != null) {
                    plot.add(target);
                }
                break;
            case "series":
                Set<String> allowed = "sched_latency_scatter".equals(card.key()) ? threadSeries : syscallSeries;
                for (JsonElement name : arr(choice, "series")) {
                    String value = name.getAsString();
                    if (allowed.contains(value) && !series.contains(value)) {
                        series.add(value);
                    } else if (!allowed.contains(value)) {
                        rejected.add(card.key() + " series " + value + " (not offered)");
                    }
                }
                break;
            default:
                break;
            }
            JsonObject view = new JsonObject();
            view.addProperty("id", card.viewId());
            view.addProperty("name", AnswerPipeline.displayNameForViewId(card.viewId()));
            view.addProperty("key", card.key());
            view.addProperty("look_at", str(choice, "look_at"));
            viewList.add(view);
            names.add(AnswerPipeline.displayNameForViewId(card.viewId()));
            lookAt.add("- **" + AnswerPipeline.displayNameForViewId(card.viewId()) + ":** " + str(choice, "look_at"));
        }
        // Resources highlights the followed thread: follow the thread the answer is about.
        if (follow == null && choices.containsKey("resources") && target != null) {
            follow = target;
        }
        // A scatter with no valid series would plot nothing: fall back to the rule-based series.
        if (series.isEmpty() && (choices.containsKey("syscall_latency_scatter") || choices.containsKey("sched_latency_scatter"))
                && rules != null) {
            arr(rules, "plot_series").forEach(name -> series.add(name.getAsString()));
        }

        // Zoom: the moment, padded by the first view's rule (all views share one range).
        Card first = picked.get(0);
        long start = moment.start();
        long end = moment.end();
        long length = Math.max(1, end - start);
        long pad = Math.round(length * first.zoomPad());
        long minSpan = Math.round(first.zoomMinSpanMs() * 1_000_000);
        if (length + 2 * pad < minSpan) {
            pad = (minSpan - length) / 2;
        }
        long zoomStart = Math.max(traceStart, start - pad);
        long zoomEnd = Math.min(traceEnd, end + pad);

        JsonObject viewPlan = new JsonObject();
        viewPlan.addProperty("source", "view_picker");
        viewPlan.add("views", viewList);
        JsonObject selection = new JsonObject();
        selection.addProperty("start_ns", start);
        selection.addProperty("end_ns", end);
        selection.addProperty("start_offset_ms", (start - traceStart) / 1_000_000.0);
        selection.addProperty("end_offset_ms", (end - traceStart) / 1_000_000.0);
        viewPlan.add("selection", selection);
        JsonObject zoom = new JsonObject();
        zoom.addProperty("start_ns", zoomStart);
        zoom.addProperty("end_ns", zoomEnd);
        zoom.addProperty("rule", String.format(Locale.ROOT, "%s: pad %.2f x the moment each side, at least %s ms",
                first.name(), first.zoomPad(), trim(first.zoomMinSpanMs())));
        viewPlan.add("zoom", zoom);
        viewPlan.addProperty("moment", moment.id());
        if (follow != null) {
            viewPlan.addProperty("follow_tid", follow);
        }
        if (select != null) {
            viewPlan.addProperty("select_tid", select);
        }
        if (cpu != null) {
            viewPlan.addProperty("cpu", cpu);
        }
        viewPlan.add("plot_tids", toArray(plot));
        viewPlan.add("plot_series", toArray(series));
        viewPlan.addProperty("reason", moment.label());
        viewPlan.add("picker_reasoning", answer.get("reasoning"));
        if (rejected.size() > 0) {
            viewPlan.add("rejected", rejected);
        }
        if (notOffered.size() > 0) {
            viewPlan.add("views_not_offered", notOffered);
        }
        if (rules != null) {
            JsonObject compare = new JsonObject();
            JsonArray ruleViews = new JsonArray();
            arr(rules, "views").forEach(view -> ruleViews.add(str(view.getAsJsonObject(), "name")));
            compare.add("views", ruleViews);
            compare.add("reason", rules.get("reason"));
            viewPlan.add("rule_based", compare);
        }

        List<String> focus = new ArrayList<>();
        if (follow != null) {
            focus.add("following TID " + follow);
        }
        if (select != null && !select.equals(follow)) {
            focus.add("TID " + select + " selected");
        }
        if (!plot.isEmpty()) {
            focus.add("TID " + plot.get(0) + (plot.size() > 1 ? " and others" : "") + " plotted");
        }
        if (!series.isEmpty()) {
            focus.add(String.join(", ", series) + " plotted");
        }
        if (cpu != null) {
            focus.add("CPU " + cpu);
        }
        String clock = TmfTimestamp.fromNanos(start).toString() + " – " + TmfTimestamp.fromNanos(end).toString();
        viewPlan.addProperty("clock_range", clock);
        viewPlan.addProperty("summary", String.format(Locale.ROOT, "%s, %,.3f–%,.3f ms into the trace (%s on the views' time axis)%s: %s.",
                String.join(" + ", names), (start - traceStart) / 1_000_000.0, (end - traceStart) / 1_000_000.0, clock,
                focus.isEmpty() ? "" : " (" + String.join(", ", focus) + ")", moment.label())
                + "\n" + String.join("\n", lookAt));
        return viewPlan;
    }

    // ------------------------------------------------------------------ what code offers the skill

    /** The stretches of time the findings are about; the first is the whole trace. */
    private static Map<String, Moment> moments(JsonArray findings, long traceStart, long traceEnd) {
        Map<String, Moment> moments = new LinkedHashMap<>();
        moments.put("whole_trace", new Moment("whole_trace", "the whole trace", null, traceStart, traceEnd));
        for (JsonElement element : findings) {
            JsonObject finding = element.getAsJsonObject();
            String id = str(finding, "id");
            JsonObject window = obj(finding, "window");
            JsonObject data = obj(obj(finding, "evidence"), "data");
            if (id == null) {
                continue;
            }
            if (window != null && "user".equals(str(window, "source")) && !moments.containsKey("user_window")) {
                String asked = str(window, "interpreted_as");
                moments.put("user_window", new Moment("user_window", "the time range the question names"
                        + (asked != null ? " (" + asked + ")" : ""), id, num(window, "start_ns", traceStart),
                        num(window, "end_ns", traceEnd)));
            }
            if (data == null) {
                continue;
            }
            switch (id) {
            case "window.late_cycle":
                if (window != null && !moments.containsKey("late_cycle")) {
                    moments.put("late_cycle", new Moment("late_cycle", "the late cycle: " + str(finding, "claim"), id,
                            num(window, "start_ns", traceStart), num(window, "end_ns", traceEnd)));
                }
                break;
            case "blocked.wake_chain":
                if (data.has("interval_start_ns")) {
                    moments.put("critical_path_wait", new Moment("critical_path_wait",
                            "the wait whose critical path was computed (" + str(data, "which_wait") + ")", id,
                            num(data, "interval_start_ns", traceStart), num(data, "interval_end_ns", traceEnd)));
                }
                break;
            case "process.example_chain":
                if (data.has("interval_start_offset_ms")) {
                    long start = traceStart + Math.round(dbl(data, "interval_start_offset_ms", 0) * 1_000_000);
                    moments.put("example_wait", new Moment("example_wait", "a " + str(data, "example_kind")
                            + " wait of the main thread on its bottleneck, with its critical path", id, start,
                            start + Math.round(dbl(data, "interval_ms", 0) * 1_000_000)));
                }
                break;
            case "scheduling.latency":
                if (data.has("worst_start_ns")) {
                    moments.put("worst_wakeup_delay", new Moment("worst_wakeup_delay", String.format(Locale.ROOT,
                            "the thread's worst wake-up scheduling delay (%.3f ms)", dbl(data, "worst_ms", 0)), id,
                            num(data, "worst_start_ns", traceStart), num(data, "worst_end_ns", traceEnd)));
                }
                break;
            case "syscalls.longest":
                JsonArray longest = arr(data, "longest");
                if (longest.size() > 0 && !moments.containsKey("longest_syscall")) {
                    // The longest call that returned: exit and exit_group last until the thread ends.
                    JsonObject call = data.has("longest_completed") ? obj(data, "longest_completed")
                            : longest.get(0).getAsJsonObject();
                    moments.put("longest_syscall", new Moment("longest_syscall", String.format(Locale.ROOT,
                            "the thread's longest system call (%s, %.3f ms)", str(call, "system_call"),
                            dbl(call, "duration_ms", 0)), id, num(call, "start_ns", traceStart),
                            num(call, "end_ns", traceEnd)));
                }
                break;
            case "running.cpu_peak":
                if (data.has("peak_start_ns")) {
                    moments.put("cpu_peak", new Moment("cpu_peak", "the thread's busiest CPU window", id,
                            num(data, "peak_start_ns", traceStart), num(data, "peak_end_ns", traceEnd)));
                }
                break;
            case "trace.event_peak":
                boolean afterStart = data.has("after_start_peak_start_ns");
                if (data.has("peak_start_ns")) {
                    moments.put("event_peak", new Moment("event_peak", afterStart
                            ? "the trace's busiest stretch by event rate after start-up (the start itself is the state dump)"
                            : "the trace's busiest stretch by event rate", id,
                            num(data, afterStart ? "after_start_peak_start_ns" : "peak_start_ns", traceStart),
                            num(data, afterStart ? "after_start_peak_end_ns" : "peak_end_ns", traceEnd)));
                }
                break;
            default:
                break;
            }
        }
        return moments;
    }

    /** The thread the answer is about and every thread the findings name, with why it is involved. */
    private static Map<Integer, String> threads(JsonArray findings, JsonObject plan, ITmfTrace trace) {
        Map<Integer, String> threads = new LinkedHashMap<>();
        if (plan.has("tid") && !plan.get("tid").isJsonNull()) {
            threads.put(plan.get("tid").getAsInt(), "the thread the question is about");
        }
        if (plan.has("pid") && !plan.get("pid").isJsonNull()) {
            threads.put(plan.get("pid").getAsInt(), "the main thread of the process the question is about");
        }
        for (JsonElement element : findings) {
            collectThreads(obj(obj(element.getAsJsonObject(), "evidence"), "data"), threads);
        }
        return threads;
    }

    private static void collectThreads(JsonElement element, Map<Integer, String> into) {
        if (element == null || element.isJsonNull() || into.size() >= MAX_THREADS) {
            return;
        }
        if (element.isJsonArray()) {
            element.getAsJsonArray().forEach(child -> collectThreads(child, into));
        } else if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                JsonElement value = entry.getValue();
                String why = THREAD_KEYS.get(entry.getKey());
                if ("tid".equals(entry.getKey())) {
                    why = "named in the evidence";
                }
                if (why != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                    int tid = value.getAsInt();
                    if (tid > 0 && into.size() < MAX_THREADS) {
                        into.putIfAbsent(tid, why);
                    }
                } else {
                    collectThreads(value, into);
                }
            }
        }
    }

    /** CPUs the findings name ("cpus": [3] or [{"cpu": 3, ...}], "cpu": 3, "first_cpu", "last_cpu"). */
    private static Set<Integer> cpus(JsonArray findings) {
        Set<Integer> cpus = new LinkedHashSet<>();
        for (JsonElement element : findings) {
            collectCpus(obj(obj(element.getAsJsonObject(), "evidence"), "data"), cpus, false);
        }
        return cpus;
    }

    private static void collectCpus(JsonElement element, Set<Integer> into, boolean inCpuList) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonPrimitive()) {
            if (inCpuList && element.getAsJsonPrimitive().isNumber()) {
                into.add(element.getAsInt());
            }
        } else if (element.isJsonArray()) {
            element.getAsJsonArray().forEach(child -> collectCpus(child, into, inCpuList));
        } else {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                String key = entry.getKey();
                boolean cpuKey = "cpus".equals(key) || "cpu".equals(key) || "first_cpu".equals(key) || "last_cpu".equals(key);
                collectCpus(entry.getValue(), into, cpuKey);
            }
        }
    }

    /** System-call names in the findings: the longest calls, the calls it blocked in, the most frequent. */
    private static Set<String> syscallSeries(JsonArray findings) {
        Set<String> names = new LinkedHashSet<>();
        for (JsonElement element : findings) {
            collectSyscalls(obj(obj(element.getAsJsonObject(), "evidence"), "data"), names);
        }
        return names;
    }

    private static void collectSyscalls(JsonElement element, Set<String> into) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonArray()) {
            element.getAsJsonArray().forEach(child -> collectSyscalls(child, into));
        } else if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                JsonElement value = entry.getValue();
                if (("system_call".equals(entry.getKey()) || "longest_syscall".equals(entry.getKey()))
                        && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    into.add(value.getAsString());
                } else {
                    collectSyscalls(value, into);
                }
            }
        }
    }

    /** The event types the trace declares (an LTTng trace: the events that were enabled), or null if unknown. */
    private static Set<String> eventNames(ITmfTrace trace) {
        if (!(trace instanceof ITmfTraceWithPreDefinedEvents)) {
            return null;
        }
        Set<String> names = new LinkedHashSet<>();
        for (ITmfEventType type : ((ITmfTraceWithPreDefinedEvents) trace).getContainedEventTypes()) {
            names.add(type.getName());
        }
        return names.isEmpty() ? null : names;
    }

    private static String threadName(ITmfTrace trace, int tid) {
        KernelAnalysisModule kernel = TmfTraceUtils.getAnalysisModuleOfClass(trace, KernelAnalysisModule.class,
                KernelAnalysisModule.ID);
        return kernel == null ? null : KernelThreadInformationProvider.getExecutableName(kernel, tid);
    }

    private static JsonArray toArray(Iterable<?> values) {
        JsonArray array = new JsonArray();
        for (Object value : values) {
            if (value instanceof Number) {
                array.add((Number) value);
            } else {
                array.add(String.valueOf(value));
            }
        }
        return array;
    }

    private static double round3(double value) {
        return Math.round(value * 1000) / 1000.0;
    }

    private static String trim(double value) {
        return value == Math.rint(value) ? String.valueOf((long) value) : String.valueOf(value);
    }
}
