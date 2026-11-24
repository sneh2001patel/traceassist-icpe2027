package org.eclipse.tracecompass.helloworld.ui.views;

import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.arr;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.bool;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.dbl;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.num;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.obj;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.str;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.ExplainWindow;
import org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.ProcessAnalysis;
import org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.QueryPlan;
import org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The adaptive search over the thread finder's suspects
 * (thread_finder_design.md, step 3). When the finder cannot name the target,
 * code runs the symptom's analyses on every suspect, level by level, within
 * an estimated-cost budget, and picks the suspect the evidence points to.
 * <p>
 * Implemented symptoms: {@code one_off_delay}, {@code bottleneck}, and the
 * four state-based ones: {@code busiest_cpu}, {@code long_blocked_waits},
 * {@code slow_scheduling}, {@code slow_syscalls_io}. After
 * a level, the match judge (an AI skill, step 4) rates each suspect match,
 * weak or no; a match or weak match moves up a level, and if nobody is
 * either, everyone does. Code then scores the suspects, turns the scores
 * into percentages and a confidence label, and writes the answer's "Why
 * this thread" section ({@link #whySection}).
 */
final class ThreadSearch {

    /** The search may spend at most this share of the trace's event count (estimated cost). */
    static final double CAP_SHARE = 0.75;
    /** Cost weight of a query on data that is already built (state system, execution graph). */
    static final double WEIGHT_STATE = 0.05;
    /** Cost weight of an event scan or graph analysis over a window. */
    static final double WEIGHT_SCAN = 1.0;
    /** The search stops when it has run this long, whatever the estimate says. */
    static final long MAX_WALL_NS = Duration.ofMinutes(30).toNanos();

    /** Evidence confirmed at a deeper level counts for more (index: level reached). */
    private static final double[] DEPTH = {0, 0.25, 0.5, 1.0};
    /** Keys in a finding's data that name another thread involved in the window. */
    private static final Set<String> LINK_KEYS = Set.of("tid", "holder_tid", "woken_by_tid", "likely_cause_tid");

    /** The late-cycle finder (TMLL) for one thread; supplied by the view, which owns the service client. */
    interface LateCycleFinder {
        JsonObject find(int tid) throws Exception;
    }

    private ThreadSearch() {
    }

    /** The finder could not name the target, and the symptom has a search. */
    static boolean applies(ThreadFinder.Decision decision) {
        if (decision == null || decision.wholeTrace() || bool(decision.json(), "target_clear")) {
            return false;
        }
        JsonArray suspects = arr(decision.json(), "suspects");
        if ("one_off_delay".equals(decision.symptom()) || PROFILES.containsKey(decision.symptom())) {
            int threads = 0;
            for (JsonElement element : suspects) {
                threads += isSet(element.getAsJsonObject(), "tid") ? 1 : 0;
            }
            return threads >= 2;
        }
        if ("bottleneck".equals(decision.symptom())) {
            // A thread suspect: the process's wait chain may point to it or to another thread.
            return "thread".equals(str(decision.json(), "scope")) ? suspects.size() >= 1 : suspects.size() >= 2;
        }
        return false;
    }

    /** Searches the decision's suspects and returns the decision with the search's pick as its target. */
    static ThreadFinder.Decision run(ThreadFinder.Decision decision, String question, ITmfTrace trace,
            LateCycleFinder lateCycles) {
        JsonObject inventory = TraceInventory.of(trace);
        Map<Integer, JsonObject> threadRows = new HashMap<>();
        Map<Integer, String> processNames = new HashMap<>();
        for (JsonElement element : arr(inventory, "threads")) {
            JsonObject row = element.getAsJsonObject();
            threadRows.put(row.get("tid").getAsInt(), row);
        }
        for (JsonElement element : arr(inventory, "processes")) {
            JsonObject row = element.getAsJsonObject();
            processNames.put(row.get("pid").getAsInt(), str(row, "name"));
        }
        boolean processScope = "process".equals(str(decision.json(), "scope"));
        String symptom = decision.symptom();

        List<Suspect> suspects = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (JsonElement element : arr(decision.json(), "suspects")) {
            JsonObject entry = element.getAsJsonObject();
            Integer tid = isSet(entry, "tid") ? entry.get("tid").getAsInt() : null;
            Integer pid = isSet(entry, "pid") ? entry.get("pid").getAsInt() : null;
            if (tid != null && pid == null && threadRows.containsKey(tid)) {
                pid = threadRows.get(tid).get("pid").getAsInt();
            }
            if ("bottleneck".equals(symptom) && processScope) {
                tid = null; // a process suspect
            }
            if (("one_off_delay".equals(symptom) || PROFILES.containsKey(symptom)) && tid == null) {
                continue;
            }
            if (tid == null && pid == null || !seen.add(tid != null ? "t" + tid : "p" + pid)) {
                continue;
            }
            String name = tid != null ? (threadRows.containsKey(tid) ? str(threadRows.get(tid), "name") : null)
                    : processNames.get(pid);
            suspects.add(new Suspect(tid, pid, name, str(entry, "reason"), suspects.size()));
        }

        Budget budget = new Budget(trace);
        JsonObject numbers = obj(decision.json(), "question_numbers");
        Judge judge = new Judge(question, numbers, symptom, budget);
        if ("one_off_delay".equals(symptom)) {
            searchOneOffDelay(question, trace, suspects, numbers, budget, lateCycles, threadRows, judge);
        } else if (PROFILES.containsKey(symptom)) {
            searchProfile(question, trace, symptom, suspects, numbers, budget, threadRows, judge);
        } else {
            searchBottleneck(trace, processScope, suspects, budget, threadRows, judge);
        }

        /*
         * Scores (code, thread_finder_design.md [5]): signal strength x
         * closeness to the question's numbers x depth of confirmation x the
         * judge's verdict (match 1, weak 0.5, no 0); 0 for a suspect that is
         * part of another's delay. With no score left, the closest weak
         * match on the evidence alone is the pick, at low confidence.
         */
        double total = 0;
        for (Suspect s : suspects) {
            s.score = s.partOf != null ? 0 : evidenceScore(s) * verdictFactor(s.verdict);
            total += s.score;
        }
        boolean matched = total > 0;
        Map<Suspect, Double> rank = new HashMap<>();
        double rankTotal = 0;
        for (Suspect s : suspects) {
            double value = matched ? s.score : s.partOf != null ? 0 : evidenceScore(s);
            rank.put(s, value);
            rankTotal += value;
        }
        Suspect pick = suspects.stream()
                .max(Comparator.comparingDouble((Suspect s) -> rank.get(s)).thenComparing(s -> -s.order))
                .orElseThrow();
        if (rank.get(pick) <= 0) {
            pick = suspects.get(0);
        }
        double share = rankTotal > 0 ? rank.get(pick) * 100 / rankTotal : 0;
        String exit;
        if (!matched) {
            exit = rankTotal > 0 ? "no suspect matched the question; the closest weak match"
                    : "no suspect showed the symptom; the thread finder's most likely suspect";
        } else if (budget.wallClockHit) {
            exit = "stopped at the wall-clock limit; best evidence so far";
        } else if (budget.refused > 0) {
            exit = budget.refused + " analyses not run: they would have gone over the budget";
        } else {
            exit = "all suspects searched";
        }
        String confidence;
        if (!matched || share < 40 || budget.wallClockHit || budget.refused > 0 && pick.level < 3) {
            confidence = "low";
        } else if (share >= 70 && "match".equals(pick.verdict) && pick.level == 3) {
            confidence = "high";
        } else {
            confidence = "medium";
        }

        JsonArray results = new JsonArray();
        for (Suspect s : suspects) {
            JsonObject row = new JsonObject();
            if (s.tid != null) {
                row.addProperty("tid", s.tid);
            }
            row.addProperty("pid", s.pid);
            row.addProperty("label", s.label());
            row.addProperty("name", s.name);
            row.addProperty("finder_reason", s.reason);
            row.addProperty("level_reached", s.level);
            row.addProperty("verdict", s.verdict);
            row.addProperty("verdict_reason", s.verdictReason);
            row.addProperty("verdict_level", s.verdict == null ? null : s.verdictLevel);
            row.addProperty("score", round3(s.score));
            row.addProperty("share_percent", rankTotal > 0 ? Math.round(rank.get(s) * 1000 / rankTotal) / 10.0 : 0);
            if (s.partOf != null) {
                row.addProperty("part_of_delay_of_tid", s.partOf.tid);
                row.addProperty("part_of_delay_of", s.partOf.label());
            }
            row.add("evidence", s.facts);
            results.add(row);
        }
        JsonObject search = new JsonObject();
        search.addProperty("symptom", symptom);
        search.addProperty("pick", pick.label());
        search.addProperty("pick_name", pick.name);
        search.addProperty("pick_reason", pickReason(pick, suspects, symptom));
        search.addProperty("pick_share_percent", Math.round(share * 10) / 10.0);
        search.addProperty("confidence", confidence);
        search.addProperty("exit", exit);
        search.add("suspects", results);
        search.add("judge", judge.log);
        search.add("budget", budget.json());

        JsonObject json = decision.json().deepCopy();
        json.addProperty("used", "search pick");
        json.addProperty("picked", pick.label() + (pick.name != null ? " (" + pick.name + ")" : ""));
        json.add("search", search);

        JsonObject target = new JsonObject();
        if (pick.tid != null) {
            target.addProperty("tid", pick.tid);
        } else {
            target.addProperty("pid", pick.pid);
        }
        if (pick.name != null) {
            target.addProperty("name", pick.name);
        }
        target.addProperty("matched", "thread search: " + str(search, "pick_reason"));
        target.addProperty("source", "thread_search");
        return new ThreadFinder.Decision(target, false, symptom, json);
    }

    // ------------------------------------------------------------------ one-off delay

    /**
     * Level 1: cycle lengths from the state history (all suspects). Level 2:
     * TMLL's late-cycle finder (all suspects, strongest level-1 signal
     * first). Level 3: the explainers on the late cycle (the suspects with
     * one; all of them on their longest cycle when none has one). Then, a
     * suspect that held up another suspect during that one's late cycle (it
     * held its CPU, woke it, or is on its critical path) is part of the same
     * delay, not a separate answer: the pick is the thread at the end of the
     * chain, whose answer explains the others.
     */
    private static void searchOneOffDelay(String question, ITmfTrace trace, List<Suspect> suspects,
            JsonObject numbers, Budget budget, LateCycleFinder lateCycles, Map<Integer, JsonObject> threadRows,
            Judge judge) {
        long traceStart = trace.getStartTime().toNanos();
        for (Suspect s : suspects) {
            JsonObject stats = budget.run(s, 1, "cycle lengths (state history)", lifetimeFraction(s, threadRows, budget),
                    WEIGHT_STATE, () -> TraceInventory.cycleStats(trace, s.tid));
            if (stats == null) {
                continue;
            }
            s.level = 1;
            s.facts.add("level_1", stats);
            if (bool(stats, "available")) {
                double longest = dbl(stats, "longest_cycle_ms", 0);
                double median = dbl(stats, "median_cycle_ms", 0);
                s.strength = 1 - 1 / Math.max(1, dbl(stats, "longest_over_median", 1));
                s.closeness = closeness(numbers, longest - median, longest, median);
                s.delayMs = longest - median;
                s.cycleMs = longest;
                s.periodMs = median;
                s.windowStart = num(stats, "longest_start_ns", 0L);
                s.windowEnd = num(stats, "longest_end_ns", 0L);
            }
        }

        List<Suspect> byStrength = new ArrayList<>(suspects);
        byStrength.sort(Comparator.comparingDouble((Suspect s) -> -s.strength * s.closeness).thenComparingInt(s -> s.order));
        for (Suspect s : byStrength) {
            if (s.level < 1 || s.windowStart == null) {
                continue;
            }
            JsonObject found = budget.run(s, 2, "TMLL late-cycle finder", lifetimeFraction(s, threadRows, budget),
                    WEIGHT_STATE, () -> lateCycles.find(s.tid));
            if (found == null) {
                continue;
            }
            s.level = 2;
            JsonObject stageA = obj(obj(found, "periodic_jitter"), "stage_a");
            JsonObject summary = new JsonObject();
            if (stageA == null || !bool(stageA, "available")) {
                summary.addProperty("available", false);
                summary.addProperty("reason", stageA == null ? "no answer from the late-cycle finder" : str(stageA, "reason"));
                s.facts.add("level_2", summary);
                continue;
            }
            JsonArray anomalies = arr(stageA, "anomalies");
            summary.add("activation_count", stageA.get("activation_count"));
            summary.add("expected_period_ms", stageA.get("expected_period_ms"));
            summary.addProperty("late_cycle_count", anomalies.size());
            JsonObject worst = null;
            for (JsonElement element : anomalies) {
                JsonObject late = element.getAsJsonObject();
                if (worst == null || dbl(late, "delay_ms", 0) > dbl(worst, "delay_ms", 0)) {
                    worst = late;
                }
            }
            if (worst == null) {
                // TMLL's detector found no abnormal cycle: the level-1 signal counts for less.
                s.strength *= 0.5;
            } else {
                s.positive = true;
                s.lateCycles = found;
                double delay = dbl(worst, "delay_ms", 0);
                double cycle = dbl(worst, "observed_period_ms", 0);
                summary.addProperty("worst_delay_ms", delay);
                summary.addProperty("worst_cycle_ms", cycle);
                summary.add("worst_delay_factor", worst.get("delay_factor"));
                summary.add("worst_gap_kind", worst.get("gap_kind"));
                s.windowStart = num(worst, "gap_start_timestamp_ns", s.windowStart);
                s.windowEnd = num(worst, "gap_end_timestamp_ns", s.windowEnd);
                summary.addProperty("worst_start_offset_ms", (s.windowStart - traceStart) / 1_000_000.0);
                s.strength = 1 - 1 / Math.max(1, dbl(worst, "delay_factor", 1));
                s.closeness = closeness(numbers, delay, cycle, dbl(stageA, "expected_period_ms", 0));
                s.delayMs = delay;
                s.cycleMs = cycle;
                s.periodMs = dbl(stageA, "expected_period_ms", s.periodMs);
            }
            s.facts.add("level_2", summary);
        }

        /*
         * The judge after level 2 decides who goes deeper: a match or a weak
         * match does; if nobody is either, everyone does. Level 1 to 2 needs
         * no judge: level 2 is a cheap state-system query for every suspect.
         * Without a judge (it failed), the late cycle TMLL found decides.
         */
        judge.rate(2, suspects);
        boolean anyPromising = suspects.stream().anyMatch(ThreadSearch::promising);
        for (Suspect s : byStrength) {
            if (s.level < 2 || anyPromising && !promising(s) || s.windowStart == null) {
                continue;
            }
            List<ExplainWindow> windows;
            JsonObject scan;
            if (s.positive) {
                windows = AnswerPipeline.chooseWindows(QueryPlan.of(question, s.tid, null, trace, true), trace, s.lateCycles);
                scan = AnswerPipeline.lateCycleScan(s.lateCycles);
            } else {
                JsonObject details = new JsonObject();
                details.addProperty("interpreted_as", "the thread's longest cycle (no abnormal cycle was found)");
                windows = List.of(
                        new ExplainWindow("whole_trace", "whole_trace", traceStart, trace.getEndTime().toNanos(), null),
                        new ExplainWindow("longest_cycle", "user", s.windowStart, s.windowEnd, details));
                scan = null;
            }
            double fraction = (s.windowEnd - s.windowStart) / (double) budget.durationNs;
            JsonArray findings = budget.run(s, 3, "state split and per-state explainers of the late cycle", fraction,
                    WEIGHT_SCAN, () -> UnifiedExplainer.explain(trace, s.tid, windows, false, scan, question));
            if (findings == null) {
                continue;
            }
            s.level = 3;
            JsonArray claims = new JsonArray();
            for (JsonElement element : findings) {
                JsonObject finding = element.getAsJsonObject();
                String about = str(finding, "about");
                if (about == null || !(about.startsWith("late_cycle[") || "longest_cycle".equals(about))) {
                    continue;
                }
                if (claims.size() < 6) {
                    claims.add(str(finding, "id") + ": " + str(finding, "claim"));
                }
                collectTids(obj(obj(finding, "evidence"), "data"), s.linked);
            }
            s.linked.remove(s.tid);
            JsonObject summary = new JsonObject();
            summary.add("findings", claims);
            JsonArray linked = new JsonArray();
            s.linked.forEach(linked::add);
            summary.add("threads_involved", linked);
            s.facts.add("level_3", summary);
        }

        // One delay, several suspects: the ones that held up another suspect are part of its delay.
        for (Suspect a : suspects) {
            for (Suspect b : suspects) {
                if (a == b || a.level < 3 || !b.positive || b.tid == null || !a.linked.contains(b.tid) || !overlap(a, b)) {
                    continue;
                }
                boolean mutual = b.linked.contains(a.tid);
                if (!mutual || b.windowEnd < a.windowEnd || b.windowEnd.equals(a.windowEnd) && b.order > a.order) {
                    b.partOf = a;
                }
            }
        }
        // A chain of three or more (C held up B, B held up A): every link points to its end, A.
        for (Suspect s : suspects) {
            Suspect end = s.partOf;
            for (int i = 0; end != null && end.partOf != null && i < suspects.size(); i++) {
                end = end.partOf;
            }
            s.partOf = end == s || end != null && end.partOf != null ? null : end; // a loop links nobody
        }
        judge.rate(3, suspects);
    }

    /** Goes to level 3: the judge's match or weak match; without a verdict, a late cycle TMLL found. */
    private static boolean promising(Suspect s) {
        return s.verdict == null ? s.positive : !"no".equals(s.verdict);
    }

    // ------------------------------------------------------------------ the four state-based symptoms

    /**
     * What each state-based symptom measures (thread_finder_design.md,
     * section 4).
     *
     * @param metric
     *            the level-1 value compared across suspects (a key of
     *            {@link TraceInventory#stateProfile})
     * @param worst
     *            the level-1 interval that is the thread's worst moment (key
     *            prefix), or null when level 2 finds it
     * @param detail
     *            the level-2 detail finder ({@link UnifiedExplainer#details})
     * @param finding
     *            the id of the finding it produces
     * @param moment
     *            what the level-3 window is, for the explainers and the log
     * @param describe
     *            level 3 also accounts for what the thread did (its activity)
     */
    private record Profile(String metric, String metricLabel, String worst, String detail, String finding,
            String moment, boolean describe) {
    }

    private static final Map<String, Profile> PROFILES = Map.of(
            "busiest_cpu", new Profile("running_ms", "time on the CPU", null, "cpu_peak", "running.cpu_peak",
                    "its busiest CPU window", true),
            "long_blocked_waits", new Profile("longest_blocked_ms", "longest blocked wait", "longest_blocked",
                    "syscalls", "syscalls.longest", "its longest blocked wait", false),
            "slow_scheduling", new Profile("waiting_for_cpu_ms", "time waiting for a CPU", "longest_wait_for_cpu",
                    "sched_latency", "scheduling.latency", "its worst wait for a CPU", false),
            "slow_syscalls_io", new Profile("longest_system_call_ms", "longest system call", "longest_system_call",
                    "syscalls", "syscalls.longest", "its longest system call", false));

    /**
     * Level 1: the state profile from the state history (all suspects; the
     * strength is each one's share of the metric over all suspects). Level 2:
     * the symptom's detail finding from the state system (all suspects: the
     * busiest CPU window, the longest system calls, the wake-up delays; for a
     * long blocked wait, the call it blocked in). The judge, then level 3:
     * the per-state explainers over the suspect's worst moment (what it ran,
     * who held its CPU, who woke it), for the match or weak suspects, or all
     * when none is either. The judge again.
     */
    private static void searchProfile(String question, ITmfTrace trace, String symptom, List<Suspect> suspects,
            JsonObject numbers, Budget budget, Map<Integer, JsonObject> threadRows, Judge judge) {
        Profile profile = PROFILES.get(symptom);
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        for (Suspect s : suspects) {
            JsonObject stats = budget.run(s, 1, "state profile (state history)", lifetimeFraction(s, threadRows, budget),
                    WEIGHT_STATE, () -> TraceInventory.stateProfile(trace, s.tid));
            if (stats == null) {
                continue;
            }
            s.level = 1;
            s.facts.add("level_1", stats);
            if (!bool(stats, "available")) {
                continue;
            }
            s.metric = dbl(stats, profile.metric(), 0);
            s.worstMs = s.metric;
            if (profile.worst() != null && stats.has(profile.worst() + "_start_ns")) {
                s.worstMs = dbl(stats, profile.worst() + "_ms", 0);
                s.windowStart = num(stats, profile.worst() + "_start_ns", 0L);
                s.windowEnd = num(stats, profile.worst() + "_end_ns", 0L);
            }
        }
        double sum = 0;
        for (Suspect s : suspects) {
            sum += s.metric;
        }
        for (Suspect s : suspects) {
            s.strength = sum > 0 ? s.metric / sum : 0;
            s.closeness = closenessTo(numbers, s.worstMs);
            s.positive = s.metric > 0; // without a judge, everyone with a measurement goes deeper
        }

        List<Suspect> byStrength = new ArrayList<>(suspects);
        byStrength.sort(Comparator.comparingDouble((Suspect s) -> -s.strength * s.closeness).thenComparingInt(s -> s.order));
        for (Suspect s : byStrength) {
            if (s.level < 1 || !bool(obj(s.facts, "level_1"), "available")) {
                continue;
            }
            boolean inWait = "long_blocked_waits".equals(symptom) && s.windowStart != null;
            ExplainWindow window = inWait
                    ? new ExplainWindow("longest_blocked", "user", s.windowStart, s.windowEnd, interpreted(profile.moment()))
                    : new ExplainWindow("whole_trace", "whole_trace", traceStart, traceEnd, null);
            double fraction = inWait ? (s.windowEnd - s.windowStart) / (double) budget.durationNs
                    : lifetimeFraction(s, threadRows, budget);
            JsonArray findings = budget.run(s, 2, profile.finding() + " (state system)", fraction, WEIGHT_STATE,
                    () -> UnifiedExplainer.details(trace, s.tid, window, Set.of(profile.detail())));
            if (findings == null) {
                continue;
            }
            s.level = 2;
            JsonObject summary = new JsonObject();
            JsonObject finding = findingOf(findings, profile.finding());
            JsonObject data = finding == null ? null : obj(obj(finding, "evidence"), "data");
            if (data == null) {
                summary.addProperty("found", false);
                s.facts.add("level_2", summary);
                continue;
            }
            summary.add("claim", finding.get("claim"));
            switch (symptom) {
            case "busiest_cpu":
                s.windowStart = num(data, "peak_start_ns", 0L);
                s.windowEnd = num(data, "peak_end_ns", 0L);
                for (String key : new String[] {"peak_running_ms", "peak_percent", "average_percent", "window_ms"}) {
                    summary.add(key, data.get(key));
                }
                break;
            case "slow_scheduling":
                if (data.has("worst_start_ns")) {
                    s.worstMs = dbl(data, "worst_ms", s.worstMs);
                    s.windowStart = num(data, "worst_start_ns", 0L);
                    s.windowEnd = num(data, "worst_end_ns", 0L);
                }
                for (String key : new String[] {"wakeups", "median_ms", "p99_ms", "worst_ms", "preempted_ms"}) {
                    summary.add(key, data.get(key));
                }
                break;
            default: // the longest system calls (in the thread's life, or in its longest blocked wait)
                JsonArray longest = arr(data, "longest");
                JsonArray top = new JsonArray();
                for (int i = 0; i < Math.min(3, longest.size()); i++) {
                    JsonObject call = longest.get(i).getAsJsonObject();
                    JsonObject item = new JsonObject();
                    for (String key : new String[] {"system_call", "duration_ms", "start_offset_ms"}) {
                        item.add(key, call.get(key));
                    }
                    top.add(item);
                }
                summary.add("call_count", data.get("call_count"));
                summary.add("median_ms", data.get("median_ms"));
                summary.add("longest", top);
                if (inWait && !top.isEmpty()) {
                    summary.add("blocked_in", top.get(0).getAsJsonObject().get("system_call"));
                }
                if ("slow_syscalls_io".equals(symptom) && !longest.isEmpty()) {
                    // The longest call that returned: exit and exit_group last until the thread ends.
                    JsonObject first = data.has("longest_completed") ? obj(data, "longest_completed")
                            : longest.get(0).getAsJsonObject();
                    s.worstMs = dbl(first, "duration_ms", s.worstMs);
                    s.windowStart = num(first, "start_ns", 0L);
                    s.windowEnd = num(first, "end_ns", 0L);
                }
                break;
            }
            s.closeness = closenessTo(numbers, s.worstMs);
            s.facts.add("level_2", summary);
        }

        judge.rate(2, suspects);
        boolean anyPromising = suspects.stream().anyMatch(ThreadSearch::promising);
        for (Suspect s : byStrength) {
            if (s.level < 2 || anyPromising && !promising(s) || s.windowStart == null || s.windowEnd <= s.windowStart) {
                continue;
            }
            List<ExplainWindow> windows = List.of(
                    new ExplainWindow("whole_trace", "whole_trace", traceStart, traceEnd, null),
                    new ExplainWindow("worst_moment", "user", s.windowStart, s.windowEnd, interpreted(profile.moment())));
            JsonArray findings = budget.run(s, 3, "state split and per-state explainers of " + profile.moment(),
                    (s.windowEnd - s.windowStart) / (double) budget.durationNs, WEIGHT_SCAN,
                    () -> UnifiedExplainer.explain(trace, s.tid, windows, profile.describe(), null, question));
            if (findings == null) {
                continue;
            }
            s.level = 3;
            JsonArray claims = new JsonArray();
            for (JsonElement element : findings) {
                JsonObject finding = element.getAsJsonObject();
                if ("worst_moment".equals(str(finding, "about")) && claims.size() < 6) {
                    claims.add(str(finding, "id") + ": " + str(finding, "claim"));
                }
            }
            JsonObject summary = new JsonObject();
            summary.addProperty("window", profile.moment());
            summary.addProperty("start_offset_ms", (s.windowStart - traceStart) / 1_000_000.0);
            summary.addProperty("length_ms", (s.windowEnd - s.windowStart) / 1_000_000.0);
            summary.add("findings", claims);
            s.facts.add("level_3", summary);
        }
        judge.rate(3, suspects);
    }

    private static JsonObject interpreted(String what) {
        JsonObject details = new JsonObject();
        details.addProperty("interpreted_as", what);
        return details;
    }

    private static JsonObject findingOf(JsonArray findings, String id) {
        for (JsonElement element : findings) {
            if (id.equals(str(element.getAsJsonObject(), "id"))) {
                return element.getAsJsonObject();
            }
        }
        return null;
    }

    /** How well a measured worst moment fits a size the question states ("waits about 200 ms"). */
    private static double closenessTo(JsonObject numbers, double worstMs) {
        Double magnitude = optional(numbers, "magnitude_ms");
        return magnitude == null || magnitude <= 0 ? 1 : Math.max(0.05, ratio(worstMs, magnitude));
    }

    // ------------------------------------------------------------------ bottleneck

    /**
     * Level 1: the inventory's state shares (no cost: already built). Levels
     * 2-3 in one analysis: the process explainer (the main thread's wait
     * chain, an example critical path, the round profile), cached, so the
     * answer reuses it. Process suspects are scored by the share of the main
     * thread's waiting on other threads that its bottleneck explains, times
     * the share of its life the main thread spent waiting on them; thread
     * suspects by the share of the main thread's waits each one ended. A
     * bottleneck the finder did not suspect is added to the suspects.
     */
    private static void searchBottleneck(ITmfTrace trace, boolean processScope, List<Suspect> suspects, Budget budget,
            Map<Integer, JsonObject> threadRows, Judge judge) {
        long start = trace.getStartTime().toNanos();
        long end = trace.getEndTime().toNanos();
        ExplainWindow whole = new ExplainWindow("whole_trace", "whole_trace", start, end, null);
        Map<Integer, List<Suspect>> byProcess = new LinkedHashMap<>();
        for (Suspect s : suspects) {
            if (s.pid != null) {
                byProcess.computeIfAbsent(s.pid, k -> new ArrayList<>()).add(s);
            }
        }
        for (Map.Entry<Integer, List<Suspect>> entry : byProcess.entrySet()) {
            int pid = entry.getKey();
            Suspect first = entry.getValue().get(0);
            JsonObject mainRow = threadRows.get(pid);
            for (Suspect s : entry.getValue()) {
                JsonObject level1 = new JsonObject();
                JsonObject row = s.tid != null ? threadRows.get(s.tid) : mainRow;
                if (row != null) {
                    for (String key : new String[] {"running_percent", "waiting_for_cpu_percent", "blocked_percent", "lifetime_ms"}) {
                        level1.add(key, row.get(key));
                    }
                }
                s.facts.add("level_1", level1);
                s.level = 1;
            }
            ProcessAnalysis analysis = budget.run(first, 2,
                    "process explainer: main-thread wait chain, example critical path, round profile", 1.0, WEIGHT_STATE,
                    () -> AnswerPipeline.processAnalysis(trace, pid, whole, false));
            if (analysis == null) {
                continue;
            }
            JsonObject data = null;
            for (JsonElement element : analysis.findings) {
                JsonObject finding = element.getAsJsonObject();
                if ("process.bottleneck".equals(str(finding, "id"))) {
                    data = obj(obj(finding, "evidence"), "data");
                }
            }
            JsonObject summary = new JsonObject();
            if (data == null || !"main_thread_wait_chain".equals(str(data, "method"))) {
                summary.addProperty("bottleneck_found", false);
                for (Suspect s : entry.getValue()) {
                    s.level = 3;
                    s.facts.add("level_2_3", summary);
                }
                continue;
            }
            int bottleneck = data.get("bottleneck_tid").getAsInt();
            double onThreads = dbl(data, "main_wait_on_threads_ms", 0);
            double mainLife = mainRow == null ? 0 : dbl(mainRow, "lifetime_ms", 0);
            summary.addProperty("bottleneck_found", true);
            summary.addProperty("bottleneck_tid", bottleneck);
            summary.add("bottleneck_name", data.get("bottleneck_name"));
            summary.add("percent_of_main_thread_waits", data.get("bottleneck_percent_of_main_thread_waits"));
            summary.addProperty("main_wait_on_threads_ms", onThreads);
            summary.add("root", data.get("root"));
            if (processScope) {
                double waitShare = mainLife > 0 ? Math.min(1, onThreads / mainLife) : 1;
                first.strength = dbl(data, "bottleneck_percent_of_main_thread_waits", 0) / 100.0 * waitShare;
                first.level = 3;
                first.facts.add("level_2_3", summary);
                continue;
            }
            Map<Integer, Double> ended = new HashMap<>();
            for (JsonElement element : arr(data, "wakers_of_main_thread")) {
                JsonObject waker = element.getAsJsonObject();
                ended.put(waker.get("tid").getAsInt(), dbl(waker, "ended_main_waits_ms", 0));
            }
            List<Suspect> group = new ArrayList<>(entry.getValue());
            if (group.stream().noneMatch(s -> s.tid != null && s.tid == bottleneck)) {
                Suspect added = new Suspect(bottleneck, pid, str(data, "bottleneck_name"),
                        "added by the search: the process's wait chain points to it", suspects.size());
                suspects.add(added);
                group.add(added);
            }
            for (Suspect s : group) {
                JsonObject own = summary.deepCopy();
                double share = s.tid == null || onThreads <= 0 ? 0 : ended.getOrDefault(s.tid, 0.0) / onThreads;
                own.addProperty("percent_of_main_thread_waits_it_ended", round3(share * 100));
                s.strength = share;
                s.level = 3;
                s.facts.add("level_2_3", own);
            }
        }
        judge.rate(3, suspects);
    }

    // ------------------------------------------------------------------ helpers

    private static String pickReason(Suspect pick, List<Suspect> suspects, String symptom) {
        StringBuilder reason = new StringBuilder();
        String who = pick.label() + (pick.name != null ? " (" + pick.name + ")" : "");
        if ("one_off_delay".equals(symptom)) {
            JsonObject level2 = obj(pick.facts, "level_2");
            JsonObject level1 = obj(pick.facts, "level_1");
            if (pick.positive && level2 != null) {
                reason.append(String.format(Locale.ROOT, "%s had the late cycle that best fits the question: %.3f ms "
                        + "instead of about %.3f ms", who, dbl(level2, "worst_cycle_ms", 0),
                        dbl(level2, "expected_period_ms", 0)));
            } else if (level1 != null && bool(level1, "available")) {
                reason.append(String.format(Locale.ROOT, "%s: no abnormal cycle was found; its longest cycle was %.3f ms "
                        + "against a median of %.3f ms", who, dbl(level1, "longest_cycle_ms", 0),
                        dbl(level1, "median_cycle_ms", 0)));
            } else {
                reason.append(who).append(": the thread finder's most likely suspect");
            }
            List<String> part = new ArrayList<>();
            for (Suspect s : suspects) {
                if (s.partOf == pick) {
                    part.add(s.label() + (s.name != null ? " (" + s.name + ")" : ""));
                }
            }
            if (!part.isEmpty()) {
                reason.append("; ").append(String.join(", ", part))
                        .append(part.size() == 1 ? " was" : " were")
                        .append(" delayed too, as part of the same delay (it held this thread up during its late cycle)");
            }
        } else if (PROFILES.containsKey(symptom)) {
            Profile profile = PROFILES.get(symptom);
            List<Double> peers = new ArrayList<>();
            for (Suspect s : suspects) {
                if (s != pick && s.level >= 1) {
                    peers.add(s.metric);
                }
            }
            peers.sort(Double::compare);
            double median = peers.isEmpty() ? 0 : peers.get(peers.size() / 2);
            reason.append(String.format(Locale.ROOT, "%s: %s %.3f ms", who, profile.metricLabel(), pick.metric));
            if (median > 0) {
                reason.append(String.format(Locale.ROOT, ", %.1fx the median of the other suspects (%.3f ms)",
                        pick.metric / median, median));
            } else if (!peers.isEmpty()) {
                reason.append(", against 0 ms for the other suspects");
            }
        } else {
            JsonObject found = obj(pick.facts, "level_2_3");
            if (found != null && bool(found, "bottleneck_found")) {
                reason.append(pick.tid != null
                        ? String.format(Locale.ROOT, "%s ended %.1f%% of the main thread's waiting on other threads", who,
                                dbl(found, "percent_of_main_thread_waits_it_ended", 0))
                        : String.format(Locale.ROOT, "%s: TID %d ends %.1f%% of its main thread's waiting on other threads",
                                who, num(found, "bottleneck_tid", 0L), dbl(found, "percent_of_main_thread_waits", 0)));
            } else {
                reason.append(who).append(": the thread finder's most likely suspect");
            }
        }
        return reason.toString();
    }

    /** How well a measured delay or cycle fits the question's numbers: 1 = exactly, towards 0 = far off. */
    private static double closeness(JsonObject numbers, double delayMs, double cycleMs, double periodMs) {
        double closeness = 1;
        Double magnitude = optional(numbers, "magnitude_ms");
        if (magnitude != null && magnitude > 0) {
            // "Delayed by about 30 ms" is the delay; "took about 15 ms" is the cycle: whichever fits.
            closeness *= Math.max(0.05, Math.max(ratio(delayMs, magnitude), ratio(cycleMs, magnitude)));
        }
        Double period = optional(numbers, "period_ms");
        if (period != null && period > 0 && periodMs > 0) {
            closeness *= Math.max(0.05, ratio(periodMs, period));
        }
        return closeness;
    }

    private static double ratio(double a, double b) {
        return a <= 0 || b <= 0 ? 0 : Math.min(a, b) / Math.max(a, b);
    }

    private static Double optional(JsonObject object, String key) {
        return object != null && isSet(object, key) ? object.get(key).getAsDouble() : null;
    }

    private static boolean overlap(Suspect a, Suspect b) {
        return a.windowStart != null && b.windowStart != null && a.windowStart <= b.windowEnd && b.windowStart <= a.windowEnd;
    }

    private static double lifetimeFraction(Suspect s, Map<Integer, JsonObject> threadRows, Budget budget) {
        JsonObject row = s.tid == null ? null : threadRows.get(s.tid);
        return row == null ? 1.0 : dbl(row, "lifetime_ms", 0) * 1_000_000.0 / budget.durationNs;
    }

    /** Every thread a finding's data names (CPU holders, wakers, critical-path segments). */
    private static void collectTids(JsonElement element, Set<Integer> into) {
        if (element == null || element.isJsonNull()) {
            return;
        }
        if (element.isJsonArray()) {
            element.getAsJsonArray().forEach(child -> collectTids(child, into));
        } else if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                JsonElement value = entry.getValue();
                if (LINK_KEYS.contains(entry.getKey()) && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                    into.add(value.getAsInt());
                } else {
                    collectTids(value, into);
                }
            }
        }
    }

    /** The evidence alone: signal strength x closeness to the question's numbers x depth of confirmation. */
    private static double evidenceScore(Suspect s) {
        return s.strength * s.closeness * DEPTH[s.level];
    }

    private static double verdictFactor(String verdict) {
        if (verdict == null) {
            return 1; // no judge: the evidence alone
        }
        return "match".equals(verdict) ? 1 : "weak".equals(verdict) ? 0.5 : 0;
    }

    // ------------------------------------------------------------------ the answer's "Why this thread"

    /**
     * The answer's opening section when TraceAssist picked the thread or
     * process (the question named no TID), written by code from the thread
     * finder's decision and the search, so it is the same every run. Null for
     * a whole-trace question or when the finder did not run.
     */
    static String whySection(JsonObject finder) {
        if (finder == null || !finder.has("scope") || "trace".equals(str(finder, "scope"))) {
            return null;
        }
        String noun = "process".equals(str(finder, "scope")) ? "process" : "thread";
        JsonObject search = obj(finder, "search");
        if (search == null) {
            String picked = str(finder, "picked");
            if (picked == null) {
                return null;
            }
            JsonObject target = obj(finder, "target");
            String reason = bool(finder, "follow_up") ? "it continues the previous question"
                    : target != null && str(target, "reason") != null && !str(target, "reason").isBlank()
                            ? lowerFirst(str(target, "reason")) : "the thread finder's most likely suspect";
            return "**Why this " + noun + ":** the question names no TID, so TraceAssist picked " + picked + ": "
                    + stripPeriod(reason) + ".";
        }
        JsonObject pick = null;
        List<String> partOf = new ArrayList<>();
        List<String> others = new ArrayList<>();
        List<String> noSign = new ArrayList<>();
        for (JsonElement element : arr(search, "suspects")) {
            JsonObject row = element.getAsJsonObject();
            String who = str(row, "label") + (str(row, "name") != null ? " (" + str(row, "name") + ")" : "");
            if (str(search, "pick").equals(str(row, "label"))) {
                pick = row;
            } else if (row.has("part_of_delay_of")) {
                partOf.add(who);
            } else if (dbl(row, "share_percent", 0) >= 1) {
                String reason = str(row, "verdict_reason");
                others.add(String.format(Locale.ROOT, "%s (%.0f%%)%s", who, dbl(row, "share_percent", 0),
                        reason == null ? "" : ": " + stripPeriod(lowerFirst(reason))));
            } else {
                noSign.add(who);
            }
        }
        StringBuilder text = new StringBuilder("**Why this ").append(noun).append(":** ");
        text.append(str(search, "pick"));
        if (str(search, "pick_name") != null) {
            text.append(" (").append(str(search, "pick_name")).append(")");
        }
        text.append(String.format(Locale.ROOT, ", %.0f%%. ", dbl(search, "pick_share_percent", 0)));
        String reason = pick == null ? null : str(pick, "verdict_reason");
        text.append(stripPeriod(reason != null ? reason : str(search, "pick_reason"))).append(".");
        if (!partOf.isEmpty()) {
            text.append(" ").append(String.join(", ", partOf)).append(partOf.size() == 1 ? " was" : " were")
                    .append(" delayed too, as part of the same delay: it held this thread up during its late cycle.");
        }
        if (!others.isEmpty()) {
            text.append(" Also look at ").append(String.join("; ", others)).append(".");
        }
        if (!noSign.isEmpty()) {
            text.append(" Checked, no sign of it: ").append(String.join(", ", noSign)).append(".");
        }
        text.append(" Confidence: ").append(str(search, "confidence")).append(".");
        String exit = str(search, "exit");
        if (exit != null && !"all suspects searched".equals(exit)) {
            text.append(" (Search: ").append(exit).append(".)");
        }
        return text.toString();
    }

    private static String stripPeriod(String text) {
        String trimmed = text == null ? "" : text.trim();
        return trimmed.endsWith(".") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private static String lowerFirst(String text) {
        // "This is the only thread" -> "this is the only thread"; leave "TID 1234 ..." alone.
        if (text == null || text.length() < 2 || !Character.isUpperCase(text.charAt(0))
                || Character.isUpperCase(text.charAt(1))) {
            return text;
        }
        return Character.toLowerCase(text.charAt(0)) + text.substring(1);
    }

    // ------------------------------------------------------------------ the match judge

    /**
     * The match judge (AI skill {@code skills/match_judge/}): after a level,
     * rates each measured suspect match, weak or no, from the evidence and a
     * code-computed comparison. Its verdicts decide who goes deeper and weigh
     * the scores; it cannot run analyses, raise the budget or revisit a
     * suspect. A failed call is logged and the code facts decide instead.
     */
    private static final class Judge {
        static final String SKILL = "match_judge";
        private static final Set<String> VERDICTS = Set.of("match", "weak", "no");

        final String question;
        final JsonObject numbers;
        final String symptom;
        final Budget budget;
        final JsonArray log = new JsonArray();

        Judge(String question, JsonObject numbers, String symptom, Budget budget) {
            this.question = question;
            this.numbers = numbers;
            this.symptom = symptom;
            this.budget = budget;
        }

        void rate(int level, List<Suspect> suspects) {
            List<Suspect> measured = new ArrayList<>();
            for (Suspect s : suspects) {
                if (s.level >= 1) {
                    measured.add(s);
                }
            }
            if (measured.isEmpty()) {
                return;
            }
            JsonObject entry = new JsonObject();
            entry.addProperty("level", level);
            log.add(entry);
            if (System.nanoTime() - budget.startedNs > MAX_WALL_NS) {
                budget.wallClockHit = true;
                entry.addProperty("status", "not run: wall-clock limit reached");
                return;
            }
            JsonObject input = new JsonObject();
            input.addProperty("question", question);
            input.add("question_numbers", numbers);
            input.addProperty("symptom", symptom);
            input.addProperty("level", level);
            JsonArray list = new JsonArray();
            for (Suspect s : measured) {
                JsonObject row = new JsonObject();
                row.addProperty("suspect", s.label());
                row.addProperty("name", s.name);
                row.addProperty("finder_reason", s.reason);
                row.addProperty("level_reached", s.level);
                row.add("evidence", s.facts);
                row.add("comparison", comparison(s, measured));
                list.add(row);
            }
            input.add("suspects", list);
            long started = System.nanoTime();
            try {
                JsonObject answer = AiSkill.load(SKILL).run(input);
                Map<String, Suspect> byLabel = new HashMap<>();
                measured.forEach(s -> byLabel.put(s.label(), s));
                JsonArray verdicts = new JsonArray();
                JsonArray rejected = new JsonArray();
                for (JsonElement element : arr(answer, "verdicts")) {
                    JsonObject verdict = element.getAsJsonObject();
                    Suspect s = byLabel.get(str(verdict, "suspect"));
                    if (s == null || !VERDICTS.contains(str(verdict, "verdict"))) {
                        rejected.add(verdict); // a suspect it was not shown: ignored
                        continue;
                    }
                    s.verdict = str(verdict, "verdict");
                    s.verdictReason = str(verdict, "reason");
                    s.verdictLevel = level;
                    verdicts.add(verdict);
                }
                entry.addProperty("status", "done");
                entry.addProperty("cached", bool(answer, "_cached"));
                entry.add("verdicts", verdicts);
                if (rejected.size() > 0) {
                    entry.add("rejected", rejected);
                }
                entry.add("reasoning", answer.get("reasoning"));
            } catch (Exception exception) {
                entry.addProperty("status", "failed (code facts decide): " + (exception.getMessage() != null
                        ? exception.getMessage() : exception.toString()));
            } finally {
                entry.addProperty("ms", round3((System.nanoTime() - started) / 1_000_000.0));
            }
        }

        /** The numbers the judge decides on (code-computed, so it never does arithmetic). */
        private JsonObject comparison(Suspect s, List<Suspect> measured) {
            JsonObject comparison = new JsonObject();
            List<Double> peers = new ArrayList<>();
            boolean delay = "one_off_delay".equals(symptom);
            for (Suspect other : measured) {
                if (other != s) {
                    peers.add(delay ? other.delayMs : PROFILES.containsKey(symptom) ? other.metric : other.strength);
                }
            }
            peers.sort(Double::compare);
            Double peerMedian = peers.isEmpty() ? null : peers.get(peers.size() / 2);
            if (delay) {
                comparison.addProperty("delay_ms", round3(s.delayMs));
                comparison.addProperty("cycle_ms", round3(s.cycleMs));
                comparison.addProperty("typical_cycle_ms", round3(s.periodMs));
                JsonObject vsQuestion = new JsonObject();
                Double magnitude = optional(numbers, "magnitude_ms");
                if (magnitude != null && magnitude > 0) {
                    vsQuestion.addProperty("delay_vs_stated_size", round3(s.delayMs / magnitude));
                    vsQuestion.addProperty("cycle_vs_stated_size", round3(s.cycleMs / magnitude));
                }
                Double period = optional(numbers, "period_ms");
                if (period != null && period > 0 && s.periodMs > 0) {
                    vsQuestion.addProperty("typical_cycle_vs_stated_period", round3(s.periodMs / period));
                }
                comparison.add("vs_question", vsQuestion);
                if (peerMedian != null) {
                    comparison.addProperty("delay_vs_peers", peerMedian > 0 ? round3(s.delayMs / peerMedian) : null);
                    comparison.addProperty("peer_median_delay_ms", round3(peerMedian));
                }
                JsonObject level1 = obj(s.facts, "level_1");
                if (level1 != null && level1.has("longest_z_score")) {
                    comparison.addProperty("longest_cycle_z_score", round3(dbl(level1, "longest_z_score", 0)));
                }
                if (s.level >= 2) {
                    comparison.addProperty("late_cycle_found", s.positive);
                }
                if (s.partOf != null) {
                    comparison.addProperty("part_of_delay_of",
                            s.partOf.label() + (s.partOf.name != null ? " (" + s.partOf.name + ")" : ""));
                }
            } else if (PROFILES.containsKey(symptom)) {
                Profile profile = PROFILES.get(symptom);
                comparison.addProperty("measure", profile.metricLabel());
                comparison.addProperty("value_ms", round3(s.metric));
                if (peerMedian != null) {
                    comparison.addProperty("value_vs_peers", peerMedian > 0 ? round3(s.metric / peerMedian) : null);
                    comparison.addProperty("peer_median_ms", round3(peerMedian));
                }
                comparison.addProperty("worst_moment", profile.moment());
                comparison.addProperty("worst_moment_ms", round3(s.worstMs));
                JsonObject vsQuestion = new JsonObject();
                Double magnitude = optional(numbers, "magnitude_ms");
                if (magnitude != null && magnitude > 0) {
                    vsQuestion.addProperty("worst_moment_vs_stated_size", round3(s.worstMs / magnitude));
                }
                comparison.add("vs_question", vsQuestion);
            } else {
                comparison.addProperty(s.tid != null ? "share_of_main_thread_waits_it_ended_percent"
                        : "bottleneck_share_x_main_thread_waiting_share_percent", round3(s.strength * 100));
                if (peerMedian != null) {
                    comparison.addProperty("vs_peers", peerMedian > 0 ? round3(s.strength / peerMedian) : null);
                    comparison.addProperty("peer_median_percent", round3(peerMedian * 100));
                }
            }
            return comparison;
        }
    }

    private static boolean isSet(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull();
    }

    private static double round3(double value) {
        return Math.round(value * 1000) / 1000.0;
    }

    private static final class Suspect {
        final Integer tid;
        final Integer pid;
        final String name;
        final String reason;
        final int order;
        final JsonObject facts = new JsonObject();
        final Set<Integer> linked = new LinkedHashSet<>();
        int level;
        double strength;
        double closeness = 1;
        boolean positive;
        JsonObject lateCycles;
        Long windowStart;
        Long windowEnd;
        Suspect partOf;
        double score;
        /** The measured values the judge compares (one-off delay: delay, cycle, period; bottleneck: share). */
        double delayMs;
        double cycleMs;
        double periodMs;
        /** The state-based symptoms: the level-1 metric and the worst single moment, in ms. */
        double metric;
        double worstMs;
        /** The match judge's latest verdict (match, weak, no), or null without a judge. */
        String verdict;
        String verdictReason;
        int verdictLevel;

        Suspect(Integer tid, Integer pid, String name, String reason, int order) {
            this.tid = tid;
            this.pid = pid;
            this.name = name;
            this.reason = reason;
            this.order = order;
        }

        String label() {
            return tid != null ? "TID " + tid : "PID " + pid;
        }
    }

    /**
     * The search's budget (thread_finder_design.md, section 5): every
     * analysis is charged its estimated cost before it runs, cost = event
     * count x share of the trace's time it covers x weight of its kind.
     * Level 1 always runs; a deeper analysis that would take the total over
     * 75% of the event count is not started. The search also stops after 30
     * minutes, whatever the estimate. Shared builds the answer needs anyway
     * (the kernel state system, the execution graph) are not charged.
     */
    static final class Budget {
        final long events;
        final double cap;
        final long durationNs;
        final long startedNs = System.nanoTime();
        final JsonArray log = new JsonArray();
        double spent;
        int refused;
        boolean wallClockHit;

        Budget(ITmfTrace trace) {
            events = Math.max(0, trace.getNbEvents());
            cap = events * CAP_SHARE;
            durationNs = Math.max(1, trace.getEndTime().toNanos() - trace.getStartTime().toNanos());
        }

        /** Runs one analysis if the budget allows it; null when refused or failed (both logged). */
        <T> T run(Suspect suspect, int level, String analysis, double fraction, double weight, Callable<T> work) {
            double cost = events * Math.min(1, Math.max(0, fraction)) * weight;
            JsonObject entry = new JsonObject();
            entry.addProperty("suspect", suspect.label());
            entry.addProperty("level", level);
            entry.addProperty("analysis", analysis);
            entry.addProperty("estimated_cost_events", Math.round(cost));
            log.add(entry);
            if (System.nanoTime() - startedNs > MAX_WALL_NS) {
                wallClockHit = true;
                entry.addProperty("status", "not run: wall-clock limit reached");
                return null;
            }
            if (level > 1 && events > 0 && spent + cost > cap) {
                refused++;
                entry.addProperty("status", "not run: over the budget");
                return null;
            }
            spent += cost;
            long started = System.nanoTime();
            try {
                T result = work.call();
                entry.addProperty("status", "done");
                return result;
            } catch (Exception exception) {
                entry.addProperty("status", "failed: " + (exception.getMessage() != null ? exception.getMessage()
                        : exception.toString()));
                return null;
            } finally {
                entry.addProperty("ms", round3((System.nanoTime() - started) / 1_000_000.0));
            }
        }

        JsonObject json() {
            JsonObject json = new JsonObject();
            json.addProperty("event_count", events);
            json.addProperty("cap_events", Math.round(cap));
            json.addProperty("spent_events", Math.round(spent));
            json.addProperty("spent_percent_of_cap", cap > 0 ? Math.round(spent * 1000 / cap) / 10.0 : 0);
            json.addProperty("wall_ms", round3((System.nanoTime() - startedNs) / 1_000_000.0));
            json.add("analyses", log);
            return json;
        }
    }
}
