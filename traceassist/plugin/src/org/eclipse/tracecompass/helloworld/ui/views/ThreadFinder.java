package org.eclipse.tracecompass.helloworld.ui.views;

import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.arr;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.bool;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.obj;
import static org.eclipse.tracecompass.helloworld.ui.views.AnswerPipeline.UnifiedExplainer.str;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Finds what a question without a TID is about (thread_finder_design.md,
 * steps 1-2): the trace inventory (code) and the thread_finder AI skill,
 * whose answer is checked against the inventory before it is used.
 * <p>
 * A question whose target is not clear goes to {@link ThreadSearch}, which
 * checks every suspect, when its symptom has a search; otherwise to the
 * skill's most likely suspect.
 */
final class ThreadFinder {

    static final String SKILL = "thread_finder";
    static final int MAX_SUSPECTS = 5;

    /**
     * The finder's decision.
     *
     * @param target
     *            the thread ({@code tid}) or process ({@code pid}) to analyse,
     *            in the shape of the name resolver's result; null for the
     *            whole trace
     * @param json
     *            the skill's (checked) answer and how it was used, for the
     *            plan and the answer log
     */
    record Decision(JsonObject target, boolean wholeTrace, String symptom, JsonObject json) {
    }

    private ThreadFinder() {
    }

    /**
     * Decides the question's target. Throws when the inventory is unavailable,
     * the skill cannot be reached, or its answer names nothing usable; the
     * caller then falls back to the name resolver.
     *
     * @param nameMatches
     *            the name resolver's exact matches, or null
     * @param previousTarget
     *            the previous question's target, or null
     */
    static Decision decide(String question, ITmfTrace trace, JsonObject nameMatches, JsonObject previousTarget)
            throws Exception {
        JsonObject inventory = TraceInventory.of(trace);
        if (!bool(inventory, "available")) {
            throw new IllegalStateException("trace inventory unavailable: " + str(inventory, "reason"));
        }
        JsonObject input = new JsonObject();
        input.addProperty("question", question);
        input.add("inventory", inventory);
        input.add("name_matches", nameMatches == null ? null : withoutBookkeeping(nameMatches));
        input.add("previous_target", previousTarget == null ? null : withoutBookkeeping(previousTarget));

        JsonObject answer = AiSkill.load(SKILL).run(input);

        // Everything the skill may name: the inventory, the exact name matches, the previous target.
        Map<Integer, Integer> pidOfTid = new HashMap<>();
        Map<Integer, String> names = new HashMap<>();
        Set<Integer> pids = new HashSet<>();
        for (JsonElement element : arr(inventory, "threads")) {
            JsonObject thread = element.getAsJsonObject();
            pidOfTid.put(thread.get("tid").getAsInt(), thread.get("pid").getAsInt());
            names.put(thread.get("tid").getAsInt(), str(thread, "name"));
            pids.add(thread.get("pid").getAsInt());
        }
        for (JsonElement element : arr(inventory, "processes")) {
            JsonObject process = element.getAsJsonObject();
            pids.add(process.get("pid").getAsInt());
            names.putIfAbsent(process.get("pid").getAsInt(), str(process, "name"));
        }
        for (JsonObject known : new JsonObject[] {nameMatches, previousTarget}) {
            if (known == null) {
                continue;
            }
            if (known.has("tid")) {
                pidOfTid.putIfAbsent(known.get("tid").getAsInt(), null);
                names.putIfAbsent(known.get("tid").getAsInt(), str(known, "name"));
            }
            if (known.has("pid")) {
                pids.add(known.get("pid").getAsInt());
                names.putIfAbsent(known.get("pid").getAsInt(), str(known, "name"));
            }
        }

        String scope = str(answer, "scope");
        String symptom = str(answer, "symptom");
        JsonObject chosen = obj(answer, "target");
        JsonArray suspects = new JsonArray();
        JsonArray rejected = new JsonArray();
        for (JsonElement element : arr(answer, "suspects")) {
            JsonObject suspect = element.getAsJsonObject();
            if (known(suspect, pidOfTid, pids) && suspects.size() < MAX_SUSPECTS) {
                suspects.add(suspect);
            } else {
                rejected.add(suspect);
            }
        }
        JsonObject decision = answer.deepCopy();
        decision.add("suspects", suspects);
        if (rejected.size() > 0) {
            decision.add("rejected_suspects", rejected);
        }
        if (chosen != null && !known(chosen, pidOfTid, pids) && (isSet(chosen, "tid") || isSet(chosen, "pid"))) {
            decision.add("rejected_target", chosen);
            chosen = null;
        }

        if ("trace".equals(scope)) {
            decision.addProperty("used", "whole trace");
            return new Decision(null, true, symptom, decision);
        }
        JsonObject pick = chosen != null && (isSet(chosen, "tid") || isSet(chosen, "pid")) ? chosen
                : suspects.size() > 0 ? suspects.get(0).getAsJsonObject() : null;
        if (pick == null) {
            throw new IllegalStateException("the thread finder named no usable target: " + str(answer, "reasoning"));
        }
        decision.addProperty("target_clear", pick == chosen);
        decision.addProperty("used", pick == chosen ? "target"
                : "most likely suspect (no search for this symptom yet, or the search did not run)");

        JsonObject target = new JsonObject();
        if ("process".equals(scope)) {
            int pid = isSet(pick, "pid") ? pick.get("pid").getAsInt()
                    : pidOfTid.getOrDefault(pick.get("tid").getAsInt(), pick.get("tid").getAsInt());
            target.addProperty("pid", pid);
            if (names.containsKey(pid)) {
                target.addProperty("name", names.get(pid));
            }
        } else if (isSet(pick, "tid")) {
            int tid = pick.get("tid").getAsInt();
            target.addProperty("tid", tid);
            if (names.containsKey(tid)) {
                target.addProperty("name", names.get(tid));
            }
        } else {
            // A thread question that names only a process: its main thread.
            int pid = pick.get("pid").getAsInt();
            target.addProperty("tid", pid);
            if (names.containsKey(pid)) {
                target.addProperty("name", names.get(pid));
            }
        }
        decision.addProperty("picked", (target.has("tid") ? "TID " + target.get("tid").getAsInt()
                : "PID " + target.get("pid").getAsInt()) + (target.has("name") ? " (" + str(target, "name") + ")" : ""));
        target.addProperty("matched", "thread finder: " + str(pick, "reason"));
        target.addProperty("source", "thread_finder");
        if (bool(answer, "follow_up")) {
            target.addProperty("inherited_from_previous_question", true);
        }
        return new Decision(target, false, symptom, decision);
    }

    private static boolean isSet(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull();
    }

    /** Every TID and PID the entry names is one the skill was shown. */
    private static boolean known(JsonObject entry, Map<Integer, Integer> pidOfTid, Set<Integer> pids) {
        boolean tid = isSet(entry, "tid");
        boolean pid = isSet(entry, "pid");
        if (!tid && !pid) {
            return false;
        }
        return (!tid || pidOfTid.containsKey(entry.get("tid").getAsInt()))
                && (!pid || pids.contains(entry.get("pid").getAsInt()));
    }

    /** A target without the pipeline's bookkeeping fields, as the skill should see it. */
    private static JsonObject withoutBookkeeping(JsonObject target) {
        JsonObject copy = new JsonObject();
        for (String key : new String[] {"tid", "pid", "name"}) {
            if (target.has(key)) {
                copy.add(key, target.get(key));
            }
        }
        return copy;
    }
}
