package org.eclipse.tracecompass.helloworld.ui.views;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

/**
 * Shortens the findings for the model (the answer writer and the view picker), without changing
 * the findings themselves. A program with thousands of short-lived threads gave findings with a
 * row per thread, listed again in the claim sentence: about 440,000 tokens, more than the model's
 * context window. Long lists keep the rows that matter and summarize the rest:
 * <ul>
 * <li>a list of more than {@link #MAX_ROWS} objects keeps the first few rows (the main thread
 * comes first), the top rows by each time field ({@code *_ms}) and count field, and every row
 * whose {@code tid} the finding names elsewhere ({@code bottleneck_tid}, {@code tid}, ...), in their
 * original order; the others become one {@code <list>_not_listed} entry with their number and
 * their summed time fields;</li>
 * <li>a list of more than {@link #MAX_ROWS} plain values keeps its first {@link #MAX_ROWS};</li>
 * <li>a claim longer than {@link #MAX_CLAIM_CHARS} is cut after its last complete part.</li>
 * </ul>
 * Findings of an ordinary program are unchanged: no list there is that long.
 */
final class FindingsCompactor {

    /** Most rows a list keeps. */
    static final int MAX_ROWS = 40;
    /** Rows kept from the start of a list, whatever their values. */
    private static final int FIRST_ROWS = 5;
    /** Rows kept per time or count field, by largest value. */
    private static final int TOP_PER_FIELD = 8;
    /** Longest claim kept whole. */
    static final int MAX_CLAIM_CHARS = 3000;

    private FindingsCompactor() {
    }

    /** A shortened copy of the findings; the argument is not changed. */
    static JsonArray forModel(JsonArray findings) {
        return forModel(findings, Set.of());
    }

    /**
     * A shortened copy of the findings, always keeping the rows of {@code keepTids} (the
     * question's target thread); the argument is not changed.
     */
    static JsonArray forModel(JsonArray findings, Set<Long> keepTids) {
        JsonArray out = new JsonArray();
        for (JsonElement element : findings) {
            JsonElement copy = element.deepCopy();
            if (copy.isJsonObject()) {
                JsonObject finding = copy.getAsJsonObject();
                if (finding.has("claim") && finding.get("claim").isJsonPrimitive()) {
                    finding.addProperty("claim", shortClaim(finding.get("claim").getAsString()));
                }
                compact(finding, keepTids);
            }
            out.add(copy);
        }
        return out;
    }

    static String shortClaim(String claim) {
        if (claim.length() <= MAX_CLAIM_CHARS) {
            return claim;
        }
        int cut = claim.lastIndexOf("; ", MAX_CLAIM_CHARS);
        if (cut < MAX_CLAIM_CHARS / 2) {
            cut = MAX_CLAIM_CHARS;
        }
        return claim.substring(0, cut) + "; ... (" + (claim.length() - cut)
                + " more characters not shown; the data lists the threads that matter)";
    }

    /** Shortens every long list inside this object, recursively. */
    private static void compact(JsonObject object, Set<Long> keepTids) {
        Set<Long> named = namedTids(object);
        named.addAll(keepTids);
        for (String key : new ArrayList<>(object.keySet())) {
            JsonElement value = object.get(key);
            if (value.isJsonObject()) {
                compact(value.getAsJsonObject(), keepTids);
            } else if (value.isJsonArray()) {
                JsonArray list = value.getAsJsonArray();
                for (JsonElement item : list) {
                    if (item.isJsonObject()) {
                        compact(item.getAsJsonObject(), keepTids);
                    }
                }
                if (list.size() > MAX_ROWS) {
                    shorten(object, key, list, named);
                }
            }
        }
    }

    private static void shorten(JsonObject parent, String key, JsonArray list, Set<Long> named) {
        boolean rows = true;
        for (JsonElement item : list) {
            rows &= item.isJsonObject();
        }
        JsonObject notListed = new JsonObject();
        if (!rows) {
            JsonArray kept = new JsonArray();
            for (int i = 0; i < MAX_ROWS; i++) {
                kept.add(list.get(i));
            }
            parent.add(key, kept);
            notListed.addProperty("count", list.size() - MAX_ROWS);
            notListed.addProperty("total", list.size());
            parent.add(key + "_not_listed", notListed);
            return;
        }

        Set<Integer> keep = new TreeSet<>();
        for (int i = 0; i < FIRST_ROWS; i++) {
            keep.add(i);
        }
        for (int i = 0; i < list.size(); i++) {
            JsonPrimitive tid = primitive(list.get(i).getAsJsonObject(), "tid");
            if (tid != null && tid.isNumber() && named.contains(tid.getAsLong())) {
                keep.add(i);
            }
        }
        for (String field : rankingFields(list)) {
            List<Integer> order = new ArrayList<>();
            for (int i = 0; i < list.size(); i++) {
                order.add(i);
            }
            order.sort(Comparator.comparingDouble((Integer i) -> -number(list.get(i).getAsJsonObject(), field)));
            for (int i = 0; i < TOP_PER_FIELD && i < order.size(); i++) {
                keep.add(order.get(i));
            }
        }
        List<Integer> chosen = new ArrayList<>(keep);
        if (chosen.size() > MAX_ROWS) {
            chosen = chosen.subList(0, MAX_ROWS);
        }
        Set<Integer> chosenSet = new HashSet<>(chosen);
        JsonArray kept = new JsonArray();
        Map<String, Double> sums = new LinkedHashMap<>();
        Map<String, Integer> folders = new LinkedHashMap<>();
        int omitted = 0;
        for (int i = 0; i < list.size(); i++) {
            JsonObject row = list.get(i).getAsJsonObject();
            if (chosenSet.contains(i)) {
                kept.add(row);
                continue;
            }
            omitted++;
            for (String field : row.keySet()) {
                if (summable(row, field)) {
                    sums.merge(field, number(row, field), Double::sum);
                }
            }
            for (String field : new String[] {"name", "path"}) {
                JsonPrimitive value = primitive(row, field);
                if (value != null && value.isString() && value.getAsString().startsWith("/")) {
                    String path = value.getAsString();
                    folders.merge(path.substring(0, Math.max(1, path.lastIndexOf('/'))), 1, Integer::sum);
                }
            }
        }
        parent.add(key, kept);
        notListed.addProperty("count", omitted);
        notListed.addProperty("total", list.size());
        if (!sums.isEmpty()) {
            JsonObject summed = new JsonObject();
            sums.forEach(summed::addProperty);
            notListed.add("summed", summed);
        }
        if (!folders.isEmpty()) {
            JsonObject byFolder = new JsonObject();
            folders.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(5)
                    .forEach(e -> byFolder.addProperty(e.getKey(), e.getValue()));
            notListed.add("by_folder", byFolder);
        }
        notListed.addProperty("note", "rows left out to keep the evidence short; the rows listed are the first "
                + "ones, the largest by each time and count field, and any thread the finding names");
        parent.add(key + "_not_listed", notListed);
    }

    /** Numeric fields whose sum over rows means something: not ids, percentages or timestamps. */
    private static boolean summable(JsonObject row, String field) {
        JsonPrimitive value = primitive(row, field);
        return value != null && value.isNumber() && !field.equals("tid") && !field.equals("pid")
                && !field.endsWith("_tid") && !field.endsWith("_pid") && !field.endsWith("id")
                && !field.contains("percent") && !field.endsWith("_ns") && !field.contains("timestamp")
                && !field.equals("cpu") && !field.endsWith("_cpu");
    }

    /** The numeric fields rows are ranked by: times ({@code *_ms}) and counts. */
    private static Set<String> rankingFields(JsonArray list) {
        Set<String> fields = new TreeSet<>();
        for (JsonElement item : list) {
            for (Map.Entry<String, JsonElement> entry : item.getAsJsonObject().entrySet()) {
                String field = entry.getKey();
                if ((field.endsWith("_ms") || field.endsWith("count") || field.endsWith("_waits"))
                        && entry.getValue().isJsonPrimitive() && entry.getValue().getAsJsonPrimitive().isNumber()) {
                    fields.add(field);
                }
            }
        }
        return fields;
    }

    /** TIDs the object names directly ({@code tid}, {@code *_tid}), so their rows are always kept. */
    private static Set<Long> namedTids(JsonObject object) {
        Set<Long> tids = new HashSet<>();
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            String field = entry.getKey();
            JsonElement value = entry.getValue();
            if ((field.equals("tid") || field.endsWith("_tid")) && value.isJsonPrimitive()
                    && value.getAsJsonPrimitive().isNumber()) {
                tids.add(value.getAsLong());
            }
        }
        return tids;
    }

    private static JsonPrimitive primitive(JsonObject row, String field) {
        JsonElement value = row.get(field);
        return value != null && value.isJsonPrimitive() ? value.getAsJsonPrimitive() : null;
    }

    private static double number(JsonObject row, String field) {
        JsonPrimitive value = primitive(row, field);
        return value != null && value.isNumber() ? value.getAsDouble() : 0;
    }
}
