package org.eclipse.tracecompass.helloworld.ui.views;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.osgi.framework.Bundle;
import org.osgi.framework.FrameworkUtil;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * An AI skill: one decision the framework delegates to a model, defined
 * entirely by files in the plug-in's {@code skills/<name>/} directory:
 * <ul>
 * <li>{@code SKILL.md}: a front matter block (name, model, temperature,
 * schema file) and, below it, the instructions given to the model;</li>
 * <li>{@code schema.json}: the JSON schema its answer must follow.</li>
 * </ul>
 * A skill gets a JSON input and returns a JSON object that follows its
 * schema. Answers are cached per skill and input, so the same input always
 * gives the same decision within a session.
 */
final class AiSkill {

    private static final String RESPONSES_URL = "https://api.openai.com/v1/responses";
    private static final Duration TIMEOUT = Duration.ofMinutes(2);

    /** HTTP/1.1 like the answer client: a pooled HTTP/2 connection to the API can go stale. */
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    private static final Map<String, AiSkill> SKILLS = new HashMap<>();

    /** Decisions by skill and input hash; bounded, oldest dropped first. */
    private static final Map<String, JsonObject> CACHE = Collections.synchronizedMap(
            new LinkedHashMap<String, JsonObject>(64, 0.75f, true) {
                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, JsonObject> eldest) {
                    return size() > 500;
                }
            });

    /** False while a repeatability test runs: every call goes to the model (and is not cached). */
    private static volatile boolean cacheEnabled = true;

    /** Turns the decision cache on or off (the test endpoint's {@code skill_cache} flag). */
    static void useCache(boolean enabled) {
        cacheEnabled = enabled;
    }

    /** Models that rejected a temperature setting (reasoning models do): sent without it from then on. */
    private static final java.util.Set<String> NO_TEMPERATURE = Collections.synchronizedSet(new java.util.HashSet<>());
    /** Models that rejected a reasoning-effort setting: sent without it from then on. */
    private static final java.util.Set<String> NO_REASONING = Collections.synchronizedSet(new java.util.HashSet<>());

    final String name;
    final String model;
    final Double temperature;
    /** "low", "medium" or "high" for a reasoning model, or null for the model's default. */
    final String reasoningEffort;
    private final String instructions;
    private final JsonObject schema;
    /** The files it was parsed from, to notice an edit. */
    private final String source;

    private AiSkill(String name, String model, Double temperature, String reasoningEffort, String instructions,
            JsonObject schema, String source) {
        this.name = name;
        this.model = model;
        this.temperature = temperature;
        this.reasoningEffort = reasoningEffort;
        this.instructions = instructions;
        this.schema = schema;
        this.source = source;
    }

    /**
     * The skill in {@code skills/<name>/}. Its files are re-read on every call
     * (they are small), so an edited skill applies to the next question
     * without restarting Trace Compass.
     */
    static synchronized AiSkill load(String name) throws IOException {
        String skillFile = read("skills/" + name + "/SKILL.md");
        String schemaFile = read("skills/" + name + "/" + frontMatter(skillFile).getOrDefault("schema", "schema.json"));
        AiSkill skill = SKILLS.get(name);
        if (skill == null || !skill.source.equals(skillFile + "\n" + schemaFile)) {
            skill = parse(name, skillFile, schemaFile);
            SKILLS.put(name, skill);
        }
        return skill;
    }

    /** The skill's decision for this input (cached). Throws when the model is unreachable or its answer is not valid JSON. */
    JsonObject run(JsonObject input) throws IOException, InterruptedException {
        String inputText = input.toString();
        // The instructions and schema are part of the key: an edited skill never reuses old decisions.
        String key = name + ":" + sha256(model + "\n" + instructions + "\n" + schema + "\n" + inputText);
        JsonObject cached = cacheEnabled ? CACHE.get(key) : null;
        if (cached != null) {
            JsonObject copy = cached.deepCopy();
            copy.addProperty("_cached", true);
            return copy;
        }
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("OPENAI_API_KEY is not configured.");
        }
        JsonObject format = new JsonObject();
        format.addProperty("type", "json_schema");
        format.addProperty("name", name);
        format.add("schema", schema);
        format.addProperty("strict", true);
        JsonObject text = new JsonObject();
        text.add("format", format);
        JsonObject request = new JsonObject();
        request.addProperty("model", model);
        request.addProperty("store", false);
        request.addProperty("instructions", instructions);
        request.addProperty("input", inputText);
        request.add("text", text);
        boolean withTemperature = temperature != null && !NO_TEMPERATURE.contains(model);
        if (withTemperature) {
            request.addProperty("temperature", temperature);
        }

        boolean withReasoning = reasoningEffort != null && !NO_REASONING.contains(model);
        if (withReasoning) {
            JsonObject reasoning = new JsonObject();
            reasoning.addProperty("effort", reasoningEffort);
            request.add("reasoning", reasoning);
        }

        HttpResponse<String> response = send(apiKey, request);
        // A setting the model does not accept: drop it, remember that, and ask again (at most twice).
        for (int retry = 0; retry < 2 && response.statusCode() == 400; retry++) {
            if (request.has("temperature") && response.body().contains("temperature")) {
                NO_TEMPERATURE.add(model);
                request.remove("temperature");
            } else if (request.has("reasoning") && response.body().contains("reasoning")) {
                NO_REASONING.add(model);
                request.remove("reasoning");
            } else {
                break;
            }
            response = send(apiKey, request);
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Skill " + name + ": the model API returned HTTP " + response.statusCode() + ": "
                    + response.body());
        }
        JsonObject body = JsonParser.parseString(response.body()).getAsJsonObject();
        String answer = outputText(body);
        if (answer == null) {
            throw new IOException("Skill " + name + ": the model returned no text.");
        }
        JsonElement parsed;
        try {
            parsed = JsonParser.parseString(answer);
        } catch (RuntimeException exception) {
            throw new IOException("Skill " + name + ": the answer is not JSON: " + answer, exception);
        }
        if (!parsed.isJsonObject()) {
            throw new IOException("Skill " + name + ": the answer is not a JSON object: " + answer);
        }
        JsonObject result = parsed.getAsJsonObject();
        if (cacheEnabled) {
            CACHE.put(key, result.deepCopy());
        }
        return result;
    }

    private static HttpResponse<String> send(String apiKey, JsonObject request) throws IOException, InterruptedException {
        HttpRequest http = HttpRequest.newBuilder()
                .uri(URI.create(RESPONSES_URL))
                .timeout(TIMEOUT)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .build();
        try {
            return CLIENT.send(http, HttpResponse.BodyHandlers.ofString());
        } catch (IOException firstFailure) {
            // One retry on a connection-level failure (TLS alert, reset, stale connection).
            return CLIENT.send(http, HttpResponse.BodyHandlers.ofString());
        }
    }

    /** The concatenated output_text parts of a Responses API answer, or null. */
    private static String outputText(JsonObject body) {
        StringBuilder text = new StringBuilder();
        for (JsonElement item : AnswerPipeline.UnifiedExplainer.arr(body, "output")) {
            if (!item.isJsonObject()) {
                continue;
            }
            for (JsonElement part : AnswerPipeline.UnifiedExplainer.arr(item.getAsJsonObject(), "content")) {
                JsonObject content = part.isJsonObject() ? part.getAsJsonObject() : null;
                if (content != null && "output_text".equals(AnswerPipeline.UnifiedExplainer.str(content, "type"))
                        && content.has("text")) {
                    text.append(content.get("text").getAsString());
                }
            }
        }
        return text.length() == 0 ? null : text.toString();
    }

    /** The front matter of a SKILL.md: the "key: value" lines between the opening and closing "---". */
    static Map<String, String> frontMatter(String skillFile) {
        Map<String, String> front = new HashMap<>();
        String[] lines = skillFile.split("\\r?\\n", -1);
        if (lines.length > 0 && lines[0].trim().equals("---")) {
            for (int i = 1; i < lines.length && !lines[i].trim().equals("---"); i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0) {
                    front.put(lines[i].substring(0, colon).trim(), lines[i].substring(colon + 1).trim());
                }
            }
        }
        return front;
    }

    /** A skill from its SKILL.md (front matter + instructions) and its schema file's text. */
    private static AiSkill parse(String name, String skillFile, String schemaFile) {
        String[] lines = skillFile.split("\\r?\\n", -1);
        int body = 0;
        if (lines.length > 0 && lines[0].trim().equals("---")) {
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].trim().equals("---")) {
                    body = i + 1;
                    break;
                }
            }
        }
        Map<String, String> front = frontMatter(skillFile);
        String instructions = String.join("\n", java.util.Arrays.copyOfRange(lines, body, lines.length)).trim();
        // TRACEASSIST_MODEL, when set, overrides every skill's model (and so the cache key).
        String fromEnv = System.getenv("TRACEASSIST_MODEL");
        String model = fromEnv != null && !fromEnv.isBlank() ? fromEnv.trim()
                : front.getOrDefault("model", AnswerWriter.DEFAULT_MODEL);
        String temperatureText = front.get("temperature");
        Double temperature = temperatureText == null || temperatureText.isEmpty() ? null : Double.valueOf(temperatureText);
        JsonObject schema = JsonParser.parseString(schemaFile).getAsJsonObject();
        String effort = front.get("reasoning_effort");
        return new AiSkill(name, model, temperature, effort == null || effort.isBlank() ? null : effort.trim(),
                instructions, schema, skillFile + "\n" + schemaFile);
    }

    /** Where the skill files are read from instead of the bundle, if set (the Trace Server bundle sets it to the plug-in's project folder). */
    static final String HOME_PROPERTY = "traceassist.home";

    /** A file from the plug-in (its project folder when launched from the workspace, or {@value #HOME_PROPERTY}). */
    static String read(String path) throws IOException {
        String home = System.getProperty(HOME_PROPERTY);
        if (home != null && !home.isBlank()) {
            java.nio.file.Path file = java.nio.file.Path.of(home.trim(), path);
            if (java.nio.file.Files.isRegularFile(file)) {
                return java.nio.file.Files.readString(file, StandardCharsets.UTF_8);
            }
        }
        Bundle bundle = FrameworkUtil.getBundle(AiSkill.class);
        URL url = bundle == null ? AiSkill.class.getClassLoader().getResource(path) : bundle.getEntry(path);
        if (url == null) {
            throw new IOException("Skill file not found in the plug-in: " + path);
        }
        try (InputStream stream = url.openStream()) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String sha256(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            return Integer.toHexString(text.hashCode());
        }
    }
}
