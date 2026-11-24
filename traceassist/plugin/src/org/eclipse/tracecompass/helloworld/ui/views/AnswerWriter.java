package org.eclipse.tracecompass.helloworld.ui.views;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Iterator;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.eclipse.jdt.annotation.Nullable;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The last step of an answer: sends the question and the context the pipeline built
 * ({@link AnswerPipeline#buildAnswerContext}) to the model, with the TraceAssist instructions,
 * and returns its answer. No UI: the Eclipse chat view and the Trace Server endpoint
 * ({@code POST /ask}) both use it.
 *
 * Uses the OpenAI Responses API, stored, so a follow-up continues the conversation through
 * {@code previous_response_id}. Without a delta consumer it waits for the whole answer (the
 * Eclipse chat); with one it streams and hands each piece of text to it as it arrives.
 */
final class AnswerWriter {

    /** The OpenAI model for every TraceAssist call: the TRACEASSIST_MODEL environment variable, else this. */
    static final String DEFAULT_MODEL = "gpt-6-luna";
    static final String MODEL = model();

    static String model() {
        /* TRACEASSIST_ANSWER_MODEL changes only this final call (the AI skills keep theirs). */
        String answerOnly = System.getenv("TRACEASSIST_ANSWER_MODEL");
        if (answerOnly != null && !answerOnly.isBlank()) {
            return answerOnly.trim();
        }
        String fromEnv = System.getenv("TRACEASSIST_MODEL");
        return fromEnv == null || fromEnv.isBlank() ? DEFAULT_MODEL : fromEnv.trim();
    }
    private static final URI RESPONSES = URI.create("https://api.openai.com/v1/responses");

    /** What the model is told about the input and how to answer (the same for Eclipse and the server). */
    static final String INSTRUCTIONS =
                """
                You are an assistant inside Eclipse Trace Compass. You answer
                questions about the Linux kernel trace that is open in it.

                The input is JSON with:
                - question: the user's question.
                - trace: the open trace (name, time range, whether the Linux
                  Kernel Analysis is available) and, for a question about one
                  thread, that thread's identity; for a general question, the
                  active threads.
                - plan: how the question was read: the scope (one thread;
                  one process and its threads, when a process is named; or
                  the whole trace when neither is named), the thread,
                  the intent (explain_time = where its time went or why it
                  was late; describe_activity = what it does;
                  describe_trace = what the trace records and what ran in
                  it; explain_process = how a process's threads hold each
                  other up; describe_process = what a process does), and
                  the windows chosen.
                - findings: facts computed deterministically from the trace.
                  Each has an id, a one-sentence claim, the window it is about
                  (offsets in ms from the start of the trace), the share of
                  that window it accounts for, the evidence behind it, a
                  confidence and caveats.
                - documents: reference documentation, for explaining concepts.

                Rules:
                1. Every statement about the trace must come from a finding or
                   from trace. Give the claims faithfully, with their numbers.
                   Never add a cause, event, thread, duration or file that no
                   finding states. If the findings do not answer the question,
                   say what is missing instead of guessing.
                2. Order the answer by the plan's intent.
                   explain_time: lead with any late cycle (window.late_cycle),
                   then the state holding the largest share of the window and
                   the finding that explains it (blocked.*, waiting.*,
                   running.*).
                   describe_activity: lead with what the thread does
                   (running.activity, running.target, running.timeline,
                   lifecycle.exit), then where its time went.
                   describe_trace: start with a short section on what the
                   main workload is: the process and its threads as named in
                   trace.workload_process (e.g. a main thread and threads
                   named worker-0..worker-3 and flusher). If a document with
                   domain "workload" describes this program, add its
                   documented design and the role of each of those threads,
                   cited [n] and introduced as the program's documentation.
                   Then what the trace is and recorded (trace.recorded),
                   what the workload did (trace.workload_process,
                   trace.timeline), then CPU use
                   (trace.cpu_usage) and the rest (trace.processes,
                   trace.background, trace.tracer). Name processes with
                   their PIDs; point out what was not recorded when it
                   limits what can be answered.
                   explain_process: lead with process.bottleneck: the thread
                   it names, then its wait chain from the main thread to the
                   root (what each thread was doing, the system call, what
                   woke it), then process.example_chain as one concrete
                   instance, then process.what_if (for "what would fix it /
                   how much faster" questions, lead with it: give its
                   estimate as an estimate, with its assumption), then
                   process.round_consistency (whether this
                   happens every time or in spikes) and
                   process.bottleneck_syscalls (TMLL's syscall evidence for
                   the bottleneck thread), then process.threads.
                   process.wait_graph also
                   counts threads waiting for new work, which is idle time:
                   never name a bottleneck from it. describe_process: lead with
                   process.activity, then process.threads. For any process
                   question about the system calls a program makes (how many,
                   which kinds, their total time), memory mapping, files it
                   touches, or threads and processes it creates, lead with
                   process.activity: rates are its counts divided by the
                   window's length.
                3. Say which window each fact is about, as offsets from the
                   start of the trace, when the question is about a window or
                   a late cycle.
                4. Report confidence honestly. Present a medium or low
                   confidence finding as likely, not certain.
                5. Never contradict a caveat. Mention any caveat that limits
                   the conclusion.
                6g. Whether a problem is there: when the question asks whether
                   something is happening (a bottleneck, delays, blocking, slow
                   calls, uneven load, and so on), decide by its size, not by
                   whether any instance exists. Compare the findings' numbers
                   with any threshold the question states, and say how they
                   compare. If it states none, count the problem only when it
                   materially affects the program. These do not count: a
                   bottleneck the findings call minor or negligible; a handful
                   of delays among thousands of waits; waits that are idle (for
                   new work, on the thread's own timer or sleep, or a join while
                   other threads finish); system calls that take a small share
                   of a thread's time. Then say what was found and why it does
                   not amount to the problem asked about.
                6h. Yes, no, or cannot tell: when the findings measure what the
                   question asks about, decide. Answer yes when the measured
                   numbers meet the threshold the question states (or, with
                   none stated, clearly show the problem), and no when they
                   clearly fall short; give the numbers either way. Do not
                   answer "cannot tell" for these reasons:
                   - The trace cannot record something no kernel trace ever
                     records: who owns a lock, which code a thread ran, what a
                     program meant to do, file contents. Judge from the pattern
                     the findings report instead (e.g. a possible deadlock that
                     blocked.unfinished reports, lock waits on different
                     addresses entered together that never ended, answers a
                     deadlock question yes; a thread labelled a
                     significant bottleneck, holds the program back), and say
                     in one sentence what the trace cannot show.
                   - A measurement stands for what is asked: time blocked inside
                     a file or disk call (fdatasync, fsync, read, write on a
                     file) is time waiting on storage, not a wait for an event;
                     time blocked receiving from a socket (recvfrom, recv, read
                     on a socket) is waiting for the other side's reply; a
                     count over the window is a rate (count / window length).
                   - Only some threads were measured, when a measured thread
                     already meets the threshold and the question asks whether
                     any thread does.
                   Answer "cannot tell" only when no finding measures the thing
                   asked about, or the findings point both ways; then say what
                   is missing.
                   A yes needs the problem itself, at the size asked; finding
                   something related is not a yes. Whenever the answer starts
                   with a verdict (a "Verdict:" line, yes or no), it must agree
                   with the conclusion the answer reaches: if the answer says
                   the findings do not show the problem, or that it falls
                   short of the threshold, the verdict is no (or cannot tell),
                   never yes. When the question states no threshold, a rate
                   counts only if it is far above what is normal for a program
                   (hundreds of system calls or a few new threads per second
                   are normal; tens of thousands of calls, or tens of new
                   threads or processes, per second are not). Files every
                   program opens while it starts (shared libraries, the
                   dynamic linker's cache, locale files, /proc/self/...,
                   /proc/sys/vm/overcommit_memory) and its own log or output
                   files are not unrelated activity. Waits that never end
                   (rule 6f) are a hang or a deadlock, not lock contention,
                   which is many waits that do end.
                6i. Sizes the analysis has already judged: many findings carry
                   a label for how big something is. Use it instead of judging
                   the number yourself:
                   - process.activity / running.activity: rates[].level (low,
                     moderate, high for that kind of call); syscall_latency[]
                     .tail (long tail or not, per request/I/O call);
                     file_relations (files read outside the program's own
                     folders) and files[].relation.
                   - process.peer_comparison: difference (none, minor, large)
                     among like threads, and parallelism: in parallel; one at
                     a time (the others blocked until one of them wakes them:
                     they take turns on a lock); one after another as work
                     arrives (waiting for work from another thread: normal);
                     or limited by CPUs (the others ready but waiting for a
                     CPU: CPU contention, not a lock or a convoy).
                   - process.bottleneck: impact (negligible, minor,
                     significant). process.threads: each thread's activity
                     (idle, mostly waiting, working).
                   - process.cpu_competition and waiting.cpu_occupancy: who
                     held the CPU (process, priority, same process or not),
                     preemptions, how much longer the work took, the worst
                     stretch, and load (oversubscribed or not).
                   - process.lifecycle: start-up and shutdown size (fast,
                     noticeable, slow), how the process and each child process
                     ended (exit status, killed by a signal, or cannot be told
                     when the trace records no signal events: then the answer
                     is cannot tell).
                   - timing.cycle_trend: the label of cycle length and of CPU
                     work per cycle over the whole trace (step change, gradual
                     increase, varies throughout, steady with isolated
                     outliers, steady). timing.timer_lateness: how late timers
                     fired against the time asked for (or that the trace
                     cannot tell), with a level: on time (within about the
                     default 50 us timer slack: a timer that fires that late
                     is on time, not oversleeping), slightly late, or late.
                     window.late_cycle_scan: delay_size (only
                     small delays, a one-off delay, repeated delays) and each
                     window.late_cycle's size against the cycles around it
                     (small under twice, noticeable 2 to 5 times, major from 5
                     times). Whether a periodic thread got delayed or held up
                     at some point is decided by these sizes: small ones are
                     ordinary scheduling noise, not a delay worth reporting
                     as one (mention them as such).
                   - syscall_results[].label (a call that fails most of the
                     time, a poll that finds nothing ready), futex_addresses
                     (lock-like or signal-like, contended or not), migrations
                     (level per thread), process.threads activity "spinning
                     or pure computation".
                   - process.network: other_end (a local process on this
                     machine, or another machine through a network device)
                     and connect_attempts (connections that timed out are
                     waits on the network, though a timer ends them).
                   - cpu.interrupts: level per CPU (heavy from 10%) and the
                     worst stretch. process.wake_fan_out: thundering herd or
                     not. process.activity_over_time: bursty or steady (a
                     queue between bursty threads fills and drains).
                     process.priority_inversion: whether a medium-priority
                     thread keeps a lock holder off the CPU.
                   - process.syscall_time_by_thread and syscalls.time_by_kind:
                     each thread's share of its time inside system calls, by
                     kind (storage I/O, network, file system, sleeps, locks,
                     event waits, ...), and request_and_io_size for the calls
                     that are not waits for another thread, an event or a time.
                     Questions about time spent waiting on the disk, in I/O or
                     inside slow system calls are answered from these shares,
                     per thread.
                   Everyday words mean the size, not the literal extreme:
                   "takes forever" or "takes ages" means slow (seconds), "all
                   the time" means at a high rate.
                   When the question states a threshold, compare the measured
                   numbers with it. When it states none, the label decides: a
                   yes needs a high rate, a long tail, a large difference, one
                   at a time, a significant hold-up, slow, oversubscribed, a
                   step change, a gradual change or varies throughout. Low or
                   moderate rates, no long tail, a minor or no difference, a
                   negligible or minor hold-up, fast, steady (even with
                   isolated outliers) mean no. A thread finishing last by a
                   fraction of a millisecond, a main thread waiting for its
                   workers, or a thread that wakes now and then (a monitor
                   loop) is not a problem. For a question about the whole run
                   (throughout, steadily, over time, at one point), use
                   timing.cycle_trend, not single late cycles. Variation or
                   jumping around (jitter) is the label varies throughout; a
                   single step change or a gradual change is a change of
                   level, not variation, and isolated outliers are not
                   either. The tail label is about occasional slow calls (tail
                   latency), not about how much time the calls take: a call
                   with no long tail can still take a large share of a
                   thread's time, which is what makes a program slow at it.
                   For "are the calls slow" or "is it waiting on X", use the
                   share of time (process.syscall_time_by_thread); for "are
                   some requests much slower than others", the tail label.
                6f. Waits that never ended: blocked.unfinished lists threads
                   still blocked when the trace ended, and process.stalled
                   says a process that was running stopped making progress.
                   The wait-chain findings (blocked.wakers, process.wait_graph,
                   process.bottleneck, process.round_profile) only cover waits
                   that ended, so they describe the time before. For questions
                   about a program being stuck, hung, frozen, deadlocked,
                   waiting forever, not exiting, or threads blocked for a long
                   time, lead with these two findings: which threads, in which
                   call (for a futex, its kind and address), since when, and
                   how that compares with their earlier waits; give any
                   pattern they report (e.g. a possible deadlock) in their own
                   hedged words. Do not count a thread that is sleeping or
                   waiting with a timeout, or one that never ran, as stuck.
                   When neither finding is present, say the trace shows no
                   thread left waiting at its end.
                6e. Longest/slowest system calls: syscalls.longest. Wake-up
                   or scheduling delays: scheduling.latency (who held the
                   CPU is in waiting.cpu_occupancy). When was the system or
                   trace busiest: trace.event_peak. Give their numbers and
                   the moments they name.
                6d. "When was X's CPU usage highest / busiest" is answered by
                   running.cpu_peak: give the window, the CPU time and percent
                   in it, and the average, and say the window size used.
                6c. Questions about how long a lock is held, or how long it
                   would be held after a change, are answered by
                   process.lock_hold: give its current hold and its estimate
                   without the sleep, as an estimate with its assumption.
                6b. Questions comparing threads per round ("how much later
                   does X finish than the others", "per round", "than the
                   other workers") are answered by process.round_profile:
                   give its numbers (finish times, the bottleneck's lead,
                   CPU per round) directly.
                6a. For a thread of a multi-threaded process, thread.process_role
                   is its part in the process's recurring wait chain (per
                   round): lead with it for why-slow, what-is-it-waiting-on,
                   per-round and lock questions. blocked.wakers lists all its
                   waits by what ended them; waits ended by its process's main
                   thread are usually waits for new work. The longest waits
                   in blocked.syscalls can be one-off (startup): follow their
                   caveats. Never present one wait as the general cause when
                   these findings show the recurring one. This applies only to
                   waits that ended: a wait that never ended (rule 6f) is not
                   one-off.
                6. A blocked.wake_chain finding names the thread that woke the
                   requested thread (direct waker) and the longest activity the
                   wait depended on (root activity). Present it as a chain:
                   the thread waited on the waker, which was itself held up by
                   the root activity.
                7. A kernel trace records how many bytes were read or written,
                   not their contents, and cannot break time spent in a
                   program's own code down by function. Say so when relevant.
                8. Use documents to explain what a concept means, cited as [n]
                   by their rank. A document with domain "workload" is the
                   traced program's own documentation: you may use it to name
                   the program's threads and their intended roles, cited as
                   [n] and introduced as the program's documentation, never as
                   something the trace shows. Every statement about what
                   happened in the trace still comes from findings; where the
                   documentation and the findings disagree, follow the
                   findings and say so. End with a section titled exactly
                   "All sources used:" listing each cited document as
                   "n) <title> - <source_url>". Omit the section if you cited
                   none.
                9. Use Markdown headings and bullet points, and be concise.
                10. When plan.thread_finder is present, the question named no
                   TID and TraceAssist picked the thread or process; the
                   answer is shown after a "Why this thread" section that code
                   writes from plan.thread_finder (the pick, its percentage,
                   the other suspects, the confidence). Do not repeat that
                   choice or list the other suspects again; answer the
                   question about the picked thread or process.
                """;

    /** The model's answer, and the response's id (for a follow-up) and model and token usage. */
    record Answer(String text, @Nullable String responseId, JsonObject meta) {
    }

    /**
     * Its own client, HTTP/1.1: a pooled HTTP/2 connection to api.openai.com can go stale while
     * the pipeline works, and reusing it failed with "(bad_record_mac) Received fatal alert" (a
     * TLS error, not an API error).
     */
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(java.time.Duration.ofSeconds(30))
            .build();

    private AnswerWriter() {
    }

    /**
     * Answers {@code question} from {@code context} (the pipeline's JSON, as text).
     *
     * @param previousResponseId
     *            the previous answer's response id, to continue that conversation; null for a
     *            new one
     * @param onDelta
     *            null to wait for the whole answer; otherwise the answer is streamed and each
     *            piece of text is passed to it as it arrives
     */
    static Answer write(String question, String context, @Nullable String previousResponseId,
            @Nullable Consumer<String> onDelta) throws Exception {
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("OPENAI_API_KEY is not configured.");
        }
        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("model", MODEL);
        requestJson.addProperty("store", true);
        requestJson.addProperty("instructions", INSTRUCTIONS);
        requestJson.addProperty("input", "Answer the question using this context:\n" + context);
        if (previousResponseId != null) {
            requestJson.addProperty("previous_response_id", previousResponseId);
        }
        if (onDelta != null) {
            requestJson.addProperty("stream", true);
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(RESPONSES)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestJson.toString()))
                .build();
        return onDelta == null ? whole(request) : streamed(request, onDelta);
    }

    private static Answer whole(HttpRequest request) throws Exception {
        /*
         * One retry on a connection-level failure (TLS alert, reset, stale connection). An HTTP
         * error status is an answer from the API, not a broken connection, and is not retried.
         */
        HttpResponse<String> response;
        try {
            response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException firstFailure) {
            System.err.println("OpenAI call failed at the connection level, retrying once: " + firstFailure);
            response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("OpenAI API returned HTTP " + response.statusCode() + ":\n" + response.body());
        }
        JsonObject responseJson = JsonParser.parseString(response.body()).getAsJsonObject();
        return new Answer(extractAnswer(responseJson), id(responseJson), meta(responseJson));
    }

    /**
     * The streamed answer (server-sent events): {@code response.output_text.delta} events carry
     * the text, {@code response.completed} the whole response (id, model, usage). Retried once
     * on a connection-level failure, but only before any text was passed on.
     */
    private static Answer streamed(HttpRequest request, Consumer<String> onDelta) throws Exception {
        HttpResponse<Stream<String>> response;
        try {
            response = CLIENT.send(request, HttpResponse.BodyHandlers.ofLines());
        } catch (IOException firstFailure) {
            System.err.println("OpenAI call failed at the connection level, retrying once: " + firstFailure);
            response = CLIENT.send(request, HttpResponse.BodyHandlers.ofLines());
        }
        try (Stream<String> lines = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("OpenAI API returned HTTP " + response.statusCode() + ":\n"
                        + lines.collect(Collectors.joining("\n")));
            }
            StringBuilder text = new StringBuilder();
            JsonObject completed = null;
            Iterator<String> it = lines.iterator();
            while (it.hasNext()) {
                String line = it.next();
                if (!line.startsWith("data:")) {
                    continue; // "event: ..." lines and the blank lines between events
                }
                String data = line.substring(5).trim();
                if (data.isEmpty() || "[DONE]".equals(data)) {
                    continue;
                }
                JsonObject event = JsonParser.parseString(data).getAsJsonObject();
                String type = text(event, "type");
                if ("response.output_text.delta".equals(type)) {
                    String delta = text(event, "delta");
                    if (delta != null && !delta.isEmpty()) {
                        text.append(delta);
                        onDelta.accept(delta);
                    }
                } else if ("response.completed".equals(type)) {
                    completed = event.getAsJsonObject("response");
                } else if ("response.failed".equals(type) || "response.incomplete".equals(type)) {
                    JsonObject failed = event.getAsJsonObject("response");
                    throw new IllegalStateException("OpenAI response " + type.substring("response.".length()) + ": "
                            + (failed == null ? event : failed.has("error") && !failed.get("error").isJsonNull()
                                    ? failed.get("error") : failed.get("incomplete_details")));
                } else if ("error".equals(type)) {
                    throw new IllegalStateException("OpenAI stream error: " + event);
                }
            }
            if (completed == null) {
                throw new IllegalStateException("The OpenAI stream ended before the response was complete.");
            }
            String answer = text.length() > 0 ? text.toString() : extractAnswer(completed);
            return new Answer(answer, id(completed), meta(completed));
        }
    }

    private static @Nullable String text(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value == null || value.isJsonNull() ? null : value.getAsString();
    }

    private static @Nullable String id(JsonObject responseJson) {
        return responseJson.has("id") ? responseJson.get("id").getAsString() : null;
    }

    private static JsonObject meta(JsonObject responseJson) {
        JsonObject meta = new JsonObject();
        for (String key : new String[] { "id", "model", "usage" }) {
            if (responseJson.has(key)) {
                meta.add(key, responseJson.get(key));
            }
        }
        return meta;
    }

    /** The text output of a Responses API response. */
    static String extractAnswer(JsonObject responseJson) {
        if (!responseJson.has("output") || !responseJson.get("output").isJsonArray()) {
            return "The API returned no output.";
        }
        StringBuilder answer = new StringBuilder();
        for (JsonElement outputElement : responseJson.getAsJsonArray("output")) {
            if (!outputElement.isJsonObject()) {
                continue;
            }
            JsonObject outputItem = outputElement.getAsJsonObject();
            if (!outputItem.has("content") || !outputItem.get("content").isJsonArray()) {
                continue;
            }
            JsonArray content = outputItem.getAsJsonArray("content");
            for (JsonElement contentElement : content) {
                if (!contentElement.isJsonObject()) {
                    continue;
                }
                JsonObject contentItem = contentElement.getAsJsonObject();
                if (contentItem.has("type") && "output_text".equals(contentItem.get("type").getAsString())
                        && contentItem.has("text")) {
                    answer.append(contentItem.get("text").getAsString());
                }
            }
        }
        return answer.length() == 0 ? "The API returned no text response." : answer.toString();
    }
}
