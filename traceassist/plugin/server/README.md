# TraceAssist in the Trace Server

The TraceAssist answer pipeline runs headless inside the Trace Compass Trace Server, as an
OSGi bundle (`org.eclipse.tracecompass.traceassist.server`). The pipeline covers target
resolution, the thread finder and search, the explainers, TMLL, RAG and the view picker.
It serves the same endpoint as the Eclipse plug-in's test endpoint, on port **8092**:

```
POST http://127.0.0.1:8092/test/context  {"trace_path": "...", "question": "...", "rag": true,
                                          "previous_target": {...}, "skill_cache": true}
GET  http://127.0.0.1:8092/test/health
```

The request and response are the same as Eclipse's 8090 endpoint.
Like 8090, it stops before the final LLM call: it returns the context, findings, plan,
target, view plan and the "Why this thread" text.

## Asking: `POST /ask`

The whole answer, for a chat client:

```
POST http://127.0.0.1:8092/ask  {"trace_path": "...", "question": "...", "rag": true,
                                 "previous_target": {...}, "previous_response_id": "resp_...",
                                 "stream": true}
```

- It runs the pipeline, then the final model call (`AnswerWriter`). That is the same call,
  instructions and model as the Eclipse chat, which uses `AnswerWriter` too.
- **A follow-up** sends back the previous answer's `target` and `response_id`, as
  `previous_target` and `previous_response_id`. The client keeps the conversation; the server
  keeps none.
- **With `"stream": true`** the response is newline-delimited JSON, one event per line:
  - `{"type": "plan", ...}`: the target, view plan, plan and "Why this thread" text. It
    comes as soon as the pipeline is done, so the views can open while the answer is written.
  - `{"type": "delta", "text": "..."}`: the answer as it is written.
  - `{"type": "done", "answer", "response_id", "model", "usage", "stage_durations_ms"}`.
  - or `{"type": "error", "error": "..."}`.
- **Without `stream`** it returns one JSON object with all of the above.
- Each view in `view_plan.views` carries `tsp_output`, the Trace Server output (data
  provider id) that shows it, from the view cards (`skills/views/*/VIEW.md`). It is `null`
  when the server has no such output (Critical Path, Statistics, Event Density).
- Unlike the Eclipse chat, the server writes no answer log: Eclipse's log is the CASCON
  experiment's `answers.csv`.

Each request gets its own thread, so a health check doesn't wait. Questions run one at a time:
the pipeline switches the active trace.

## The viewer's experiment: `experiment_uuid`

`/ask` and `/test/context` both take `experiment_uuid`, the TSP id of the experiment the client
shows. The VS Code extension always sends it.

- **The pipeline runs on the server's own experiment.** It is found with the server's
  `ExperimentManagerService.getExperimentByUUID`, through reflection, so the plug-in doesn't
  depend on the Trace Server. Its analyses (kernel, execution graph, latencies) are shared
  with the viewer's outputs, so the trace isn't indexed and analyzed a second time.
- **Without it,** with an unknown id, or in Eclipse, the endpoint opens its own copy of
  `trace_path`, as before. The response's `trace_source` says which: `server_experiment` or
  `own_copy`. The regression suite sends no id.
- **The two give the same findings except for the trace's end.** On the experiment, the trace
  ends at its last event, the range the viewer shows. On the private copy, it ends at the
  last packet's end, 1–2 ms later. A "whole trace" window ends there too, so a percentage of
  that window can differ by about 0.1%. On the experiment, the trace name is the session's
  name instead of `kernel`. Checked on 7 cases on 2026-11-05: everything else was identical.

## Critical Path

The Critical Path output is computed only after something names the thread to follow, and
the trace server API has no call for that. So on an experiment, when the plan opens Critical
Path with a `follow_tid`, `ServerCriticalPath.follow` does what Eclipse's chat does:
- it starts a critical-path analysis for that thread, over the plan's selection;
- it drops the experiment's cached Critical Path provider, so the next request binds to the new
  analysis.

Each analysis takes about 0.1–0.3 s and is kept (none are disposed), as in Eclipse. The view then
gets `tsp_output` and `tsp_descriptor`, because the server lists no Critical Path output, or
`tsp_unavailable` with the reason. The extension opens it from the descriptor. It also sends the
viewer `outputDataChanged`, so an open Critical Path fetches the new path.

## One source, two bundles

| | Eclipse plug-in (`org.eclipse.tracecompass.helloworld.ui`) | Server bundle (`org.eclipse.tracecompass.traceassist.server`) |
|---|---|---|
| Sources | everything in `src/` | `src/.../views/*.java` except `HelloWorldView.java` and `HelloWorldRagView.java`, plus `server/src/` |
| Pipeline | `AnswerPipeline` (no UI), used by `HelloWorldView` | the same `AnswerPipeline` |
| Starts the endpoint | `HelloWorldView`, if `-Dagent.test.port` is set (8090) | `ServerActivator`, when the server starts (8092) |
| Skills and view cards | `skills/` in this project | the same files (`traceassist.home` = this project); a copy in the jar is the fallback |

`AnswerPipeline.java` holds the code that used to sit inside `HelloWorldView` and runs
before the LLM call: `buildAnswerContext`, the explainers, `QueryPlan`, `planViews`, the TMLL
and RAG calls and `AgentTestServer`. It must never import SWT or the workbench. The
server build compiles it against the Trace Server's jars only, so a UI import fails the
build.

## The executable jar (for other machines)

`server/build.sh` also builds `server/build/traceassist-server.jar`, an executable jar of about
260 KB. It installs TraceAssist in any Trace Compass Trace Server and starts the server with the
user's own OpenAI API key:

```bash
java -jar traceassist-server.jar start --server <trace-server folder>
```

- **It is a launcher, not the whole program.** The pipeline runs inside the Trace Server (Trace
  Compass's trace reading and analyses), so a Trace Server is needed: the stock Trace Compass
  trace server, with `analysis.graph.core` 5.1.x. The jar holds the launcher (Java 11+), the
  bundle and the critical-path patch.
- **`install`** (which `start` also runs, and which changes nothing when already done):
  - copies the bundle into `plugins/`;
  - patches `analysis.graph.core` with `AbstractCriticalPathModule`. Without the patch, a
    windowed critical path fails with "invalid parameter windowStartNs". It refuses a
    different 5.x version unless `--force`.
  - adds the bundle and `traceassist.port` to `configuration/config.ini`.

  Originals go to `backup-before-traceassist/`. A fresh install reads the skills packaged in
  the bundle; `traceassist.home` isn't set.
- **The API key** is taken from `--api-key-file`, else `OPENAI_API_KEY`, else asked for with
  hidden input (`--ask-key` always asks). It is checked with OpenAI first (`--skip-key-check`
  turns that off), and passed only to the server process's environment: never saved, never
  printed (only `sk-…` and its last 4 characters).
- **Other options:**
  - `--port` (TraceAssist, default 8092);
  - `--tsp-port` (default 8081);
  - `--memory` (default 4g);
  - `--workspace` (the server's data folder, default `~/.tracecompass-webapp`).

  Ctrl+C stops the server.
- **Tested on 2026-11-10 on a fresh copy of the stock server**, beside the running one, on
  8181/8192 with its own workspace:
  - a second install changed nothing;
  - the hidden prompt worked, and a fake key was rejected by the check;
  - three critical-path questions gave findings identical to this machine's server;
  - `/ask` with a fake key failed with OpenAI's "Incorrect API key provided: sk-test-…WXYZ",
    so the server uses the key it was given.

`start_trace_server.sh` below is for this machine only: it reads the key from the Eclipse
launch configuration. The jar never does.

## Build, install, restart

```bash
cd ~/eclipse-workspace/org.eclipse.tracecompass.helloworld.ui
server/build.sh --install          # compile, package, install in the Trace Server
server/start_trace_server.sh       # restart it (-clean), wait for 8081 and 8092
```

- **Java changes** (anything in `src/.../views` that the server uses) need a rebuild, an
  install and a restart.
- **Skill and card edits** need nothing: both Eclipse and the server re-read them on every
  question.
- `start_trace_server.sh` takes `OPENAI_API_KEY` from the environment. If it isn't set
  there, the script reads it from the Eclipse launch configuration (`tracing.product.launch`),
  and never prints it. It logs to `~/.cache/traceassist/trace-server.log`.

## What `--install` changes in the Trace Server

Originals are kept in `<server>/backup-before-traceassist/`.

1. **Adds the bundle:** it adds `plugins/org.eclipse.tracecompass.traceassist.server_0.1.0.jar`,
   and lists it in `configuration/config.ini` (`osgi.bundles`, `@4:start`). It also adds
   `traceassist.home` and `traceassist.port`.
2. **Patches one Trace Compass class:** `org.eclipse.tracecompass.analysis.graph.core_5.1.0.*.jar`
   gets the workspace's `AbstractCriticalPathModule`.
   - Your Eclipse runs the Trace Compass sources in this workspace. They differ from the
     server's release in only that one file: the `windowStartNs`/`windowEndNs` parameters,
     which compute a critical path over a window.
   - The patch makes the server compute critical paths the same way.
   - The patched jar is no longer signed, which Equinox does not check.

To undo: copy the two files back from the backup folder, delete the TraceAssist jar, and
restart with `-clean`.

## Pitfalls

- **Nothing from Trace Compass may load before the Trace Server sets its workspace.**
  Activating `tmf.core` early ("The instance data location has not been specified yet")
  fails it for good, and the server shuts down. `ServerActivator` therefore only starts a
  thread. The thread waits for `Platform.getInstanceLocation().isSet()`, then creates the
  pipeline.
- **The bundle opens its own trace instances, as the Eclipse endpoint does.** Their analysis
  files go to a temporary folder named after each trace's full path, so they don't collide
  with the server's own TSP experiments (those use the server workspace).
