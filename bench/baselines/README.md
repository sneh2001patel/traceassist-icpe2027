# Baselines on the symptom bench

These are the four baselines of our earlier prototype study (CASCON draft), adapted to the bench's 258 pairs × 2 wordings (516 answers each). The originals are kept in `cascon_original/`. The TMLL baseline uses plain upstream TMLL, [eclipse-tmll/tmll](https://github.com/eclipse-tmll/tmll) at commit `61d408b2cdedcf4b6df96c787a310e91c59f595a`, not TraceAssist's fork in `../../tmll`: clone it to `third_party/tmll-upstream/` at the repository root, with its own `.venv` (`pip install -r ../cascon_original/tmll_baseline/requirements.txt` and `-e .`), or set `TMLL_UPSTREAM`.

| System (`score.py --system`) | What the model gets | Script |
|---|---|---|
| `llm_only` | Raw babeltrace2 text: one 200k-token slice per trace, made of 20 short windows spread over the whole trace (CASCON's "C_sampled") | `slice_baselines.py` |
| `rag` | The same slice, plus the 6 nearest documents from TMLL's knowledge base | `slice_baselines.py`, `retrieve_docs.py` |
| `tmll` | TMLL's analyses of the whole trace, from a plain Trace Server (no TraceAssist) | `tmll/tmll_baseline.py`, `tmll/collect_tmll.py` |
| `codex` | A Codex agent with a shell, babeltrace2 and Python, the full trace read-only, and network access only to the model API | `codex/codex_baseline.py` |

## Shared conditions

These are the same for every baseline and for TraceAssist:
- **Inputs:** only the run's `trace/kernel` folder, and the bench question with the verdict line (`verdict.py`). `pairs.json` is read only to know which question goes with which run. No ground truth, `capture.json`, `program.log`, answer key or other system's answers.
- **Model:** gpt-6-luna, at the model's default reasoning effort.
- **One answer per pair:** every answer comes from its own call or session, so no answer sees another.
- **Scoring:** answers are saved to `results/<system>/run1/<id>.json` in TraceAssist's format, and `python3 score.py --system <system>` grades them. Each baseline is run once; TraceAssist's run 1 is the comparison.

## Choices made for the bench (2026-11-22)

- **Slices:** the LLM-only and RAG baselines get only the 20-window slice, not CASCON's three slices, so each gives one answer per pair.
- **Codex:** a fresh session per question, not one conversation per trace.
- **RAG documents:** TMLL's knowledge base only, with no program descriptions. The CASCON `batch_server` description was also removed from TraceAssist's own knowledge base (`tmll/rag/knowledge_excluded/`), and TraceAssist's batch_server answers were rerun without it.
- **TMLL server:** a stock Trace Server 0.18.0 with no TraceAssist bundle (`tmll/server/`, from `data/trace-server/`), on port 8080 with its own workspace.
- **TMLL focus:** the threads that get full detail are those of the program the questions name: its process, its threads and its child processes, found in TMLL's Thread Status. CASCON had batch_server's thread names hard-coded.

## Running

```bash
cd bench/baselines
../../data/unpack.sh                                          # traces, these baselines' inputs, the plain Trace Server
python3 -m venv .venv && .venv/bin/pip install openai tiktoken     # done
export OPENAI_API_KEY=...                                           # read from the environment only

# LLM only and RAG
.venv/bin/python slice_baselines.py prepare                   # slices/ (done; no API)
"../../tmll/.venv/bin/python" retrieve_docs.py                # retrieved_docs.json (done; no API)
.venv/bin/python slice_baselines.py run --system llm_only
.venv/bin/python slice_baselines.py run --system rag

# TMLL
tmll/start_server.sh                                          # plain Trace Server on 8080
.venv/bin/python tmll/tmll_baseline.py prepare                # tmll/evidence/<run>/ (no API)
.venv/bin/python tmll/tmll_baseline.py run

# Codex
.venv/bin/python codex/codex_baseline.py check                # isolation + one model call
.venv/bin/python codex/codex_baseline.py run --jobs 2

python3 ../score.py --system llm_only    # and rag, tmll, codex
```

Every `run` saves each answer as soon as it's complete. A stopped run continues where it left off; `--retry-errors` asks again where an error was saved.

## Notes

- **Damaged stream in `pipeline-394e`:** the CPU 6 stream file (`bench_6`) has a damaged packet 4.5 s into the trace. babeltrace2 stops there; Trace Compass reads past it. The slicer reads windows after that point from the other 15 streams, and the slice says so. The Codex agent meets the same error and has to deal with it itself.
- **TMLL thread groups (`jobrunner-d890`):** that trace's fault is thread churn, and the program starts 2,998 threads named `job-worker`. Giving every one full detail made even the smallest evidence 1.9M tokens, over the 200k budget. So when more than 24 (the per-output entity limit) of the program's threads share a name, 24 of them, evenly spread by thread ID, keep full detail. The others are summed as a group: state totals in Thread Status and Resources Status, and CPU time in CPU Usage. The evidence names the rule and the threads shown (`presentation.thread_groups`). Its evidence is 178,892 tokens. No other trace has a thread name that common, and rebuilding the other 55 traces' evidence with this code gave byte-identical files.
- **TMLL gaps:** `Memory Usage` is missing from every trace (no memory events), and `State System Explorer` from `pipeline-5c60`. The plain Trace Server answers that request with HTTP 500 at once, on every try, with nothing in its log. The evidence marks both as "TMLL returned no output tree".
- **Slice coverage:** about 66 tokens per event means a 200k-token slice holds about 3,000 events, a few milliseconds of trace per window (0.2–13 ms in the slices checked).
- **Codex resources:** each agent container gets 4 CPUs and 8 GB (`AGENT_CPUS` and `AGENT_MEM`). CASCON gave 8 and 16 GB, one conversation at a time.
