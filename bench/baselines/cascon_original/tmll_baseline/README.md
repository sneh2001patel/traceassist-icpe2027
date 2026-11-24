# TMLL baseline

This experiment asks the exact same 13 questions as `llm_baseline` and
`RAG_baseline`, with the same answering instruction ("say what is missing, then
give your best answer"). TMLL analyzes the kernel traces; an LLM interprets its
structured results and writes a natural-language answer to each question. The
LLM does not select tools or run a separate investigation.

The first run (v1) used a stricter system prompt that forbade inferring lock
ownership, wake-ups, round boundaries or timings, and a presentation that dropped
CPU 3 and `worker-2`'s futex entry and showed only 12 sampled states per thread.
Its answers and evidence are kept in `results/v1_strict_prompt/` and
`evidence/<trace>/v1/`.

## Setup

From this directory, with Python 3.11 or newer:

```bash
git -C ../tmll submodule update --init tmll/tsp
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
export OPENAI_API_KEY=...
```

Start a Trace Compass Trace Server with the kernel analyses enabled. For an
existing installation, for example:

```bash
/path/to/tracecompass-server -data /path/to/tmll-baseline-workspace -vmargs -Dtraceserver.port=8080
```

The server must be able to read the absolute paths under
`../runs/runs_to_use/*/trace/kernel`. The baseline uses the local `../tmll`
checkout directly. It does not install, launch, or delete a server/workspace.
`prepare` creates named experiments on the server without deleting existing ones.

## Run

```bash
# Collect TMLL evidence for the 2m, 10m, and 30m traces; no LLM calls.
.venv/bin/python tmll_baseline.py prepare

# Review the API call plan after preparation.
.venv/bin/python tmll_baseline.py run --dry-run

# One independent API call per question per trace (39 calls for one repeat).
.venv/bin/python tmll_baseline.py run --repeats 1
.venv/bin/python tmll_baseline.py export --repeat 1
```

To start with one trace or selected questions:

```bash
.venv/bin/python tmll_baseline.py prepare --traces 2m --host localhost --port 8080
.venv/bin/python tmll_baseline.py run --traces 2m --questions Q1 Q4 --repeats 1
```

The API defaults match the RAG baseline: `gpt-5.6`, one repeat, two workers,
32,000 maximum output tokens, 900-second request timeout, and five SDK retries.
`--reasoning-effort`, `--model`, and the other run options can be set explicitly
to match a particular comparison run. Requests use the
[OpenAI Responses API](https://developers.openai.com/api/reference/python/resources/responses/methods/create),
with `store=False` and a shared evidence prompt-cache key. No previous question
or answer is included in a request.

## Evidence and comparison scope

`prepare` discovers native TMLL outputs and collects XY series, time graphs
(including available dependency arrows), and data-tree statistics. Raw event
tables are excluded. It also attempts TMLL z-score anomaly detection and Pearson
correlation on the selected XY outputs. Unavailable analyses and errors are
recorded in the evidence. TMLL's TSP client preserves native data-tree headers
and labels that the simplified TMLL tree model otherwise joins together.

This baseline analyzes **the full trace**, identified as `TMLL_full` in results.
It does not use the other baselines' `A_head`, `B_middle`, or `C_sampled` text
slices. This is a comparison of analysis methods with different trace access,
not an equal-input ablation. TMLL requests XY/time-graph data at a configurable
resolution (requested default `10ms`). For longer traces, the interval increases
to cap each series at approximately 12,000 samples and bound collection memory.
The effective interval is recorded in the raw results and prompt metadata.
This is not an exhaustive scheduler event history.

Collection also limits XY/time-graph requests to approximately 200 tree entries
per output, retaining workload entries, per-CPU entries and their ancestors, and
evenly sampling other entries. Workload entries are the threads named in the
questions (`batch_server`, `worker-N`, `flusher`), matched by name or by TID:
the TIDs are read from Thread Status first, because some outputs (e.g. futex
waiters) name entries by TID only. This avoids requesting thousands of unrelated
system threads in one response. Each output records available, requested, and
omitted entry counts; ML analyses use the same bounded fetch. Unrequested data is
not present in the raw file. Data-tree statistics are collected in full.

Time-graph workload entries are fetched a second time on their own at
`--workload-resample-freq` (default `100us`, no sample cap), in one request per
TSP batch, and stored as `workload_data`. At the full-trace resolution, short
running and runnable states are skipped. Time-graph arrows are requested at the
same resolution as the data and filtered to arrows to or from workload entries.

The prompt shows, for every time-graph output, `workload_state_totals`: per
workload entry (and per CPU entry whose states name a workload thread), each
state's count, total, mean, p50, p90, min, max and a duration histogram, computed
from every returned state (from `workload_data` when present). These are plain
sums of TMLL output, not a diagnosis. It also uses deterministic, evenly spaced
examples: up to 100 rows per workload series or entry (`--rows`) and 3 per other
series or entry (`--other-rows`). All returned XY samples contribute to the
reported min/max/mean/median; anomaly counts use all returned analysis rows.
Large output inventories are bounded to 24 entities (`--entities`) plus every
workload and CPU entry. Selected tree nodes retain their ancestors; time-graph
rows and data-tree statistics are restricted to the retained nodes. The prompt
records omitted node, series, state, and statistic counts. This selection is
presentation logic, not a TMLL inference about which entities matter.

The prompt reduces example and inventory counts to meet the default
200,000-token evidence budget. Complete collected results remain in the raw
file. If the compact presentation still exceeds the budget, preparation fails
with guidance rather than silently truncating JSON.

The budget excludes the system prompt, question, and answer. Leave enough room
for those within your model's context window. TMLL does not mark rounds, lock
ownership, or wake-up sources; as in the other baselines, the LLM is instructed
to say what is missing and then give its best answer.

Preparation options:

- `--keywords "cpu usage" "control flow"`: OR filter on output name/ID/description.
- `--resample-freq 1ms`: request a finer TMLL sampling resolution.
- `--max-samples 12000`: cap samples per series over the full trace; increase this
  along with a finer requested resolution if needed, at higher memory cost.
- `--max-entities 200`: bound entries requested from each XY/time-graph output.
- `--workload-resample-freq 100us`: resolution of the separate workload-entry
  time-graph fetch.
- `--analyses anomaly correlation`: the default ML analyses; pass `--analyses`
  with no values to collect native outputs without ML analyses.
- `--rows 100 --other-rows 3 --entities 24 --budget 200000`: control displayed
  evidence size. If the budget is exceeded, `--rows` is halved until it fits.
- `--tmll-timeout 3600`: timeout for the entire TMLL subprocess per trace,
  including server indexing and analysis polling.
- `--tmll-source /path/to/tmll --tmll-python /path/to/python`: use another local
  checkout/environment with its dependencies installed.
- `--reuse-raw`: rebuild prompt evidence from saved raw results without contacting
  the server. Only presentation options affect this mode; collection settings
  remain those recorded in the saved results.

Only `trace/kernel` is imported. Ground-truth files, `program.log`, workload
source/descriptions, RAG documents, and other baseline answers are never read.

## Artifacts and resuming

- `questions.json`: identical copy of both baselines' questions.
- `evidence/<trace>/tmll_raw.json.gz`: full collected structured results before
  prompt sampling, including analysis failures.
- `evidence/<trace>/tmll.txt`: exact evidence sent to the LLM.
- `evidence/<trace>/tmll.json`: token count, content hash, trace metadata, TMLL
  revision, and presentation settings.
- `results/answers.jsonl`: append-only answers, failures, token usage, and latency.
- `results/answers.csv` and `.md`: completed answers for grading; `--repeat N`
  writes `answers_repeatN.csv` and `.md`.

Rerunning skips completed, nonempty answers with the same model, trace,
question, repeat, evidence hash, and prompt/settings hash. Failed, incomplete,
and empty responses are retried. Changing evidence or answer settings creates
a distinct run; exports retain both versions with hashes identifying them.
Latency measures the LLM request only; TMLL preparation is a separate phase.
Evidence files and the virtual environment are ignored by Git.

If preparation fails after saving a raw result (for example, because the prompt
was too large), reuse it without repeating the analysis:

```bash
.venv/bin/python tmll_baseline.py prepare --traces 2m --reuse-raw
```

Wait for successful preparation of every requested trace before starting `run`.
For a new run, use `prepare && run && export` so an unsuccessful preparation
cannot trigger the answer stage. A process exiting does not imply success.

Offline checks (no server or API calls):

```bash
.venv/bin/python -m unittest discover -s tests -v
```
