# TraceAssist: artifact for the ICPE 2027 industry paper

This repository holds everything behind the paper *TraceAssist: Answering Kernel Trace Questions
in Natural Language* (ICPE 2027, Industry Track):

- **TraceAssist**, frozen at the version that produced the paper's results;
- **the symptom bench**: nine C programs with fault switches, the 56 traces recorded from them, their answer keys, and the 112 questions;
- **the four baselines**: LLM only, RAG, TMLL and Codex;
- **every system's answer and verdict** for each of the 516 question–trace pairs;
- **the paper's LaTeX source**, with the scripts that draw its figures from those results.

## Layout

| Path | What it is |
|---|---|
| [`QUESTIONS.md`](QUESTIONS.md) | All 112 questions (56 questions in a precise and an everyday wording), by category, with the traces each was asked of. |
| [`SYMPTOMS.md`](SYMPTOMS.md) | The 48 symptoms in 7 groups: what counts as present, how users ask about it, and which program and fault show it. |
| `traceassist/plugin/` | The TraceAssist Trace Compass plug-in: the answer pipeline, analyzers and answer writer (`src/`), the three AI skills and 13 view descriptions (`skills/`), and the Trace Server bundle with its build scripts and launcher (`server/`). |
| `traceassist/tracecompass-patch/` | The only change to Trace Compass: `AbstractCriticalPathModule.java` from `analysis.graph.core`, which adds a time window to the critical path. |
| `traceassist/dist/` | The frozen binaries. `org.eclipse.tracecompass.traceassist.server_0.1.0.jar` is the server bundle used for every reported answer. `traceassist-server.jar` is a launcher that installs that bundle and the critical-path patch into a Trace Server and starts it. |
| `tmll/` | Our fork of [TMLL](https://github.com/eclipse-tmll/tmll): the TraceAssist service (`tmll_assistant_service_syscall_v1.py`, port 8000), our modules (system-call frequency, periodic jitter and late cycles, and others), and the RAG code with its 37-document knowledge base and index (`rag/`). |
| `bench/` | The symptom bench: programs (`*.c`, `bench.h`, `Makefile`), recording scripts, the symptom catalog, the questions, the question–trace pairs and the answer key. See [bench/README.md](bench/README.md). |
| `bench/runs/<run>/` | One folder per recorded trace: `ground_truth/`, `capture.json` and `program.log`. The trace itself (`trace/`) is unpacked from `data/`. |
| `bench/baselines/` | The four baselines. See [bench/baselines/README.md](bench/baselines/README.md). |
| `bench/results/` | Saved answers. `traceassist/run1`–`run3` are TraceAssist's three runs; `llm_only`, `rag`, `tmll` and `codex` each have `run1`. Each run comes with its scores (`run<N>_scores.txt` and `.csv`), and the Codex run also includes the agents' transcripts. |
| `data/` | The large files, as archives outside git: the 56 traces, the baselines' inputs, and the stock Trace Server. See [data/README.md](data/README.md). |
| `paper/` | The paper's LaTeX source. `figures/make_result_figures.py` draws Figures 4 and 5 from `bench/results`. |

## The frozen version

Every saved TraceAssist answer records two fingerprints:

- **Build `a4162fd526b12d22`:** a hash of the server bundle, the skill files and the TMLL service's code.
- **Knowledge base `1d7092adf385d1ab`:** a hash of the RAG documents.

`python3 verify_frozen.py` recomputes both from this repository. It also checks that the launcher carries the same bundle, and that all 3 × 516 answers in `bench/results/traceassist` have both fingerprints. It needs no network and no API key.

The fork of TMLL is upstream commit `06ac831` plus our changes. Its `tsp` client submodule is at `d5a9e5e` (tsp-python-client). Its test-trace submodules are not included.

## Reproducing the paper's numbers (no API calls)

```bash
python3 verify_frozen.py
cd bench
python3 score.py --system traceassist --run 1      # also --run 2, 3; --system llm_only, rag, tmll, codex
python3 ../paper/figures/make_result_figures.py   # Figures 4 and 5
```

`score.py` reads each answer's verdict line and compares it with `pairs.json`. Its output matches the stored `run<N>_scores.txt` files.

Run 1 of each system, on the 504 graded answers (the 12 on pairs the trace cannot show are reported separately):

| System | Balanced accuracy | Precision | Recall | Specificity | FP | FN | Abstained |
|---|---|---|---|---|---|---|---|
| TraceAssist | 0.93 | 0.85 | 0.93 | 0.93 | 24 | 11 | 3% |
| Codex | 0.79 | 0.54 | 0.91 | 0.68 | 113 | 14 | 8% |
| TMLL | 0.69 | 0.57 | 0.55 | 0.83 | 62 | 66 | 45% |
| LLM only | 0.58 | 0.50 | 0.28 | 0.88 | 42 | 106 | 72% |
| RAG | 0.58 | 0.51 | 0.28 | 0.89 | 40 | 107 | 70% |

Over its three runs, TraceAssist's balanced accuracy is 0.930 ± 0.005.

## Running the systems again

You need:
- Linux x86-64;
- Java 21;
- Python 3.12;
- an OpenAI API key, read from the environment and never stored.

All systems answer with `gpt-6-luna`. TraceAssist's thread finder uses `gpt-5.6-sol`.

1. **Unpack the data:** `data/unpack.sh` checks the archives against `data/SHA256SUMS` and unpacks the traces, the baselines' inputs and the Trace Server.
2. **TMLL service:**

   ```bash
   cd tmll
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt -e .
   .venv/bin/python3 tmll_assistant_service_syscall_v1.py
   ```

   TraceAssist still answers without it, but without TMLL's evidence or the RAG documents. `bench/run_traceassist.py` checks the service's health around every answer.
3. **TraceAssist:**

   ```bash
   java -jar traceassist/dist/traceassist-server.jar start --server trace-server/trace-compass-server
   ```

   This installs the frozen bundle and the critical-path patch, and serves `/ask` on 127.0.0.1:8092. To rebuild the bundle from source, use `traceassist/plugin/server/build.sh --install` instead (it needs `ECLIPSE_BUNDLE_POOL`, see the script).
4. **Ask the bench:**

   ```bash
   cd bench
   python3 run_traceassist.py --run 4
   ```

   This saves to `results/traceassist/run4`, restartably, and takes about 3 hours.
5. **Baselines:** see [bench/baselines/README.md](bench/baselines/README.md).

To record new traces, you need LTTng and root to start `lttng-sessiond`; see `bench/capture.sh` and `bench/record_all.sh`. New recordings get new random run ids, so they do not replace the paper's traces.

## Rules for the systems under test

A system under test receives only a run's `trace/kernel` folder and the question, followed by the verdict instruction (`bench/verdict.py`). Never give it any of the following:
- `ground_truth/`, `capture.json` or `program.log`;
- `runs/index.csv`, `pairs.json`, `pairs.csv` or `answer_key.json`;
- another system's answers.

## Notes

- The traces are whole-machine kernel recordings from one desktop (one kernel version, 30 s each). Besides the bench program, they show the desktop's own processes, their names and open file paths, and the user name. Several saved files keep the absolute paths of the machine they were recorded on.
- Licenses: `tmll/` keeps TMLL's MIT license (Ericsson). A license for the rest of the repository has not been chosen yet.
