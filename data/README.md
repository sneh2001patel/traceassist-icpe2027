# Data

The large files are kept as archives outside git. `SHA256SUMS` lists every archive, and `unpack.sh` checks them before unpacking them where the scripts expect them.

| Archive | Size | What it holds | Unpacked to |
|---|---|---|---|
| `traces/<run>.tar.xz` (56) | 794 MB (5.0 GB unpacked) | One LTTng kernel trace per bench run (`trace/kernel/`): 30 s each, 1.4–25.3 million events, none discarded. | `bench/runs/<run>/trace/` |
| `baseline_inputs/slices.tar.xz` | 1.8 MB | The 200,000-token trace-text slice each LLM-only and RAG answer was given. | `bench/baselines/slices/` |
| `baseline_inputs/tmll_evidence.tar.xz` | 409 MB | The TMLL evidence each TMLL-baseline answer was given. | `bench/baselines/tmll/evidence/` |
| `trace-server/trace-compass-server.tar.gz` | 102 MB | The stock Eclipse Trace Compass Trace Server 0.18.0 (build 202607110558) for Linux x86-64. | `trace-server/` (TraceAssist) and `bench/baselines/tmll/server/` (TMLL baseline) |

The baselines' inputs can be rebuilt from the traces, with `slice_baselines.py prepare` and `tmll/tmll_baseline.py prepare`. The archives hold the exact inputs the reported answers saw.

Which fault each run has is in `bench/runs/index.csv`, and each run's answer key is in `bench/runs/<run>/ground_truth/`. Never give either to a system under test.

**Getting the archives:** they are published on Zenodo, DOI [10.5281/zenodo.24489091](https://doi.org/10.5281/zenodo.24489091)
(CC BY 4.0; the bundled Trace Server is Eclipse software under EPL-2.0).
`data/download.sh` downloads them into the folders above (1.3 GB), and `data/unpack.sh` checks them
against `SHA256SUMS` and unpacks them.
