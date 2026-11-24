---
id: tmll-tsp-outputs-001
title: TSP and TMLL outputs
domain: trace_compass
concept: tsp_outputs
trace_type: lttng_kernel
source_url: https://github.com/eclipse-tracecompass/tmll
source_title: TMLL project repository
---

# TSP and TMLL outputs

TMLL consumes Trace Server Protocol outputs such as time graphs, XY series, and
tables. A RAG assistant should treat these TMLL outputs as the trace evidence
layer, not as documentation to embed in the vector store.

Retrieve documentation to explain the evidence. Query TMLL or Trace Server for
facts about the currently opened trace.
