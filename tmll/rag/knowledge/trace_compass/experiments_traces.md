---
id: trace-compass-experiments-traces-001
title: Experiments and multiple traces
domain: trace_compass
concept: experiments_traces
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/User-Guide.html
source_title: Trace Compass User Guide
---

# Experiments and multiple traces

Trace Compass experiments combine traces so analyses can be inspected across a
shared time range. This is useful when the behavior spans kernel events,
application events, and possibly multiple hosts or processes.

For Django performance diagnosis, adding application logs or userspace traces
to a kernel trace can provide the missing request and dependency correlation.
