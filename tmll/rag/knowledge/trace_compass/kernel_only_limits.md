---
id: trace-compass-kernel-only-limits-001
title: Limits of kernel-only evidence
domain: trace_compass
concept: kernel_only_limits
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# Limits of kernel-only evidence

Kernel traces are strong evidence for scheduling states, syscalls, interrupts,
CPU activity, and some resource interactions. They are weaker evidence for
application-level ownership unless identifiers are correlated.

A kernel socket wait proves a socket wait. It does not automatically prove
which Django request, database query, cache call, HTTP client, or remote
service caused the wait.
