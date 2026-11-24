---
id: trace-compass-system-call-analysis-001
title: System Call Latency Analysis
domain: trace_compass
concept: system_call_analysis
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# System Call Latency Analysis

The System Call Latency Analysis measures latency between syscall entry and
exit by syscall type. It can reveal which syscalls consumed time for a process
or thread.

For blocked-thread diagnosis, correlate syscall latency rows with blocked
scheduling intervals. This can show that a blocked interval occurred inside a
specific syscall such as `recvfrom`, `poll`, or `futex`.
