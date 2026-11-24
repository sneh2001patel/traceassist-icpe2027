---
id: kernel-runnable-001
title: Runnable time and CPU contention
domain: kernel_tracing
concept: runnable
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# Runnable time and CPU contention

A runnable thread is ready to execute but is not currently running on a CPU.
Substantial runnable time can indicate CPU contention or scheduling delay.
Low runnable time does not support CPU contention as the primary cause of a
thread's delay.
