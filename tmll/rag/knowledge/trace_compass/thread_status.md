---
id: trace-compass-thread-status-001
title: Thread Status time graph
domain: trace_compass
concept: thread_status
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# Thread Status time graph

The Thread Status or Control Flow time graph displays per-thread scheduling
states. It is useful for measuring when a thread was running, runnable,
blocked, interrupted, or not alive.

Use this view to establish the shape of a delay. It does not, by itself,
identify the application request or remote endpoint behind a syscall.
