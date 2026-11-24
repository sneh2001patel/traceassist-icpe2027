---
id: kernel-thread-states-001
title: Linux thread scheduling states
domain: kernel_tracing
concept: thread_states
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# Linux thread scheduling states

Kernel scheduling states distinguish running work from waiting work. A thread
can be running on a CPU, runnable but waiting for CPU time, blocked while
waiting for an event, interrupted, unknown, or not alive.

For diagnosis, blocked time and runnable time mean different things. Blocked
time points to a wait condition such as I/O, a lock, a timer, or socket data.
Runnable waiting-for-CPU time points more directly to scheduler delay or CPU
contention.
