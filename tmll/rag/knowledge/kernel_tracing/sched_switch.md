---
id: kernel-sched-switch-001
title: sched_switch and context switches
domain: kernel_tracing
concept: sched_switch
trace_type: lttng_kernel
source_url: https://docs.kernel.org/trace/rv/monitor_sched.html
source_title: Linux kernel scheduler monitor documentation
---

# sched_switch and context switches

The `sched_switch` event records a context switch from one task to another. It
is central evidence for reconstructing when a thread stopped running and which
thread ran next on that CPU.

By itself, a switch away from a task does not prove the root cause of a delay.
Interpret it with the task's next state, wake-up events, syscall spans, and CPU
activity around the same time range.
