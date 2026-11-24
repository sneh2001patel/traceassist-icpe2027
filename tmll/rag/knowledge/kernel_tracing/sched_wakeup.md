---
id: kernel-sched-wakeup-001
title: sched_wakeup and blocked thread wakeups
domain: kernel_tracing
concept: sched_wakeup
trace_type: lttng_kernel
source_url: https://docs.kernel.org/trace/rv/monitor_sched.html
source_title: Linux kernel scheduler monitor documentation
---

# sched_wakeup and blocked thread wakeups

Wake-up events show when a sleeping task becomes runnable again. For a blocked
thread, a wake-up near the end of the blocked interval can help identify the
thread or kernel path that made progress possible.

Wake-up correlation is stronger evidence than the blocked interval alone. It
can help separate "what the thread was waiting in" from "what resource or task
made it runnable again."
