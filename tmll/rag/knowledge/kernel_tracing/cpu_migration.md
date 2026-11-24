---
id: kernel-cpu-migration-001
title: CPU migration and task placement
domain: kernel_tracing
concept: cpu_migration
trace_type: lttng_kernel
source_url: https://docs.kernel.org/scheduler/sched-design-CFS.html
source_title: Linux CFS scheduler documentation
---

# CPU migration and task placement

A runnable task may run on different CPUs over time. CPU migration and task
placement are scheduler decisions influenced by runnable tasks, CPU capacity,
affinity, wake-ups, and load balancing.

Migration alone is not a bottleneck diagnosis. Look for long runnable
waiting-for-CPU intervals, overloaded CPUs, affinity restrictions, or repeated
short runs that match the observed latency.
