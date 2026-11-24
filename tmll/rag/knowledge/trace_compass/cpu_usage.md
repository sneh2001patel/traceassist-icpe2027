---
id: trace-compass-cpu-usage-001
title: CPU Usage analysis
domain: trace_compass
concept: cpu_usage
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# CPU Usage analysis

CPU Usage analysis summarizes processor utilization over time. It is useful
for checking whether a thread's delay coincided with high CPU demand.

Low runnable waiting-for-CPU time plus blocked syscall evidence usually argues
against CPU contention as the main cause, even if some CPUs were busy.
