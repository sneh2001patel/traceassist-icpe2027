---
id: trace-compass-critical-path-001
title: Critical Path (Process Wait Analysis)
domain: trace_compass
concept: critical_path
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/LTTng-Kernel-Analysis.html
source_title: Trace Compass LTTng Kernel Analysis Guide
---

# Critical Path (Process Wait Analysis)

Trace Compass can recover the wait causes of local and distributed processes
using operating system events. The analysis highlights the tasks and devices
causing a process to wait, by following the chain of scheduling and wake-up
events backward through however many other threads -- and, when traces from
multiple machines are combined with clock synchronization, however many other
hosts -- are causally involved.

This is a different question than "what does the Control Flow view show for
this one thread." A single thread's BLOCKED/RUNNING breakdown only describes
that thread's own states; it does not say why another thread's actions
determined how long those waits lasted. The critical path instead answers
"which other threads' work is actually on the causal chain that explains this
thread's total duration" -- the same duration can be dominated by one other
thread doing real work, or by several threads and hosts handing dependencies
back and forth (a classic case for a distributed web application, where a
client's wait may be explained by work done by an application server and a
database server on two different machines).

The corresponding view in the UI is the Critical Flow View: right-clicking a
process in the Control Flow view and selecting "Follow" runs this analysis
and displays the result there, with vertical arrows representing
synchronization and communication between the processes involved.

The critical path is recursive and can span every task running on the
system, so a wide critical path is not itself evidence of a problem -- it
means many threads/hosts happened to be part of the causal chain, not that
all of them are the bottleneck. Identifying which specific participant
dominates the path's total duration still requires looking at how much of
that duration each participant's own segments account for.
