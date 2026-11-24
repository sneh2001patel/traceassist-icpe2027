---
key: critical_path
name: Critical Path
view_id: org.eclipse.linuxtools.tmf.analysis.graph.ui.criticalpath.view.criticalpathview
tsp_output: none
focus: thread
zoom_pad: 0.05
zoom_min_span_ms: 0.05
---
# Critical Path

## What it shows

For one followed thread, the chain of threads and states it depended on over time: while it
waited, which thread it was waiting for and what that thread was doing (running, blocked on
a timer, waiting for a CPU, on another thread), down to the root cause.

## Questions it answers

Why a thread waited: who woke it, and what that thread was itself waiting on; a wait chain
across threads (A waited on B, which waited on C's timer); the bottleneck of a program
(follow its main thread over a typical wait).

## What can be focused

One thread (`tid`): the thread to follow. For a program's bottleneck, follow the main
thread; for a thread's late cycle or wait, follow that thread.

## Zoom rule

The wait itself plus 5% on each side, at least 0.05 ms: the path is only meaningful inside
the wait.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It shows nothing until a thread is followed: always focus a thread.
- It is computed for the thread's whole life; on a large trace it can take a while to appear.
- A late cycle the thread spent running (its own work) has no other thread on its path:
  Control Flow shows it better.
- Wake-ups across CPUs can be attributed to the wrong thread (a known Trace Compass issue);
  the explainer's wake chain is the reference.
