---
key: syscall_latency_scatter
name: System Call Latency vs Time
view_id: org.eclipse.tracecompass.analysis.os.linux.views.latency.scatter
tsp_output: org.eclipse.tracecompass.internal.analysis.timing.core.segmentstore.scatter.dataprovider:org.eclipse.tracecompass.analysis.os.linux.latency.syscall
focus: series
zoom_pad: 2.0
zoom_min_span_ms: 1.0
---
# System Call Latency vs Time

## What it shows

One dot per system call: its duration against when it started, for every thread, grouped
into series by system-call name (futex, read, write, fsync, ...).

## Questions it answers

Which system calls were slow and when; whether one call stands out from the others of its
kind; the longest calls of a thread.

## What can be focused

Series (`series`): the system-call names to tick, e.g. the names among the thread's longest
calls. Names must be among the given series.

## Zoom rule

The call plus twice its length on each side, at least 1 ms, so the dots of the calls around
it are visible for comparison.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It plots nothing until a series is ticked: always focus at least one series.
- It shows all threads' calls, not one thread's: the table, or Control Flow, ties a call to
  its thread.
- The series list fills in only after the latency analysis (a pass over all events), which can
  take minutes on a large trace.
- A deliberate sleep (clock_nanosleep, nanosleep) or an idle futex wait is a long call but not
  a slow one.
- exit and exit_group never return: Trace Compass ends them when the thread ends, so they
  look like the longest calls of every thread. They are not slow calls; the longest-call
  moment skips them.
