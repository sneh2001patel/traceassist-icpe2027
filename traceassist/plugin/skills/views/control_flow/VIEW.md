---
key: control_flow
name: Control Flow
view_id: org.eclipse.tracecompass.analysis.os.linux.views.controlflow
tsp_output: org.eclipse.tracecompass.internal.analysis.os.linux.core.threadstatus.ThreadStatusDataProvider
focus: thread
zoom_pad: 0.1
zoom_min_span_ms: 0.05
---
# Control Flow

## What it shows

One row per thread (grouped under its process), coloured by its state over time: running in
user mode, running in a system call, interrupted, waiting for a CPU, blocked, or unknown.
Selecting a row selects the thread; hovering a state shows its exact start, end and
duration.

## Questions it answers

What a thread did over time and in which state; the shape of a late cycle (a long blocked or
waiting stretch among regular short cycles); a thread's own work (a long running stretch);
how the threads of a process interleave; when a thread was created or exited.

## What can be focused

One thread (`tid`): its row is selected and scrolled into view. Use the thread the evidence
is about.

## Zoom rule

The moment plus 10% on each side, at least 0.05 ms: enough to see the whole stretch and the
normal cycles next to it.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- Many threads means many rows: without a selected thread the interesting row may be far off-
  screen, so always focus a thread.
- It shows states, not who caused them: for who woke a thread or what it waited on, add
  Critical Path; for who held its CPU, add Resources.
- A very short moment (microseconds) in a long trace needs the zoom rule; at full range it is
  invisible.
