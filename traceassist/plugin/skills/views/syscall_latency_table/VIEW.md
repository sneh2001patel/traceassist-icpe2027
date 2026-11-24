---
key: syscall_latency_table
name: System Call Latencies
view_id: org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.latency.syscall
tsp_output: org.eclipse.tracecompass.analysis.timing.core.segmentstore.SegmentStoreTableDataProvider:org.eclipse.tracecompass.analysis.os.linux.latency.syscall
focus: none
zoom_pad: 0
zoom_min_span_ms: 0
---
# System Call Latencies

## What it shows

A table of system calls with their start, end, duration and thread, sortable by duration.

## Questions it answers

The exact durations and times of system calls; the longest calls (sort by duration); which
thread made a call.

## What can be focused

Nothing to focus: it lists the calls; the shared selection highlights the call at that time.

## Zoom rule

The call itself (no padding).
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It fills in only after the latency analysis is done.
- It lists every thread's calls: say which thread to look for in the look-at text.
- exit and exit_group never return: Trace Compass ends them when the thread ends, so they
  look like the longest calls of every thread. They are not slow calls; the longest-call
  moment skips them.
