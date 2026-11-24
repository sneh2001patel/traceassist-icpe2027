---
key: sched_latency_table
name: Sched_Wakeup/Switch Latencies
view_id: org.eclipse.tracecompass.analysis.timing.ui.segstore.table:org.eclipse.tracecompass.analysis.os.linux.core.swslatency.sws
tsp_output: org.eclipse.tracecompass.analysis.timing.core.segmentstore.SegmentStoreTableDataProvider:org.eclipse.tracecompass.analysis.os.linux.core.swslatency.sws
focus: none
zoom_pad: 0
zoom_min_span_ms: 0
---
# Sched_Wakeup/Switch Latencies

## What it shows

A table of wake-up delays with their start, end, duration and thread, sortable by duration.

## Questions it answers

Exact wake-up delays; the worst ones (sort by duration).

## What can be focused

Nothing to focus.

## Zoom rule

The delay itself (no padding).
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It fills in only after the latency analysis is done.
