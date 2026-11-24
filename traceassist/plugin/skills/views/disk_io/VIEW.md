---
key: disk_io
name: Disk I/O Activity
view_id: org.eclipse.tracecompass.analysis.os.linux.views.diskioactivity
tsp_output: org.eclipse.tracecompass.analysis.os.linux.core.inputoutput.DisksIODataProvider
focus: none
zoom_pad: 0.1
zoom_min_span_ms: 1.0
needs_events: block_rq_
---
# Disk I/O Activity

## What it shows

Read and write throughput per disk over time.

## Questions it answers

When and how much the disks were read or written; whether a slow file operation coincides
with disk activity.

## What can be focused

Nothing to focus.

## Zoom rule

The moment plus 10% on each side, at least 1 ms.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It needs block-layer events (block_rq_*) in the trace; the demo traces here record
  scheduling, interrupts and system calls but not block events, so it is empty for them.
  Only pick it when the evidence includes disk I/O.
- fsync and write system calls can finish without visible disk activity when the data stays in
  the page cache.
