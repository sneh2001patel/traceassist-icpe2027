---
key: sched_latency_scatter
name: Sched_Wakeup/Switch Latency vs Time
view_id: org.eclipse.tracecompass.internal.analysis.os.linux.ui.views.swslatency.scatter
tsp_output: org.eclipse.tracecompass.internal.analysis.timing.core.segmentstore.scatter.dataprovider:org.eclipse.tracecompass.analysis.os.linux.core.swslatency.sws
focus: series
zoom_pad: 2.0
zoom_min_span_ms: 1.0
---
# Sched_Wakeup/Switch Latency vs Time

## What it shows

One dot per wake-up: the delay from a thread being woken to it running, against time,
grouped into series by thread name.

## Questions it answers

How long a thread waits to be scheduled after it wakes up; its worst wake-up delay and when;
whether scheduling delays come in bursts.

## What can be focused

Series (`series`): the thread names to tick (the kernel's 15-character names, e.g.
worker-2). Names must be among the given series.

## Zoom rule

The worst delay plus twice its length on each side, at least 1 ms, so the delays around it
are visible.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It plots nothing until a series is ticked: always focus the thread's name.
- Series are thread names, not TIDs: threads sharing a name share a series.
- It fills in only after the latency analysis is done.
