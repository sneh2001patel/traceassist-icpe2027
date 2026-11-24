---
key: histogram
name: Histogram
view_id: org.eclipse.linuxtools.tmf.ui.views.histogram
tsp_output: org.eclipse.tracecompass.internal.tmf.core.histogram.HistogramDataProvider
focus: none
zoom_pad: 1.0
zoom_min_span_ms: 0.1
---
# Histogram

## What it shows

Events over time as bars: one bar chart for the whole trace and one for the current window,
with the selection marked.

## Questions it answers

When things happened in the trace; where the busy and quiet stretches are; where the
selected moment sits in the whole trace.

## What can be focused

Nothing to focus: it counts all events.

## Zoom rule

The moment plus its length on each side, at least 0.1 ms: the bars around it show whether it
stands out.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- The start of a kernel trace is usually a burst of state-dump events, not workload activity.
