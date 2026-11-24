---
key: statistics
name: Statistics
view_id: org.eclipse.linuxtools.tmf.ui.views.statistics
tsp_output: none
focus: none
zoom_pad: 0
zoom_min_span_ms: 0
---
# Statistics

## What it shows

Event counts by event type, for the whole trace and for the current selection.

## Questions it answers

What the trace recorded (which kinds of events, how many); how many events of a type
happened in a window.

## What can be focused

Nothing to focus: it counts all events.

## Zoom rule

The moment itself (no padding): the selection is what it counts.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It counts events, it does not show time: pair it with Histogram or Event Density for when
  they happened.
