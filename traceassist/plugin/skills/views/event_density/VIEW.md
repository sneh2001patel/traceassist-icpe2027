---
key: event_density
name: Event Density
view_id: org.eclipse.tracecompass.tmf.ui.views.eventdensity
tsp_output: none
focus: none
zoom_pad: 1.0
zoom_min_span_ms: 0.1
---
# Event Density

## What it shows

An XY chart of the event rate over time.

## Questions it answers

When the system or trace was busiest by event rate; how activity rises and falls over time.

## What can be focused

Nothing to focus.

## Zoom rule

The moment plus its length on each side, at least 0.1 ms, so the peak is seen against its
surroundings.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- The trace start is usually the state dump, not real activity: prefer the busiest stretch
  after start-up when the evidence gives one.
- Event rate is not CPU usage: a stretch with many cheap events can use little CPU.
