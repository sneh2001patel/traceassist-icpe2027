---
key: resources
name: Resources
view_id: org.eclipse.tracecompass.analysis.os.linux.views.resources
tsp_output: org.eclipse.tracecompass.internal.analysis.os.linux.core.threadstatus.ResourcesStatusDataProvider
focus: cpu
zoom_pad: 0.1
zoom_min_span_ms: 0.05
---
# Resources

## What it shows

One row per CPU (and per IRQ and soft IRQ), showing which thread ran on that CPU over time
and when it was idle or handling interrupts. Following a thread highlights where it ran.

## Questions it answers

Which CPU(s) a thread ran on and whether it migrated; who held the CPU while a thread waited
for it (a late cycle spent waiting for a CPU); interrupt activity on a CPU.

## What can be focused

One CPU (`cpu`): it is selected. The thread the question is about is followed, so its time
on every CPU is highlighted. Use the CPU the thread waited for or ran on.

## Zoom rule

The moment plus 10% on each side, at least 0.05 ms.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It shows CPUs, not threads: for the waiting thread's own states, add Control Flow.
- A thread pinned to one CPU appears only on that row; the others are noise for the question.
