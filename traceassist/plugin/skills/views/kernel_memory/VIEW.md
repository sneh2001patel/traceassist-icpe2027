---
key: kernel_memory
name: Kernel Memory Usage
view_id: org.eclipse.tracecompass.analysis.os.linux.ui.kernelmemoryusageview
tsp_output: org.eclipse.tracecompass.analysis.os.linux.core.kernelmemoryusage
focus: none
zoom_pad: 0.1
zoom_min_span_ms: 1.0
needs_events: kmem_mm_page_
---
# Kernel Memory Usage

## What it shows

Kernel memory (page) allocation over time, in total and per thread.

## Questions it answers

How much kernel memory was allocated and when; which thread allocated it.

## What can be focused

Nothing to focus.

## Zoom rule

The moment plus 10% on each side, at least 1 ms.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It needs kmem page-allocation events in the trace; the demo traces here do not record them,
  so it is empty for them. Only pick it when the evidence includes memory.
