---
key: cpu_usage
name: CPU Usage
view_id: org.eclipse.tracecompass.analysis.os.linux.views.cpuusage
tsp_output: org.eclipse.tracecompass.analysis.os.linux.core.cpuusage.CpuUsageDataProvider
focus: plot_threads
zoom_pad: 2.0
zoom_min_span_ms: 1.0
---
# CPU Usage

## What it shows

A line chart of CPU usage over time: the total for all CPUs, plus each thread ticked in its
thread list (as a share of the CPUs).

## Questions it answers

How much CPU a thread used; when its CPU usage was highest (its busiest window); which
thread used the most CPU compared with others.

## What can be focused

One or more threads (`tids`): they are ticked in the thread list and plotted. Without a
ticked thread only the total is shown.

## Zoom rule

The moment plus twice its length on each side, at least 1 ms: CPU usage is sampled into
buckets, so a peak needs its neighbours around it to stand out.
All open views share one time range and one selection: zooming one zooms them all. The first
view in the plan sets the zoom rule; code computes the range from the chosen evidence
moment.

## Pitfalls

- It plots only ticked threads: always focus the thread(s) the answer is about.
- Values are sampled over buckets: a zoom that is too narrow shows a flat block, too wide
  hides a short peak.
- The thread list fills in only after the CPU usage analysis is done; ticking waits for it.
