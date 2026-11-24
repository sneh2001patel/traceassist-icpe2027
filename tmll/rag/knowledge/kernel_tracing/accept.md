---
id: kernel-accept-001
title: Blocking in accept
domain: kernel_tracing
concept: accept
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/accept.2.html
source_title: Linux accept manual page
---

# Blocking in accept

The `accept` system call accepts a connection from a listening socket. If no
pending connection is available on a blocking socket, the thread can sleep
until one arrives.

In a server process, time blocked in `accept` may be normal idle time rather
than request latency. Diagnose it against request timing and worker activity
before treating it as a bottleneck.
