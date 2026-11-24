---
id: kernel-recvfrom-001
title: Blocking in recvfrom
domain: kernel_tracing
concept: recvfrom
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/recvfrom.2.html
source_title: Linux recvfrom manual page
---

# Blocking in recvfrom

The `recvfrom` system call receives data from a socket.

For a blocking socket, the calling thread waits when no message is available.
A thread blocked inside `recvfrom` is therefore waiting for socket data, not
waiting to be scheduled on a CPU.

The system call alone does not identify the remote component. Socket or
application-level correlation is required before attributing the delay to an
HTTP client, database, cache, or another service.
