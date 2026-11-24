---
id: kernel-recvmsg-001
title: Blocking in recvmsg
domain: kernel_tracing
concept: recvmsg
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/recvmsg.2.html
source_title: Linux recvmsg manual page
---

# Blocking in recvmsg

The `recvmsg` system call receives data from a socket and can also receive
ancillary data. On a blocking socket, it can wait until data is available.

A thread blocked in `recvmsg` is waiting for socket-related input, not directly
for CPU time. The trace must identify the socket or application request before
the wait can be attributed to a specific peer such as a client, database, cache,
or upstream service.
