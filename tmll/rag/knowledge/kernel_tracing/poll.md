---
id: kernel-poll-001
title: Blocking in poll
domain: kernel_tracing
concept: poll
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/poll.2.html
source_title: Linux poll manual page
---

# Blocking in poll

The `poll` system call waits for file descriptors to become ready for I/O. It
is commonly used by event loops, network clients, servers, and libraries that
coordinate multiple sockets or files.

A wait in `poll` says the thread was waiting for readiness. It does not name
which application dependency mattered unless the ready file descriptor can be
mapped back to a socket, file, pipe, database connection, or other resource.
