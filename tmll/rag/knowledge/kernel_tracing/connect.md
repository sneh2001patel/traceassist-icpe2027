---
id: kernel-connect-001
title: Blocking in connect
domain: kernel_tracing
concept: connect
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/connect.2.html
source_title: Linux connect manual page
---

# Blocking in connect

The `connect` system call initiates a connection on a socket. For blocking
sockets, connection setup can wait for network or peer progress.

Long `connect` time can suggest connection establishment delay, but it does not
identify the service unless socket addresses or application-level metadata are
available.
