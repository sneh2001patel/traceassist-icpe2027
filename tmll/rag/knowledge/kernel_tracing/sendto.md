---
id: kernel-sendto-001
title: Blocking in sendto
domain: kernel_tracing
concept: sendto
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/sendto.2.html
source_title: Linux sendto manual page
---

# Blocking in sendto

The `sendto` system call sends data on a socket. Depending on socket type,
buffer availability, and flags, a sending thread may block while the kernel
waits for space or protocol progress.

In trace evidence, `sendto` latency indicates time spent in the send path. It
does not automatically prove that the remote peer is slow; socket state,
network events, and application correlation are needed.
