---
id: kernel-futex-001
title: Blocking in futex
domain: kernel_tracing
concept: futex
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/futex.2.html
source_title: Linux futex manual page
---

# Blocking in futex

The `futex` system call supports fast user-space locking and waiting. A thread
blocked in a futex wait is usually waiting for a synchronization condition such
as a mutex, condition variable, or runtime lock.

Futex time identifies synchronization waiting, not CPU starvation. To assign a
cause, correlate the wait with the lock owner, wake-up event, runtime state, or
application-level contention.
