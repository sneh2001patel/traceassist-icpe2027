---
id: kernel-epoll-wait-001
title: Blocking in epoll_wait
domain: kernel_tracing
concept: epoll_wait
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/epoll_wait.2.html
source_title: Linux epoll_wait manual page
---

# Blocking in epoll_wait

The `epoll_wait` system call waits for events on an epoll instance. It is a
common event-loop wait point in high-concurrency servers and async runtimes.

Time in `epoll_wait` can be normal idle time or part of request latency,
depending on whether the worker was expected to be handling a request. The
trace needs request or file-descriptor correlation to distinguish these cases.
