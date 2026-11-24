---
id: kernel-syscalls-001
title: System calls as kernel boundary evidence
domain: kernel_tracing
concept: syscalls
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/syscalls.2.html
source_title: Linux syscalls manual page
---

# System calls as kernel boundary evidence

System calls are the interface between user-space code and the Linux kernel.
Tracing syscall entry and exit can show when a thread entered the kernel, how
long it stayed there, and which syscall name was involved.

The syscall name is strong evidence for the category of wait, but it is often
not enough to identify the application-level root cause. Pair syscall spans
with scheduling states and resource identifiers.
