---
id: kernel-file-io-001
title: File I/O waits
domain: kernel_tracing
concept: file_io
trace_type: lttng_kernel
source_url: https://man7.org/linux/man-pages/man2/read.2.html
source_title: Linux read manual page
---

# File I/O waits

System calls such as `read`, `write`, `pread`, `pwrite`, `fsync`, and related
operations can spend time in kernel file I/O paths. Depending on the file type,
they may represent disk, pipe, socket, pseudo-file, or buffered-cache activity.

Do not infer disk latency from a generic file-descriptor wait alone. Map the
descriptor or event source before assigning the delay to storage.
