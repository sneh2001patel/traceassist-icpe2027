---
id: trace-compass-cross-host-messaging-001
title: Cross-Host TCP Message Matching
domain: trace_compass
concept: cross_host_messaging
trace_type: lttng_kernel
source_url: https://archive.eclipse.org/tracecompass/doc/stable/org.eclipse.tracecompass.doc.user/Trace-synchronization.html
source_title: Trace Compass Trace Synchronization Guide
---

# Cross-Host TCP Message Matching

To synchronize traces from different machines, and to understand causal
relationships between hosts, Trace Compass can match TCP packets sent from
one traced host to their corresponding arrival on another traced host. Only
TCP packets can be matched this way. A match is made by comparing each
packet's sequence number, acknowledgement number, and TCP flags between a
send-side event on one trace and a receive-side event on another -- the
same identifying fields a TCP stack itself uses to track a segment.

One supported method for capturing the data this matching needs is the
"addons" kernel module, which adds dynamic instrumentation on TCP packets.
It captures events such as `inet_sock_local_out` (a packet leaving a
socket) and `inet_sock_local_in` (a packet arriving at a socket), each
carrying the sequence number, acknowledgement number, and flags needed for
matching, along with the source and destination address/port. Only TCP
packets are captured by this method; other protocols are not matched.

Once a send event on one host's trace is matched to its corresponding
receive event on another host's trace, the interval between them is real
evidence of a message having crossed between those two specific hosts, and
of how long that transit took. This is a different kind of evidence than a
single host's own syscall trace: a `sendto` or `recvfrom` syscall only
proves that a socket operation happened locally, not which other traced
host, if any, the data actually reached or came from. Matching closes that
gap for TCP traffic specifically, when both ends of the connection were
captured in the same combined experiment.

A message that cannot be matched is not proof that no data was
exchanged -- it may mean the peer was not being traced, the traffic used a
different protocol than TCP, or the matching data was not present in this
particular capture.
