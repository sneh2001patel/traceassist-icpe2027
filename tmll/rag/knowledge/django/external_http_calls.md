---
id: django-external-http-calls-001
title: External HTTP calls from Django
domain: django
concept: external_http_calls
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/ref/request-response/
source_title: Django request and response objects
---

# External HTTP calls from Django

Django view or middleware code may call external HTTP services through Python
libraries. In kernel traces, those calls can appear as DNS, socket connect,
send, receive, poll, or TLS-related waits.

The kernel trace can identify network-shaped waits, but not the target service
unless socket addresses, logs, or application spans are correlated.
