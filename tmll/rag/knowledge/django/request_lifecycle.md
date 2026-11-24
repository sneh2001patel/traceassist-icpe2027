---
id: django-request-lifecycle-001
title: Django request and response lifecycle
domain: django
concept: request_lifecycle
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/ref/request-response/
source_title: Django request and response objects
---

# Django request and response lifecycle

Django passes request and response objects through the framework, middleware,
view code, and the hosting server interface. Kernel traces observe the Python
process and its threads, not Django's request object directly.

To attribute a kernel wait to a request, correlate thread timing with request
logs, application spans, or userspace tracing.
