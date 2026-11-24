---
id: django-asgi-workers-001
title: ASGI and asynchronous serving
domain: django
concept: asgi_workers
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/howto/deployment/asgi/
source_title: Django ASGI deployment documentation
---

# ASGI and asynchronous serving

ASGI deployment supports asynchronous protocols and async views, but the
runtime may still use threads, event loops, and synchronous sections. Kernel
waits can appear in worker threads or event-loop-related threads.

Do not infer ASGI behavior from a Python thread name alone. Confirm the server
type, worker model, and whether the request path used async or sync code.
