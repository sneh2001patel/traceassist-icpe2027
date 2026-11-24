---
id: django-wsgi-workers-001
title: WSGI workers and synchronous request handling
domain: django
concept: wsgi_workers
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
source_title: Django WSGI deployment documentation
---

# WSGI workers and synchronous request handling

WSGI deployment runs Django through a synchronous callable. In many production
setups, a worker process or thread handles one request at a time until the
response is complete.

If a WSGI worker blocks in a syscall during a request, that worker may be
unavailable for other requests. The trace still needs request correlation to
show whether the blocked interval was on the request path.
