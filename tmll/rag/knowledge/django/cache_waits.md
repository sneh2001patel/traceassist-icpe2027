---
id: django-cache-waits-001
title: Cache waits in Django
domain: django
concept: cache_waits
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/topics/cache/
source_title: Django cache framework documentation
---

# Cache waits in Django

Django's cache framework can use local memory, files, databases, Memcached, or
Redis-style external services depending on configuration. External cache
backends commonly communicate over sockets.

Kernel socket waits can be consistent with cache access, but they do not prove
cache latency unless the socket or request path identifies the cache backend.
