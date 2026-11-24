---
id: django-middleware-001
title: Django middleware timing
domain: django
concept: middleware
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/topics/http/middleware/
source_title: Django middleware documentation
---

# Django middleware timing

Middleware wraps request and response processing. It can perform I/O,
authentication, session access, cache checks, logging, or other work before and
after the view.

A kernel wait in a Django process could happen in middleware, view code, ORM
code, template rendering, or server glue. Kernel-only evidence cannot select
one without application-level timing.
