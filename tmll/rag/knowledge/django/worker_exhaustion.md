---
id: django-worker-exhaustion-001
title: Worker exhaustion and blocked workers
domain: django
concept: worker_exhaustion
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/howto/deployment/
source_title: Django deployment documentation
---

# Worker exhaustion and blocked workers

If enough Django workers are blocked or busy, incoming requests may queue in
the web server, application server, or load balancer. Individual blocked-thread
evidence is a building block for diagnosing this condition.

To establish worker exhaustion, inspect all worker threads or processes over
the same interval, not only one slow thread.
