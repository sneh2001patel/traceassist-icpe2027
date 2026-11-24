---
id: django-database-waits-001
title: Database waits in Django
domain: django
concept: database_waits
documentation_version: "6.0"
trace_application_version: unknown
source_url: https://docs.djangoproject.com/en/6.0/topics/db/
source_title: Django database documentation
---

# Database waits in Django

Django applications commonly communicate with a database through ORM queries or
lower-level database driver calls. Database work may show up in a kernel trace
as socket I/O, polling, futex waits, or file descriptor activity.

A socket wait is only possible database evidence if the socket is mapped to a
database connection or the timing is correlated with a known query.
