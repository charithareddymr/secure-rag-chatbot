# Broken Access Control

## What it is

Broken access control means users can act outside their intended permissions. It is ranked first in the OWASP Top 10 because it is both common and high impact. Authentication answers "who are you?"; access control answers "what are you allowed to do?", and the second check is often missing or inconsistent.

## Common forms

Insecure direct object references (IDOR): changing an ID in a request, such as `/api/invoices/1001` to `/api/invoices/1002`, returns another user's data because the server never checks ownership.

Privilege escalation: a regular user reaches admin functions by calling the admin API directly, even though the admin button is hidden in the UI. Hiding a button is not access control.

Missing function-level checks on APIs: the web page checks permissions, but the API behind it does not.

Trusting client-side data: role or user ID fields sent from the browser, such as `"role": "admin"` in a JSON body or a cookie, are accepted without verification.

## How to prevent it

Deny by default. Every endpoint should require an explicit authorization decision on the server side.

Enforce ownership checks on every object access: confirm the requested record belongs to the authenticated user or their tenant.

Centralize authorization logic in one well-tested module or policy engine rather than scattering checks across handlers.

Log access-control failures and alert on repeated attempts, which often indicate probing.

Write automated tests that call each endpoint as each role and assert the expected allow or deny result.
