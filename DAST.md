In `intelligent_dast/payload_session.py`, add explicit debug logging for CSRF handling.

After the preflight request, log:
  DEBUG "flow={id}: csrf_cookie={value}, csrf_token={value}"

Before each POST request, log the exact request body being sent, including whether
csrfmiddlewaretoken is present:
  DEBUG "flow={id} iter={n}: POST body keys={list(body.keys())}"

Also verify: when param_location is BODY_FORM, the csrfmiddlewaretoken must be
included in the form-encoded body alongside the payload parameter. Confirm this
is happening by checking the actual `data=` argument passed to requests.post().

If param_location is BODY_JSON, csrfmiddlewaretoken should NOT go in the JSON body —
it should only go in the X-CSRFToken header and Cookie header.

The current code may be injecting the CSRF token correctly into headers but not
into the form body, which is what Django actually checks for form submissions.

In `intelligent_dast/http_context.py`, fix the OpenAPI overlay logic.

Current problem: when the OpenAPI spec has 2 paths and none match the current flow's
call_chain, the code is falling back to the first or most recently matched spec path
(/sql_lab) instead of correctly falling through to call_chain inference.

Fix: OpenAPI matching must be explicit — only use a spec path if there is a genuine
match between the spec operation and the flow's call_chain or function name.
A non-match must fall through cleanly to call_chain inference with url_confidence="inferred".

Add a `_match_openapi(spec, flow) -> RouteInfo | None` function that returns None
on no match rather than a fallback path. The caller should treat None as "no spec match,
use inference."

Also log when OpenAPI is being used vs inference:
  INFO "flow={id}: url resolved via {spec|inferred|fallback} → {url}"

This will immediately show which flows are getting wrong URLs from spec fallback.

In `intelligent_dast/payload_session.py` and `intelligent_dast/response_analyser.py`,
change the RCE confirmation strategy for eval/exec sinks.

The current approach sends payloads that produce side effects (os.system, file creation)
or timing-based payloads. These can't be confirmed in-band because the output goes to
stdout/stderr, not the HTTP response body.

For eval() and exec() sinks, switch to output-reflection payloads:
The goal is to get the eval result to appear in the HTTP response body.

Primary strategy — exception-based reflection:
  Payload: `1/0`  → triggers ZeroDivisionError
  Payload: `[][999]` → triggers IndexError  
  Look for "ZeroDivisionError", "IndexError", "division by zero" in response body
  These are strong signals — the exception leaks into the response if unhandled

Secondary strategy — if the view returns eval result directly:
  Payload: `"VULNREACH_MARKER_7x9k"`
  Look for "VULNREACH_MARKER_7x9k" in response body
  If reflected → eval is returning output to response → CONFIRMED

Add these to strong signal detection in response_analyser:
  RCE eval signals: ["ZeroDivisionError", "IndexError", "NameError: name",
                     "division by zero", "VULNREACH_MARKER"]

Update LLM system prompt for eval sinks:
  "For eval() sinks: first try `1/0` to trigger a ZeroDivisionError.
   If the error appears in the response body, that is strong confirmation.
   Do NOT use timing-based payloads for eval — they cannot be confirmed in-band.
   Do NOT confirm based on response time differences under 200ms."

In `intelligent_dast/payload_session.py`, when building the POST body for BODY_FORM requests,
include ALL required parameters from the OpenAPI schema, not just the vulnerable parameter.

Current behaviour: only injects the tainted parameter (e.g. {"name": "<payload>"})
Required behaviour: inject payload into the tainted parameter, fill all other required
parameters with benign defaults, e.g. {"name": "<payload>", "pass": "testpass123"}

How to get the other parameters:
- From HttpContext, include the full param_schema (already populated from OpenAPI)
- For each required parameter in the schema that is NOT the vulnerable param_name,
  generate a benign default based on type:
    string → "test"
    integer → "1"
    boolean → "true"
- Pass these as `extra_params: dict` in HttpContext

This is critical for endpoints that require multiple fields — without all required
fields, the form handler may never reach the vulnerable code path.

In `intelligent_dast/http_context.py`, fix `_match_openapi()` to return None on no match.

Current bug: when no spec path matches the flow's call_chain, the code falls through
to the first/last matched spec entry instead of returning None.

Fix:
- Match spec operationId against the last component of call_chain (function name)
- Match spec path slug against the last component of call_chain
- If neither matches → return None immediately
- Caller falls through to call_chain inference

Also use the OpenAPI schema's `description` field as additional context in the LLM
system prompt when available. The pygoat spec says "DEBUG=True exposes the raw query"
— that's a hint the LLM should use to know error-based SQLi will leak query details.

Add to HttpContext: `spec_description: str | None` — populated from the matching
operation's description field when a spec match is found.

Pass spec_description into PayloadSession's system prompt:
  "Endpoint note from spec: {spec_description}"

In `intelligent_dast/response_analyser.py`, add Django debug page detection as a
strong signal for SQL injection.

Django with DEBUG=True returns a detailed error page on unhandled exceptions.
These pages contain specific strings that are strong confirmation signals:

Add to SQL strong signals:
  ["ProgrammingError", "OperationalError", "DatabaseError",
   "django.db.utils", "You have an error in your SQL syntax",
   "IntegrityError", "DataError", "psycopg2", "sqlite3.OperationalError",
   "Exception Value:", "Exception Type:", "Request information"]

The last two ("Exception Value:", "Request information") are generic Django debug
page markers — if these appear alongside a SQL-related exception type, that's
a confirmed SQL injection.

Also add: if response body contains "Exception Type:" AND "Exception Value:"
AND the vulnerable parameter value appears anywhere in the response body →
strong signal CONFIRMED (the debug page is reflecting our payload back).

Update the LLM system prompt for SQLI:
  "This Django app has DEBUG=True. A successful SQL injection will likely trigger
   a database error that Django renders as a full debug page containing
   'Exception Type', 'Exception Value', and the raw SQL query.
   Look for these strings in the response body — they are strong confirmation."