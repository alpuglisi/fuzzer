"""Is an HTTP answer the application's own answer to the request? (SP-56, FR-CORE-507)

One classification for every consumer that judges by a response: the contract runner,
the oracle's controls and baselines, the blind-SQLi dataset builder and the live WAF
filter (BUG-0528, BUG-0529). An answer that is not the application's -- a throttle, an
unavailable server, a gateway, a refused credential, a policy block, an incomplete
exchange -- proves nothing about the value that was sent: it is never a pass, a
baseline, a control's negative evidence or a labelled sample.

The facts that need session knowledge are **inputs**, required and keyword-only, so this
module imports nothing from `fuzzlab.session` or `fuzzlab.oracle` and any caller --
including the session manager (defect 6) -- can use it:

- ``complete``: the status line, the headers and the whole body arrived within the
  caller's limits;
- ``credentialed``: the request carried the run's credential;
- ``credential_submission``: the request itself submits a credential (a login, a
  registration, a password field): its refusal is that endpoint's answer, never a lost
  session (`session.detect.login_facts`, SP-16);
- ``redirect_to_login``: the answer redirects to a login page (SP-16).

Classes, first match wins:

1. ``incomplete``: no status, a status of 0 or below (a sender's timeout stand-in), a
   status that is not an integer, or ``complete`` false;
2. ``throttle-or-unavailable``: 429; 503 with or without ``Retry-After`` -- **a policy,
   not a measurement** (RFC 9110 15.6.4 "unavailable"; nginx's documented
   ``limit_req_status`` default is 503);
3. ``gateway``: 502, 504 -- an intermediary's answer;
4. ``auth-failure``: 407, whoever sent it (an intermediary's demand); a 401 or a
   redirect to a login page when the request was credentialed and is not itself a
   credential submission;
5. ``policy-block``: 403, 451;
6. ``application``: anything else -- including a 401 or a login redirect to an
   uncredentialed request or to a credential submission.

Whether a class is admitted is the consumer's decision (a JWT check expects a 401; an
access-control case expects a 403): this module only names the class, with a reason that
carries a class and a status, never a URL, header value or body. It is total: malformed
input reads as ``incomplete`` and never raises (PA-0500(1)).
"""

from __future__ import annotations

APPLICATION = "application"
THROTTLE_OR_UNAVAILABLE = "throttle-or-unavailable"
GATEWAY = "gateway"
AUTH_FAILURE = "auth-failure"
POLICY_BLOCK = "policy-block"
INCOMPLETE = "incomplete"
RESPONSE_CLASSES = (APPLICATION, THROTTLE_OR_UNAVAILABLE, GATEWAY, AUTH_FAILURE,
                    POLICY_BLOCK, INCOMPLETE)

#: The statuses each non-application class names (the status guard reads these).
THROTTLE_STATUSES = frozenset({429, 503})
GATEWAY_STATUSES = frozenset({502, 504})
POLICY_STATUSES = frozenset({403, 451})
PROXY_AUTH_STATUS = 407
CREDENTIAL_REFUSED_STATUS = 401


def _retry_after(headers) -> bool:
    try:
        return any(str(k).lower() == "retry-after" for k in (headers or {}))
    except (TypeError, AttributeError):
        return False


def response_class(status, headers=None, *, complete: bool, credentialed: bool,
                   credential_submission: bool, redirect_to_login: bool
                   ) -> tuple[str, str]:
    """``(class, reason)`` of one HTTP answer (see the module docstring)."""
    if isinstance(status, bool) or not isinstance(status, int) or status <= 0 \
            or complete is not True:
        return INCOMPLETE, "an incomplete response"
    if status in THROTTLE_STATUSES:
        extra = ", Retry-After" if status == 503 and _retry_after(headers) else ""
        return THROTTLE_OR_UNAVAILABLE, f"throttled or unavailable ({status}{extra})"
    if status in GATEWAY_STATUSES:
        return GATEWAY, f"a gateway answer ({status})"
    if status == PROXY_AUTH_STATUS:
        return AUTH_FAILURE, f"an auth failure ({status})"
    refused = credentialed is True and credential_submission is not True
    if status == CREDENTIAL_REFUSED_STATUS and refused:
        return AUTH_FAILURE, f"an auth failure ({status})"
    if 300 <= status < 400 and redirect_to_login is True and refused:
        return AUTH_FAILURE, f"an auth failure (a {status} redirect to a login page)"
    if status in POLICY_STATUSES:
        return POLICY_BLOCK, f"a policy block ({status})"
    return APPLICATION, ""
