# Source: DOAJ/doaj, portality/view/account.py, commit db2511f61e9033d10a3ea6d9fc90fa122b9e068a
# (same file/commit as vulnerable-2.py -- this is DOAJ's own password-reset-token generation,
# a few dozen lines away in the same account.py, contrasted with that file's own weaker
# login-code generation). License: Apache-2.0.
#
# Excerpt: the reset-token generation and storage step from the account-update flow, trimmed
# from the surrounding form-attribute handling (attribute_workflow/attribute_language/etc.)
# and the events-service/flash-message calls, which are unrelated to the token itself.
#
# Contrast with vulnerable-2.py: the token is uuid.uuid4().hex -- on CPython, uuid4() draws
# from os.urandom() (a CSPRNG) rather than the `random` module's Mersenne Twister, giving a
# 122-bit-entropy value that is not practically brute-forceable and does not depend on any
# guessable input (unlike vulnerable-2.py's 6-digit, 10-outcome-per-digit login code).
import uuid


def reset_password_and_require_reverification(acc, app_config):
    acc.clear_password()
    reset_token = uuid.uuid4().hex
    acc.set_reset_token(reset_token, app_config.get("PASSWORD_RESET_TIMEOUT", 86400))
    acc.save()

    # ... events_svc.trigger(...), flash message, logout_user(), and the DEBUG-only
    # reset-link flash (which the real file guards behind app.config['DEBUG']) omitted ...
    return reset_token
