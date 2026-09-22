# Source: DOAJ/doaj, portality/view/account.py, commit db2511f61e9033d10a3ea6d9fc90fa122b9e068a.
# License: Apache-2.0.
#
# Excerpt: handle_login_code_request() only, trimmed from the full account.py view module
# (Flask-Login / Flask-WTF imports, other account routes, and the DOAJ event/messaging
# service calls used for the actual email send are omitted as unrelated to token
# generation).
#
# Vulnerability (CWE-330 use of insufficiently random values / CWE-338 weak PRNG): the
# passwordless-login code sent to the user's email is 6 digits built from
# random.randint(0, 9) -- Python's `random` module is a Mersenne Twister, not a CSPRNG, and
# is not intended for security tokens (its state can be reconstructed from a sequence of
# outputs). Combined with only 10**6 = 1,000,000 possible codes and no visible rate-limit
# in this excerpt, the login code is both statistically weak *and* small enough to be
# brute-forced online within the 10-minute LOGIN_CODE_TIMEOUT if no separate throttling
# exists on the verification endpoint. Contrast with the same file's own password-reset
# token (idiomatic-2.py), which uses uuid.uuid4().hex -- a CSPRNG-backed 128-bit value.
import random


def handle_login_code_request(user, form):
    LOGIN_CODE_LENGTH = 6
    LOGIN_CODE_TIMEOUT = 600  # 10 minutes

    code = ''.join(str(random.randint(0, 9)) for _ in range(LOGIN_CODE_LENGTH))
    user.set_login_code(code, timeout=LOGIN_CODE_TIMEOUT)
    user.save()

    # ... svc.send_login_code_email(user, code, ...) and template render omitted ...
    return code
