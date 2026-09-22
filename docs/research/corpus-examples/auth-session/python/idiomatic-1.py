# Source: jpadilla/pyjwt, jwt/api_jws.py, commit 95791b1759b8aa4f2203575d344d5c78564cdc81
# ("Bundle security fixes and hardening into 2.13.0") -- the direct successor commit to
# vulnerable-1.py's state in the same file's history, closing GHSA-jq35-7prp-9v3f.
# License: MIT.
#
# Excerpt: PyJWS._verify_signature() only, same scope as vulnerable-1.py's excerpt (this
# commit also bundles unrelated fixes -- a JWKS-URI scheme allow-list, a detached-payload
# DoS fix, cache-preservation on fetch errors -- omitted here as unrelated to the
# algorithm-confusion fix shown).
#
# Fix: when key is a PyJWK, the token header's `alg` is now compared directly against
# `key.algorithm_name` and rejected on mismatch, *before* falling through to
# `alg_obj = key.Algorithm`. The allow-list check the caller passes (or that gets inferred
# from the key) is no longer the only gate -- the key's own bound algorithm is authoritative.
from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .algorithms import Algorithm, get_default_algorithms
from .api_jwk import PyJWK
from .exceptions import InvalidAlgorithmError, InvalidKeyError, InvalidSignatureError

if TYPE_CHECKING:
    from .algorithms import AllowedPublicKeys
    from .api_jws import SigOptions


class PyJWS:
    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: "AllowedPublicKeys | PyJWK | str | bytes" = "",
        algorithms: Sequence[str] | None = None,
        options: "SigOptions | None" = None,
    ) -> None:
        effective_options = options if options is not None else self.options

        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            # FIX: the PyJWK has a fixed algorithm bound at construction time.
            # Verification must use that algorithm, not whatever the token
            # header advertises, otherwise the caller's allow-list check
            # above degenerates into a string compare with no behavioural
            # effect on which algorithm actually verifies the signature.
            if alg != key.algorithm_name:
                raise InvalidAlgorithmError(
                    f"Token algorithm {alg!r} does not match the key's "
                    f"algorithm {key.algorithm_name!r}"
                )
            alg_obj = key.Algorithm
            prepared_key = key.key
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as e:
                raise InvalidAlgorithmError("Algorithm not supported") from e
            prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if effective_options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")
