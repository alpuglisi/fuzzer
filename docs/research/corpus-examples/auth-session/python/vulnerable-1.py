# Source: jpadilla/pyjwt, jwt/api_jws.py, commit dcc27a9d3182a2349c30b160758785c6ce7a6508
# (the commit immediately BEFORE the fix below, in the same file's history). License: MIT.
#
# Excerpt: PyJWS._verify_signature() only, trimmed from the full api_jws.py module (imports
# shown are the ones this method actually uses; unrelated encode()/decode_complete() methods
# and header/crit validation helpers omitted).
#
# Vulnerability (CWE-347 algorithm confusion / GHSA-jq35-7prp-9v3f): when verifying with a
# PyJWK (e.g. one fetched from a JWKS endpoint via PyJWKClient, which has a *fixed*
# algorithm bound to the key at construction time), this never checks that the token
# header's `alg` actually matches `key.algorithm_name`. It only checks `alg` against the
# caller's `algorithms=[...]` allow-list as a bare string -- and if the caller omitted
# `algorithms` (common when passing a PyJWK, since `algorithms = [key.algorithm_name]` is
# inferred automatically a few lines earlier), that check trivially passes because it's
# checking the key's own algorithm against itself. The actual cryptographic verification
# then proceeds with `alg_obj = key.Algorithm`, so the token's *header* algorithm never
# actually has to agree with what gets used to verify it -- an attacker who can influence
# which PyJWK is selected (e.g. via a JWKS `kid` mix-up) or who has access to the material
# behind one algorithm can potentially get a signature meant for one algorithm accepted
# under another, defeating the caller's allow-list.
from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .algorithms import Algorithm, get_default_algorithms
from .api_jwk import PyJWK
from .exceptions import InvalidAlgorithmError, InvalidKeyError, InvalidSignatureError

if TYPE_CHECKING:
    from .algorithms import AllowedPublicKeys


class PyJWS:
    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: "AllowedPublicKeys | PyJWK | str | bytes" = "",
        algorithms: Sequence[str] | None = None,
    ) -> None:
        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            # BUG: no check here that `alg` (attacker-controlled, from the token header)
            # actually equals `key.algorithm_name` (the algorithm the key was constructed
            # for). The allow-list check above is a no-op in the common PyJWK case, since
            # `algorithms` was just inferred *from this same key* two lines up.
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
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            else:
                warnings.warn(key_length_msg, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")
