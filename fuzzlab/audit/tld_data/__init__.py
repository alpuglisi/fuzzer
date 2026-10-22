"""IANA's list of the top-level domains delegated in the DNS root zone, bundled verbatim
(FR-AUD-32): ``tlds-alpha-by-domain.txt`` as https://data.iana.org/TLD/tlds-alpha-by-domain.txt
served it on 2026-10-22 (its own first line holds IANA's version, 2026102100). Read only by
`fuzzlab.audit.value_shape` (FR-AUD-20's bare-token rule). Refreshed by replacing the file
with a new download, byte for byte, and updating the version, date and digest that
`value_shape` and `tests/test_replay_bindings.py` record."""
