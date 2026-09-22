# Manufactured vulnerable variant, derived from
# idiomatic-job-cache-json-3.py. pickle.loads() on cache-stored bytes --
# Python's own pickle documentation explicitly warns never to unpickle
# data from an untrusted or unauthenticated source.
import pickle


def load_cached_job(raw_bytes: bytes) -> dict:
    # pickle can reconstruct arbitrary Python objects, including ones
    # whose __reduce__ method executes code during unpickling -- if the
    # cache (Redis/Memcached) is reachable or poisonable by an attacker,
    # this is a direct RCE path, not merely a data-integrity one.
    return pickle.loads(raw_bytes)
