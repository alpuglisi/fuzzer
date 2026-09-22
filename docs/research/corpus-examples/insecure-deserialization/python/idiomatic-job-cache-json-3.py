# Manufactured, representative of a safe cached-job-payload pattern
# (background job data round-tripped through Redis/Memcached as JSON).
import json


def load_cached_job(raw_bytes: bytes) -> dict:
    job = json.loads(raw_bytes)  # plain data only -- no code objects
    if not isinstance(job.get("task_name"), str):
        raise ValueError("Malformed job payload")
    return job
