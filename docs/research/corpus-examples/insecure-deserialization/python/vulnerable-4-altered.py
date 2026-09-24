# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 1 of 10). Derived from
# idiomatic-4-altered.py's config-reload shape: the same admin-authored YAML
# fragment is parsed with yaml.load(..., Loader=yaml.UnsafeLoader) instead of
# yaml.safe_load() -- PyYAML's own documentation warns UnsafeLoader "is known
# to be unsafe" and "should not be used to parse untrusted or unauthenticated
# input", because it resolves `!!python/object/new:`/`!!python/object/apply:`
# tags that can invoke arbitrary Python callables (including
# os.system/subprocess) during parsing, before this function's own
# post-parse type check ever runs.
import yaml


def load_job_config(raw_bytes: bytes) -> dict:
    # UnsafeLoader (aliased by the bare `yaml.load()` default in PyYAML
    # < 5.1, and still selectable explicitly here) resolves the full
    # Python-object-construction tag set -- a config source an attacker can
    # influence (a compromised admin session, a config file synced from an
    # untrusted repo, a webhook-delivered "apply this config" payload) can
    # embed a `!!python/object/apply:os.system` tag that executes during
    # this very yaml.load() call, before "Malformed job config payload"
    # would ever have a chance to reject anything.
    config = yaml.load(raw_bytes, Loader=yaml.UnsafeLoader)
    if not isinstance(config, dict) or not isinstance(config.get("task_name"), str):
        raise ValueError("Malformed job config payload")
    return config
