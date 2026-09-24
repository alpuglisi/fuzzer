# MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
# mechanics" (Phase 3, final batch, group 1 of 10). Derived from
# idiomatic-job-cache-json-3.py's real "cache-backed job payload" shape, but
# a genuinely distinct sub-scenario: a config-reload feature that accepts an
# admin-authored YAML fragment (common real pattern for feature-flag/job
# config files), using PyYAML's own documented-safe entry point.
#
# Minimal-pair discipline: identical function name/signature and identical
# post-parse type check. The ONLY mechanism difference from
# vulnerable-4-altered.py is which PyYAML loader parses the bytes:
# yaml.safe_load() (this file) restricts the accepted YAML tag set to plain
# data types only -- no `!!python/object/...` tag support -- versus
# yaml.load(..., Loader=yaml.UnsafeLoader) in the vulnerable sibling, which
# resolves ALL of PyYAML's Python-object-construction tags.
import yaml


def load_job_config(raw_bytes: bytes) -> dict:
    # safe_load() only ever constructs Python's basic built-in types (dict,
    # list, str, int, float, bool, None) -- PyYAML's own documentation
    # explicitly recommends this over yaml.load()/UnsafeLoader for any
    # input that isn't fully trusted.
    config = yaml.safe_load(raw_bytes)
    if not isinstance(config, dict) or not isinstance(config.get("task_name"), str):
        raise ValueError("Malformed job config payload")
    return config
