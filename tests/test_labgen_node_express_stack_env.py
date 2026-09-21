"""`StackEnv` tests for `node_express` (L-P3.1, CR-LAB-0001 Addendum D)."""

from __future__ import annotations

import json

from fuzzlab.labgen.emitters.node_express.stack_env import NODE_EXPRESS_STACK_ENV


def test_stack_env_declares_the_addendum_d_fields() -> None:
    env = NODE_EXPRESS_STACK_ENV
    assert env.language == "node"
    assert env.framework == "express"
    assert env.framework_version
    assert env.is_multi_file is True
    assert env.workdir
    assert env.entrypoint_cmd


def test_base_image_is_digest_pinned() -> None:
    # A digest-pinned reference is "<repo>@sha256:<64 hex chars>", never a
    # bare mutable tag like "node:22-bookworm-slim" -- CR-LAB-0001 Addendum
    # D's "soft-guarantee digest-pinned" rule.
    image = NODE_EXPRESS_STACK_ENV.base_image
    assert "@sha256:" in image
    digest = image.split("@sha256:", 1)[1]
    assert len(digest) == 64
    int(digest, 16)  # raises ValueError if not valid hex


def test_route_is_declared_as_the_accumulator() -> None:
    assert NODE_EXPRESS_STACK_ENV.accumulators == ("app.js",)


def test_scaffold_files_are_loaded_once_and_include_the_lockfile_and_dockerfile() -> None:
    files = NODE_EXPRESS_STACK_ENV.scaffold_files
    assert "package.json" in files
    assert "package-lock.json" in files
    assert "Dockerfile" in files
    assert "db.js" in files
    # The lockfile must actually be valid JSON pinning both direct deps --
    # a real, npm-registry-resolved lockfile, not a hand-typed stub.
    lock = json.loads(files["package-lock.json"])
    deps = lock["packages"][""]["dependencies"]
    assert "express" in deps
    assert "mysql2" in deps
    assert lock["lockfileVersion"] == 3


def test_dockerfile_pins_the_same_digest_as_the_stack_env() -> None:
    dockerfile = NODE_EXPRESS_STACK_ENV.scaffold_files["Dockerfile"].decode("utf-8")
    digest = NODE_EXPRESS_STACK_ENV.base_image.split("@", 1)[1]
    assert digest in dockerfile
    assert "NODE_ENV=production" in dockerfile  # framework-debug-page mitigation


def test_scaffold_files_are_deterministic_across_two_loads() -> None:
    from fuzzlab.labgen.emitters.node_express.stack_env import _load_scaffold_files

    first = _load_scaffold_files()
    second = _load_scaffold_files()
    assert first == second
