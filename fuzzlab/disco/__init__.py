"""Behavioural black-box discovery and contract fuzzing (``fuzzlab disco``; D70).

The legacy crawler (``fuzzlab.tools.spider``) reads pages; this package watches what an
application *does* on the wire, so it needs nothing from the stack inside the
container. Three phases, each a file handoff the next one reads:

1. **Discovery** (component CRAWL):
   - `recorder` -- a mitmproxy addon, the scope firewall and the one producer of
     ``capture.jsonl`` (`capture`, redacted at the write);
   - `explore` -- a guarded Playwright context driven through that proxy, exploring
     a state graph keyed by layout fingerprint (`fingerprint`), clicking what has
     listeners (CDP) and filling forms valid-first (`formfill`), and tagging every
     request with the action that caused it (``x-disco-action``);
   - `synth` -- ``capture.jsonl`` -> an OpenAPI 3.1-shaped endpoint inventory with
     templated paths, merged schemas, header classes and producer -> consumer edges.
2. **Payload synthesis** (component MUT): `generate` asks an LLM for test cases per
   endpoint, structured output only, validated and scope-filtered (`contract`).
3. **Execution** (component FUZZ): `runner` executes the contract (setup steps in
   dependency order, oracles, a ``results`` ledger), every send scope-gated.

Lab-only (D11): anything that sends traffic needs ``--authorized``; every listener is
loopback; the browser goes through `fuzzlab.tools.navguard` like every other launch.
Nothing here imports the legacy spider (a guard test holds that).
"""
