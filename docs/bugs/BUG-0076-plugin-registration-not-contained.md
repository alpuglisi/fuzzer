# BUG-0076 — One plugin with malformed metadata took every plugin down

- Date: 2026-10-13
- Status: fixed (CC-PLUG-0008)
- Severity: low-medium. Any installed third-party plugin with, for example,
  `priority = "high"` crashed `fuzzlab auto --plugins` at start, before any traffic.
  Every plugin, the ML stages included, was lost. This violated FR-PLUG-3 /
  NFR-PLUG-safe ("a bad plugin is contained").

## Description
`HookRegistry.register` called `plugin_info(plugin)` outside any containment:
`int(priority)` raised `ValueError` for `"high"`, `TypeError` for `None`. Construction of
`PluginManager.from_entry_points` aborted. A `bool` priority was silently read as 0 / 1.
Separately, `handlers()` looked up each hook with `getattr(plugin, hook, None)`, which
swallows only `AttributeError`, so a hook property that raised anything else escaped
dispatch.

## Where encountered
The error-review phase (a review agent; reproduced by me: `PluginManager construction
RAISED: ValueError invalid literal for int() with base 10: 'high'`).

## What it caused to fail
`fuzzlab auto --plugins` with any such plugin installed, and every `from_entry_points`
caller.

## What the bug was identified to be
The containment boundary started at hook *invocation*. It did not cover two other
per-plugin steps: metadata reading and hook lookup.

## Root cause analysis
Five Whys:
1. *Why did construction abort?* `int("high")` raised inside `register`.
2. *Why was it not caught?* Containment (`contain`) wrapped only hook calls. Discovery
   (`ep.load()`) had its own catch; registration had none.
3. *Why did registration have none?* It was written when metadata came from built-ins,
   before third-party entry points.
4. *Why did no test catch it?* The containment tests raised from hooks, not from
   metadata or attribute lookup.
5. *Why did no rule catch it?* FR-PLUG-3 states the property, but no rule enumerated the
   per-plugin steps it must hold for.

**Root cause:** the containment boundary covered some per-plugin steps, not all of them.

## Corrective action
In CC-PLUG-0008:
- **Registration is contained.** `register` catches **every** exception from
  `plugin_info` and rejects the plugin with the reason: `invalid metadata:
  <Type>: <msg>`, under its declared name, or its class name if the name itself raises.
  The other plugins attach.
- **A bool priority is rejected.**
- **Rejections carry their reason.** `HookRegistry.rejections()` /
  `PluginManager.rejections()` return `(info, reason)`; `rejected()` is unchanged. The
  CLI prints `plugin refused (<reason>): <name>` for both rejection kinds.
- **Hook lookup is contained (sweep).** A raising hook attribute disables only that
  plugin, with its error recorded; the rest still dispatch.
- **Tests** (`tests/test_plugins.py`):
  - a string priority, a bool priority and a raising `name` are each rejected while the
    good plugin attaches;
  - a duplicate name keeps its reason;
  - a raising hook property disables only that plugin.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for plugin containment and
"contained" failures: no prior bug found a gap in the plugin containment boundary.
CC-FUZZ-0050 / CC-PLUG work added `after_run` and prioritizer containment; those were
features, not fixes.

**Result:** a new root cause, with no prior PA to analyse for failure.

## Preventive action
**PA-0077** (in `docs/PREVENTIVE_ACTIONS.md`):
1. **Every per-plugin step is inside the containment boundary:** load, metadata,
   registration, hook lookup, hook call, and recording. A containment property is
   tested at each step, not only at hook invocation.
2. **A contained failure is visible:** a rejection or disable carries its reason to the
   run record or CLI.

**Sweep (PA-0002):**
- **Entry-point load:** `discovery.discover` already catches every exception.
- **Metadata / registration:** fixed.
- **Hook lookup:** fixed.
- **Hook call:** `contain`.
- **Prioritizer collection:** `contain`.
- **`after_run`:** contained and guarded (CC-FUZZ-0050).
- **`record` / `finalize`:** they read only validated `PluginInfo`, so they cannot
  raise on plugin data.
- **`plugin_config`:** already catches unserialisable configs.
