# Preventive actions

The active rules to follow while working on this project. Each is a preventive
action from a bug investigation (`docs/bugs/`). No background here by design —
read this list and follow it. Consult it before and during changes.

Format: `PA-NNNN — <rule>. (from BUG-NNNN)`

- **PA-0001** — In tests, do not hardcode a value that a source-of-truth constant
  or registry in the code already defines (schema head version, `FEATURE_VERSION`,
  enum members, etc.); derive the expectation from that source. Reserve literal
  expected values for genuinely fixed external contracts. (from BUG-0001)
- **PA-0002** — When a bug investigation adds a preventive action, sweep the whole
  codebase for existing instances of that bug class and remediate them (or record
  why not) — do not fix only the instance that triggered the investigation. (from
  BUG-0002)
