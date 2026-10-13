# BUG-0095 — A huge JSON integer escaped the model loader's typed refusal

- Date: 2026-10-13
- Status: fixed (CC-ML-0024)
- Severity: medium. A crafted or corrupted saved model crashed a saved-mode run with a
  raw `OverflowError` instead of the typed refusal its callers handle. Size was not
  bounded at all.

## Description
A prevalence model whose `rate` is `10**1000`, resealed with a correct sha256, made
`loads_model` raise `OverflowError` ("int too large to convert to float") out of
`_is_num`'s `math.isfinite`. The boundary caught `ModelParamsError`, `RecursionError`
and `(ValueError, TypeError, KeyError)` only. Nothing bounded the text size, the total
number of values, or a GBT's tree count and depth.

## Where encountered
A third-party review of head `5eb4be9` (finding #6). Reproduced with
`scratchpad/ext/f6_overflow.py`.

## What it caused to fail
FR-ML-13 / PA-0021: the loader "fails closed with `ModelParamsError` on anything it
cannot prove well formed — one typed error at the boundary, never a raw library
exception".

## What the bug was identified to be
A validation predicate that could raise (`_is_num`), and a boundary that did not list
every exception class a stored value could produce. Unbounded input sizes were a second
gap of the same boundary.

## Root cause analysis
1. *Why a raw OverflowError?* `math.isfinite(10**1000)` converts the int to a float.
2. *Why not caught?* The boundary enumerated exception classes, not "anything".
3. *Why not tested?* CC-ML-0015's tests used malformed **structure** (wrong keys,
   types, lengths, NaN tokens), never extreme **magnitudes** or **sizes**.

**Root cause:** the typed error boundary was tested on shapes, not on numeric extremes
or sizes, and its predicates were not total.

## Corrective action
- **CC-ML-0024 (`ml/persist.py`):**
  - `_is_num` is total: a bool or non-number is False, and an int too large for a float
    is False, never an exception.
  - `loads_model` wraps `OverflowError` and `MemoryError` at its boundary in
    `ModelParamsError`.
  - **Size limits, enforced on dump and load** so a stored model is always loadable:
    - `MAX_PARAMS_BYTES` (8 MiB), checked before hashing or `json.loads`;
    - `MAX_MODEL_ELEMENTS` (2,000,000) array items and object members across the
      whole model, by an iterative walk;
    - `MAX_TREES` = 1000 and `MAX_DEPTH` = 32, checked before recursing into trees.

    A test asserts a real trained hybrid model fits.
  - **Stated limit:** a hybrid's ECOD stores its training columns, so the byte limit
    bounds a hybrid model to roughly 35k training rows. A larger one is refused at save
    time with the typed error, never stored unloadable.
- **Tests** (`tests/test_ml_persist.py`):
  - `10**1000` in seven numeric fields → `ModelParamsError`: prevalence rate, logistic
    weight, logistic bias, Platt `a`, ECOD skew, GBT prior and a GBT threshold;
  - `1e400`, `-1e400` and a 5001-digit literal (Python's int-string limit) →
    `ModelParamsError`;
  - `_is_num` is total on 9 extreme inputs;
  - oversized text is refused without parsing;
  - the element budget is enforced on load and save;
  - tree count and depth limits;
  - a real model fits;
  - saved mode refuses a resealed huge int cleanly;
  - the boundary types an `OverflowError` / `MemoryError` raised by the rebuild.

  16 of the new cases fail on `5eb4be9`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **PA-0021** (one typed error at the boundary) and **CC-ML-0015** (which built this
  loader): the same boundary, and the same promise broken by an untested input class.
- No prior bug report on this loader.

**Result:** a gap in how PA-0021 was tested, not a repeat of a recorded bug.

## Prior-preventive-action failure analysis
**PA-0021 was followed but not enforced against extremes.** It requires one typed
error at the boundary. The loader enumerated exception classes, and its tests never
supplied a value that raised outside them. The rule said what the boundary must do,
not which inputs prove it.

## Preventive action
- **PA-0096** (strengthens PA-0021):
  1. **A typed error boundary is tested with values at every numeric extreme** (huge
     integers, `1e400`, NaN, ±inf, `-0.0`, bools) **and with oversized inputs**
     (bytes, element counts, depth). Sizes are bounded before allocation.
  2. **Validation predicates are total**: they return False and never raise.

**Sweep (PA-0002):** other loaders of untrusted serialised state:
- **`core/sealed`, proxy rules and config:** validated JSON of small, project-defined
  shapes. Their numeric fields are compared, never converted to float.
- **`calibration` JSON in model rows:** read with `json.loads` and `.get`. Readers use
  the values as numbers only through rounding in display, and `round(10**1000, 4)` is
  an int, not an exception.

No other float conversion of untrusted input found.
