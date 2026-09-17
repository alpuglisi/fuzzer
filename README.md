# fuzzer

Time-based blind SQL injection detector and dataset builder.

## Authorized use only

Run this **only** against systems you own or have explicit, written
permission to test, such as a local [DVWA](https://github.com/digininja/DVWA)
or [Mutillidae](https://github.com/webpwnized/mutillidae) lab. The tool has
**no default target**: you must pass `--url` and the `--authorized` flag, so it
can never fire at a host by accident.

## What it does

`blind_sqli_fuzzer.py` sends a small catalog of payloads to a single request
parameter, measures response latency against a per-target baseline, and writes
the observations to a CSV. Detection is derived purely from measured timing, so
the ground-truth signal is independent of the payload's own label. That makes
the output usable for training or evaluating a response classifier without the
label leaking into the feature it is meant to predict.

Each row records the payload, its family, HTTP status, response size, median
latency, the latency and size deltas from baseline, the input label
(`is_malicious_payload`), the timing-only signal (`time_delay_detected`), and
the evaluation outcome (true/false positive/negative).

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python blind_sqli_fuzzer.py \
  --url http://localhost:8080/api/users \
  --param id \
  --authorized \
  --output blind_sqli_dataset.csv
```

Key options:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--url` | required | Target URL to test |
| `--param` | `id` | Request parameter to fuzz |
| `--authorized` | required | Affirms you are authorized to test the target |
| `--repeats` | `2` | Measurements per payload; the median is used |
| `--sigma` | `3` | Jitter band width, in standard deviations |
| `--min-delay` | `2` | Minimum absolute added delay (s) to count as a hit |
| `--timeout` | `15` | Per-request timeout (s); keep it above the max sleep |

## Notes

- The benign payloads are controls. If they are ever flagged, the threshold is
  too low or the target is unstable; raise `--sigma` or `--min-delay`.
- Timing signals are noisy over a real network. Increase `--repeats` and
  `--baseline-iterations` for a more stable baseline.
