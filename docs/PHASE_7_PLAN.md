# Phase 7 — Candidate ranker + active learning (plan)

Learn to **order** the auditor's candidates so the most promising injection points are
tried first — at **zero request cost** — and **allocate the oracle's budget** to the
candidates whose labels are most informative. Strict oracle/advisory split (as Phase 5):
the ranker writes **scores/uncertainty**, never `finding` labels.

*Last updated: 2026-09-21. Component **ML** (#10): candidate ranker (A.2) + active
learner (A.6.5). Builds on Phase 5's `fuzzlab/ml/` (metrics, dataset, logistic). See
`DECISIONS_AND_ROADMAP.md` (Phase 7) and the `candidate.score` contract.*

## Goal

On held-out endpoints, the ranker beats a random ordering on **NDCG@k / Precision@k**
(GroupKFold by endpoint) using only features known before any request, and active
learning (uncertainty sampling + query-by-committee) selects a small subset of
candidates that, if confirmed, would most improve the model — cutting oracle load.

## Exit criterion

Held-out **NDCG@k and Precision@k beat a random-order baseline** (GroupKFold by
endpoint), and an uncertainty/committee budget of *b* candidates captures more positives
per confirmation than a random budget — all advisory, oracle still the sole labeler.

## Principles (this phase)

- **Zero requests.** The ranker reorders existing candidates from stored features; it
  never sends traffic. (Contrast: the Phase 5 classifier screens *attempts*.)
- **Advisory only.** Writes `candidate.rank_score` / `candidate.rank_uncertainty`, never
  labels. The oracle confirms; the ranker orders; the active learner *proposes* what to
  confirm.
- **Honest evaluation.** GroupKFold by endpoint (no leakage); rank metrics per page;
  beat a random-order baseline or it does not ship. A separate, uniformly-sampled
  evaluation set for the on-lab exit.
- **Dependency-light.** Pure-Python char n-gram TF-IDF + the existing logistic model as
  a pointwise ranker; a bootstrap committee for disagreement. No numpy/sklearn.

## Tasks

- **T7.1 — Ranking metrics + text features `[done, offline]`.** `fuzzlab/ml/ranking.py`
  (`ndcg_at_k`, `precision_at_k`, and per-group `mean_ndcg_at_k`/`mean_precision_at_k`).
  `fuzzlab/ml/text_features.py::CharNgramVectorizer` (pure-Python char n-gram TF-IDF,
  L2-normalized, deterministic vocab) + `candidate_text` (param/path/category/method).
- **T7.2 — Pointwise ranker + train/score/persist `[done, offline]`.**
  `fuzzlab/ml/ranker.py::Ranker` augments the structural feature vector with char n-gram
  TF-IDF and fits a pointwise logistic scorer, exposing per-candidate **explanations**
  (top contributing features). `fuzzlab/ml/rank_train.py::train_and_rank` runs OOF
  GroupKFold, reports NDCG@k/Precision@k vs a random baseline, writes advisory
  `candidate.rank_score` (migration 7), persists a `model` row + metrics, and falls back
  on thin data. Wired as `fuzzlab auto --rank`.
- **T7.3 — Active learning `[done, offline]`.** `fuzzlab/ml/active.py`:
  `uncertainty_sampling` (score nearest the 0.5 decision boundary) and
  `query_by_committee` (a bootstrap committee's disagreement), each returning the top-*b*
  candidate ids to hand the oracle. A `Committee` helper trains N bootstrapped members
  and reports mean score + disagreement (advisory uncertainty).
- **T7.4 — Held-out exit `[on-host]`.** On the store's real dataset: NDCG@k/Precision@k
  beat the random baseline on a uniformly-sampled held-out set, and a fixed
  uncertainty/committee budget captures more positives per confirmation than random.

## Component mapping

- **ML (10)** — `ranking.py`, `text_features.py`, `ranker.py`, `rank_train.py`,
  `active.py`.
- **CORE (02)** — `candidate.rank_score` / `candidate.rank_uncertainty` (migration 7).
- **UI (12)** — the panel later surfaces the ranked order (kept minimal this phase).

## Out of scope for Phase 7 (deferred)

- Writing labels from ML (never — oracle-only).
- Pairwise/listwise LTR (pointwise is enough to beat random and stays dependency-light).
- New feature *sources* (grey-box is Phase 3; this phase consumes stored features).
