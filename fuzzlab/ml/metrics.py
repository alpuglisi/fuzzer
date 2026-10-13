"""Honest evaluation: average precision (PR-AUC) and leakage-free GroupKFold.

`oof_folds` is the one entry point every out-of-fold scorer uses: it materializes the
folds and fails closed unless every row is held out exactly once (CC-ML-0012).

Injection points on the same endpoint are correlated, so a random split leaks — a
model can memorize an endpoint. `group_kfold` keeps every group (endpoint/template)
wholly within one fold. PR-AUC (average precision) is the headline metric because the
positive class is rare. Pure Python.
"""

from __future__ import annotations

import random
from typing import Iterable, Sequence


def pr_auc(y_true: Sequence[int], scores: Sequence[float]) -> float:
    """Average precision: area under the precision-recall curve (step interpolation).

    Ranks by score descending and sums precision at each recall gain. Returns the
    positive prevalence when no positive is scored above others (degenerate), and 0.0
    when there are no positives.
    """
    pairs = sorted(zip(scores, y_true), key=lambda t: t[0], reverse=True)
    total_pos = sum(1 for y in y_true if y)
    if total_pos == 0:
        return 0.0
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    i = 0
    n = len(pairs)
    while i < n:
        # advance over ties so precision/recall are read after the whole tie group
        score = pairs[i][0]
        while i < n and pairs[i][0] == score:
            if pairs[i][1]:
                tp += 1
            else:
                fp += 1
            i += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return round(ap, 6)


def group_kfold(groups: Sequence, k: int = 5,
                seed: int = 0) -> Iterable[tuple[list[int], list[int]]]:
    """Yield (train_idx, test_idx) for k folds, never splitting a group across folds.

    Every yielded fold has a non-empty train and test set with disjoint groups, and each
    index is tested exactly once. With ``k < 2`` or fewer than 2 distinct groups no
    held-out split exists, so **no folds** are yielded — never a train == test fold,
    which would turn "out-of-fold" evaluation into in-sample (BUG-0062). Callers must
    treat that as thin data.
    """
    unique = list(dict.fromkeys(groups))
    if k < 2 or len(unique) < 2:
        return                               # no held-out split exists (BUG-0062)
    k = min(k, len(unique))
    rng = random.Random(seed)
    rng.shuffle(unique)
    folds: list[set] = [set() for _ in range(k)]
    for i, g in enumerate(unique):
        folds[i % k].add(g)
    for fold in folds:
        test_idx = [i for i, g in enumerate(groups) if g in fold]
        train_idx = [i for i, g in enumerate(groups) if g not in fold]
        if test_idx and train_idx:
            yield train_idx, test_idx


def oof_folds(groups: Sequence, k: int = 5,
              seed: int = 0) -> list[tuple[list[int], list[int]]]:
    """`group_kfold`'s folds, verified to be a true out-of-fold partition.

    Raises ``ValueError`` unless every index is in exactly one test set (and never in its
    own train set) — fail closed: a row no fold scores would silently keep a placeholder
    score and skew PR-AUC / the conformal thresholds, and an empty fold list means no
    held-out split exists at all (fewer than 2 groups, or ``k < 2``).
    """
    folds = list(group_kfold(groups, k=k, seed=seed))
    tested = [0] * len(groups)
    for train, test in folds:
        if set(train) & set(test):
            raise ValueError("fold leaks: a row is in both train and test")
        for i in test:
            tested[i] += 1
    if not folds or any(c != 1 for c in tested):
        raise ValueError(
            f"no valid out-of-fold partition ({len(set(groups))} group(s), k={k}): "
            "every row must be held out exactly once — treat as thin data")
    return folds
