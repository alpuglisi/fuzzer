"""Phase 7 T7.1: ranking metrics (NDCG@k, Precision@k) and char n-gram TF-IDF."""

import math

from fuzzlab.ml.ranking import (mean_ndcg_at_k, mean_precision_at_k, ndcg_at_k,
                                precision_at_k)
from fuzzlab.ml.text_features import CharNgramVectorizer, candidate_text


# --- ranking metrics ---------------------------------------------------------
def test_ndcg_perfect_and_worst_ordering():
    y = [1, 0, 0, 1]
    perfect = [0.9, 0.1, 0.2, 0.8]      # both positives on top
    worst = [0.1, 0.9, 0.8, 0.2]        # both positives at the bottom
    assert ndcg_at_k(y, perfect, k=4) == 1.0
    assert ndcg_at_k(y, worst, k=4) < 1.0
    assert ndcg_at_k(y, perfect, k=4) > ndcg_at_k(y, worst, k=4)


def test_ndcg_zero_when_no_positive():
    assert ndcg_at_k([0, 0, 0], [0.9, 0.5, 0.1], k=3) == 0.0


def test_ndcg_matches_hand_computation():
    # order by score desc -> relevances [0,1,1]; DCG=1/log2(3)+1/log2(4)
    y = [1, 1, 0]
    scores = [0.1, 0.5, 0.9]            # ranks: idx2(0), idx1(1), idx0(1)
    dcg = 1 / math.log2(3) + 1 / math.log2(4)
    idcg = 1 / math.log2(2) + 1 / math.log2(3)
    assert ndcg_at_k(y, scores, k=3) == round(dcg / idcg, 6)


def test_precision_at_k():
    y = [1, 0, 1, 0, 1]
    scores = [0.9, 0.8, 0.7, 0.2, 0.1]  # top-3 = idx0(1),1(0),2(1) -> 2/3
    assert precision_at_k(y, scores, k=3) == round(2 / 3, 6)


def test_ties_are_averaged_never_broken_by_input_order():
    """BUG-0073: a constant scorer gets the expected value over every order of the tie,
    whatever the input order (it used to win when the input listed positives first)."""
    const = [0.5, 0.5, 0.5]
    first, last = ndcg_at_k([1, 0, 0], const, k=3), ndcg_at_k([0, 0, 1], const, k=3)
    expected = (1 / math.log2(2) + 1 / math.log2(3) + 1 / math.log2(4)) / 3
    assert first == last == round(expected, 6) < 1.0
    assert precision_at_k([1, 0, 0], const, k=1) == precision_at_k([0, 0, 1], const, k=1) \
        == round(1 / 3, 6)
    # a partial tie: the untied top item is exact, the tied tail is averaged
    y, s = [0, 1, 0, 1], [0.9, 0.2, 0.2, 0.2]
    gains = [0, 2 / 3, 2 / 3]
    dcg = sum(g / math.log2(i + 2) for i, g in enumerate(gains))
    assert ndcg_at_k(y, s, k=3) == round(dcg / (1 + 1 / math.log2(3)), 6)
    assert precision_at_k(y, s, k=2) == round((0 + 2 / 3) / 2, 6)


def test_non_finite_scores_are_refused():
    import pytest
    with pytest.raises(ValueError):
        ndcg_at_k([1, 0], [float("nan"), 0.5], k=2)


def test_a_constant_scorer_equals_the_exact_random_expectation():
    """Averaging ties = the expectation over uniformly random orders (checked by brute
    force over every permutation)."""
    from itertools import permutations
    y = [1, 0, 1, 0, 0]
    perms = list(permutations(range(len(y))))
    for k in (1, 2, 3, 5):
        exp_nd = sum(ndcg_at_k([y[i] for i in p], [5, 4, 3, 2, 1], k) for p in perms) / len(perms)
        exp_pr = sum(precision_at_k([y[i] for i in p], [5, 4, 3, 2, 1], k)
                     for p in perms) / len(perms)
        assert abs(ndcg_at_k(y, [0.0] * 5, k) - exp_nd) < 1e-5
        assert abs(precision_at_k(y, [0.0] * 5, k) - exp_pr) < 1e-5


def test_mean_metrics_skip_pages_without_positives():
    y = [1, 0, 0, 0]
    scores = [0.9, 0.1, 0.9, 0.1]
    groups = ["p1", "p1", "p2", "p2"]   # p2 has no positive -> skipped
    # only p1 counts, and its positive is on top -> perfect
    assert mean_ndcg_at_k(y, scores, groups, k=2) == 1.0
    assert mean_precision_at_k(y, scores, groups, k=1) == 1.0


# --- char n-gram TF-IDF ------------------------------------------------------
def test_candidate_text_normalizes():
    txt = candidate_text({"param": "Redirect_URL", "url": "http://h/Go.php?x=1",
                          "category": "open-redirect", "method": "GET"})
    assert "redirect_url" in txt and "/go.php" in txt and "open-redirect" in txt


def test_vectorizer_is_deterministic_and_bounded():
    texts = ["redirect_url", "id", "file_path", "id", "template"]
    v = CharNgramVectorizer(n=3, max_features=8)
    X1 = v.fit_transform(texts)
    v2 = CharNgramVectorizer(n=3, max_features=8)
    X2 = v2.fit_transform(texts)
    assert v.vocab == v2.vocab and X1 == X2          # deterministic
    assert len(v.vocab) <= 8                          # bounded
    assert all(len(row) == len(v.vocab) for row in X1)


def test_vectors_are_l2_normalized():
    v = CharNgramVectorizer(n=3, max_features=32)
    X = v.fit_transform(["redirect_url", "id_number", "page_include"])
    for row in X:
        norm = math.sqrt(sum(x * x for x in row))
        assert abs(norm - 1.0) < 1e-9 or norm == 0.0


def test_similar_names_are_closer_than_dissimilar():
    corpus = ["redirect_url", "return_url", "id"]
    v = CharNgramVectorizer(n=3, max_features=64).fit(corpus)
    a, b, c = v.transform(["redirect_url", "return_url", "id"])
    dot = lambda p, q: sum(x * y for x, y in zip(p, q))
    assert dot(a, b) > dot(a, c)                      # the two *_url names overlap more


def test_short_text_and_unseen_ngrams():
    v = CharNgramVectorizer(n=3, max_features=16).fit(["idxx", "abcd"])
    (vec,) = v.transform(["zz"])                       # shorter than n, all-unseen
    assert vec == [0.0] * len(v.vocab)


def test_the_trainer_ranks_on_the_stored_six_dp_values():
    """Scores the store rounds to one value tie in the trainer's numbers too, so the ML
    tab (which reads stored rank scores) recomputes the same metric (PA-0069(3))."""
    from fuzzlab.ml.rank_train import evaluate_vs_random
    y, groups = [0, 1], ["p", "p"]
    near = evaluate_vs_random(y, [0.50000001, 0.5], groups, 2, 0)
    stored = evaluate_vs_random(y, [0.5, 0.5], groups, 2, 0)
    assert near == stored and near[0] < 1.0
