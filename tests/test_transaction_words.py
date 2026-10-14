"""CC-CORE-0045 (forms phase 3): one shared transaction-word rule (PA-0003). Lane I refuses
to submit a form whose route, button label or request names a transaction; lane J never
imports a captured request to one. Visiting such a page is not refused."""

from __future__ import annotations

import pytest

from fuzzlab.core.urls import TRANSACTION_TOKENS, transaction_reason


@pytest.mark.parametrize("word", sorted(TRANSACTION_TOKENS))
def test_every_word_is_refused_as_a_label_a_route_and_a_url(word):
    assert transaction_reason(word.capitalize()) == word
    assert transaction_reason(f"/{word}-now") == word
    assert transaction_reason(f"http://h/#/{word}") == word
    assert transaction_reason(f"http://h/rest/{word}s/1") == word        # plural folded


@pytest.mark.parametrize("text,reason", [
    ("Top-up", "top up"), ("Check out", "check out"),
    ("http://127.0.0.1:3000/rest/wallet/balance", "wallet"),
    ("http://127.0.0.1:3000/rest/deluxe-membership", "membership"),
    ("http://h/rest/basket/1/checkout", "checkout"),
    ("http://h/%63heckout", "checkout"),                                # decoded
    ("placeOrder", "order"),                                            # camelCase
    ("http://h/r?next=checkout", "checkout"),       # the query counts, as for destructive
])
def test_transactions_are_found(text, reason):
    assert transaction_reason(text) == reason


@pytest.mark.parametrize("text", [
    "Submit", "Add to Basket", "Search", "Log in", "buyer", "paypal", "orderly",
    "http://h/#/search?q=x", "/api/Feedbacks", "", None,
])
def test_ordinary_text_is_not_a_transaction(text):
    assert transaction_reason(text) is None
