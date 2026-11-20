"""BUG-0742 / PA-0742: two connections admitted together to one host and port each carry
their own admission through SP-04's enforcer.

`navguard._take_tunnel` gives a ``CONNECT`` the oldest live ticket, its retry slot
included (a certificate error's retry, BUG-0559 review round 3). Two WebSockets admitted
together (one page's two sockets, or concurrent M6 browsers, FR-FUZZ-720) took one
ticket: the first tunnel claimed it and the second was refused as a reuse, its own
ticket left live for the next ``CONNECT`` (measured: 1 refusal in 60 Juice Shop visits at
3 concurrent browsers, 0 in 60 one at a time; CC-LAB-0440). The order of events is pinned
here on the real ticket functions, without a browser (PA-0561(2)).
"""

from __future__ import annotations

import pytest

from fuzzlab.tools import navguard


@pytest.fixture(autouse=True)
def _clean_tickets(monkeypatch):
    monkeypatch.setattr(navguard, "_TUNNEL_TICKETS", {})


def test_two_sockets_admitted_together_each_carry_their_own_ticket():
    navguard.admit_socket("ws://127.0.0.1:3000/a")
    navguard.admit_socket("ws://127.0.0.1:3000/b")
    first = navguard._take_tunnel("127.0.0.1", 3000)
    second = navguard._take_tunnel("127.0.0.1", 3000)
    # the oldest ticket's retry slot is taken by the second CONNECT (unchanged order)
    assert first is second
    carried_a = navguard._claim(first)
    carried_b = navguard._claim(second)
    assert carried_a is first
    assert carried_b is not None and carried_b is not first      # the spare admission
    # every admission is now carried: nothing left for a stray CONNECT (no orphan)
    assert navguard._take_tunnel("127.0.0.1", 3000) is None


def test_a_spare_is_never_another_hosts_or_another_kinds():
    navguard.admit_socket("ws://127.0.0.1:3000/a")
    navguard.admit_socket("ws://127.0.0.1:3001/b")             # another port
    navguard.admit_landing("https://127.0.0.1:3000/land")      # another kind
    ticket = navguard._take_tunnel("127.0.0.1", 3000)
    assert navguard._claim(ticket) is ticket
    assert navguard._claim(ticket) is None                     # no spare of its own kind


def test_one_admission_still_carries_one_tunnel_its_retry_included():
    """A certificate error's retry: two tunnels on one ticket, the one that carries
    traffic claims it, and the other is refused (BUG-0559 review round 3)."""
    navguard.admit_socket("wss://127.0.0.1:3443/a")
    first = navguard._take_tunnel("127.0.0.1", 3443)
    retry = navguard._take_tunnel("127.0.0.1", 3443)
    assert first is retry and first.tunnels == 2
    assert navguard._claim(retry) is retry
    assert navguard._claim(first) is None


def test_the_held_tunnel_carries_the_spare_it_claimed():
    navguard.admit_socket("ws://127.0.0.1:3000/a")
    navguard.admit_socket("ws://127.0.0.1:3000/b")
    ticket = navguard._take_tunnel("127.0.0.1", 3000)
    a = navguard._HeldTunnel(ticket, via_proxy=False)
    b = navguard._HeldTunnel(navguard._take_tunnel("127.0.0.1", 3000), via_proxy=False)
    assert a._claim() and b._claim()
    assert a.ticket is not b.ticket and a.ticket.claimed and b.ticket.claimed
