"""Tests for AdversarialMemoryBank (hash embedder fallback)."""

from __future__ import annotations

import tempfile

import pytest

from agent_immune.memory.bank import AdversarialMemoryBank
from agent_immune.memory.embedder import TextEmbedder


@pytest.fixture
def bank() -> AdversarialMemoryBank:
    emb = TextEmbedder(model_name="hash-fallback")
    return AdversarialMemoryBank(embedder=emb, max_entries=100)


def test_add_query_roundtrip(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("steal all user emails now", category="confirmed", confidence=0.9)
    sim, texts, ids = bank.query_similarity("exfiltrate user mailboxes", k=2)
    assert sim >= 0.0
    assert len(ids) >= 1


def test_dedup_updates(bank: AdversarialMemoryBank) -> None:
    t = "duplicate attack text"
    id1 = bank.add_threat(t, category="suspected")
    id2 = bank.add_threat(t, category="suspected")
    assert id1 == id2


def test_save_load_roundtrip(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("secret leak pattern", category="suspected")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as tmp:
        path = tmp.name
    try:
        bank.save(path)
        emb = TextEmbedder(model_name="hash-fallback")
        b2 = AdversarialMemoryBank(embedder=emb, max_entries=100)
        b2.load(path)
        sim, _, _ = b2.query_similarity("secret leak pattern")
        assert sim > 0.99
    finally:
        import os

        os.unlink(path)


def test_decay_drops_weak(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("low priority", category="suspected", confidence=0.1)
    for _ in range(500):
        bank.decay_suspected(0.9)
    assert len(bank._suspected) == 0  # noqa: SLF001


def test_save_load_with_hmac(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("hmac test", category="confirmed")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as tmp:
        path = tmp.name
    try:
        bank.save(path, signing_key="test-secret")
        emb = TextEmbedder(model_name="hash-fallback")
        b2 = AdversarialMemoryBank(embedder=emb, max_entries=100)
        b2.load(path, signing_key="test-secret")
        sim, _, _ = b2.query_similarity("hmac test")
        assert sim > 0.99
    finally:
        import os
        os.unlink(path)


def test_load_rejects_tampered_hmac(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("tamper test", category="confirmed")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as tmp:
        path = tmp.name
    try:
        bank.save(path, signing_key="correct-key")
        emb = TextEmbedder(model_name="hash-fallback")
        b2 = AdversarialMemoryBank(embedder=emb, max_entries=100)
        with pytest.raises(ValueError, match="HMAC verification failed"):
            b2.load(path, signing_key="wrong-key")
    finally:
        import os
        os.unlink(path)


def test_max_similarity_by_tier(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("confirmed attack pattern", category="confirmed")
    bank.add_threat("suspected shady behavior", category="suspected")
    mc, ms = bank.max_similarity_by_tier("confirmed attack pattern")
    assert mc > 0.9
    assert isinstance(ms, float)


def test_record_query_match_increments(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("exact match test", category="confirmed", confidence=0.9)
    bank.record_query_match("exact match test", threshold=0.0)
    entry = list(bank._by_hash.values())[0]  # noqa: SLF001
    assert entry.times_matched >= 1


def test_eviction_on_overflow() -> None:
    emb = TextEmbedder(model_name="hash-fallback")
    small_bank = AdversarialMemoryBank(embedder=emb, max_entries=5)
    for i in range(10):
        small_bank.add_threat(f"unique attack number {i}", category="confirmed", confidence=0.5 + i * 0.01)
    total = len(small_bank._confirmed) + len(small_bank._suspected)  # noqa: SLF001
    assert total <= 5


def test_promote_from_matches(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("borderline entry", category="suspected", confidence=0.8)
    entry = bank._by_hash[list(bank._by_hash.keys())[0]]  # noqa: SLF001
    entry.times_matched = 5
    bank.promote_from_matches()
    assert entry.tier == "confirmed"
    assert entry in bank._confirmed  # noqa: SLF001


def test_add_threat_internal_returns_is_new(bank: AdversarialMemoryBank) -> None:
    eid1, is_new1 = bank._add_threat_internal("brand new text", "confirmed", 0.9)
    assert is_new1 is True
    assert eid1 is not None
    eid2, is_new2 = bank._add_threat_internal("brand new text", "confirmed", 0.9)
    assert is_new2 is False
    assert eid2 == eid1


def test_empty_bank_query(bank: AdversarialMemoryBank) -> None:
    sim, texts, ids = bank.query_similarity("anything", k=3)
    assert sim == 0.0
    assert texts == []
    assert ids == []


def test_tier_upgrade_on_readd(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("upgrade me", category="suspected")
    assert len(bank._suspected) == 1  # noqa: SLF001
    bank.add_threat("upgrade me", category="confirmed")
    assert len(bank._suspected) == 0  # noqa: SLF001
    assert len(bank._confirmed) == 1  # noqa: SLF001
