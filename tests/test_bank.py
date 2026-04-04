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
