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


def test_save_load_json_roundtrip(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("json roundtrip", category="confirmed", confidence=0.9)
    bank.add_threat("suspected entry", category="suspected", confidence=0.5)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        path = tmp.name
    try:
        bank.save_json(path)
        emb = TextEmbedder(model_name="hash-fallback")
        b2 = AdversarialMemoryBank(embedder=emb, max_entries=100)
        b2.load_json(path)
        sim, _, _ = b2.query_similarity("json roundtrip")
        assert sim > 0.99
        assert len(b2._confirmed) == 1  # noqa: SLF001
        assert len(b2._suspected) == 1  # noqa: SLF001
    finally:
        import os
        os.unlink(path)


def test_json_file_is_readable(bank: AdversarialMemoryBank) -> None:
    import json
    bank.add_threat("readable test", category="confirmed")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        path = tmp.name
    try:
        bank.save_json(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == 1
        assert len(data["confirmed"]) == 1
        assert data["confirmed"][0]["text"] == "readable test"
    finally:
        import os
        os.unlink(path)


def test_load_json_rejects_bad_schema(bank: AdversarialMemoryBank) -> None:
    import json
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as tmp:
        json.dump({"version": 999}, tmp)
        path = tmp.name
    try:
        with pytest.raises(ValueError, match="unsupported"):
            bank.load_json(path)
    finally:
        import os
        os.unlink(path)


def test_export_threats_without_embeddings(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("export test", category="confirmed")
    exported = bank.export_threats(include_embeddings=False)
    assert len(exported) == 1
    assert "embedding" not in exported[0]
    assert exported[0]["text"] == "export test"
    assert exported[0]["tier"] == "confirmed"


def test_export_threats_with_embeddings(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("embed export", category="confirmed")
    exported = bank.export_threats(include_embeddings=True)
    assert len(exported) == 1
    assert "embedding" in exported[0]
    assert isinstance(exported[0]["embedding"], list)


def test_import_threats(bank: AdversarialMemoryBank) -> None:
    entries = [
        {"text": "imported attack 1", "tier": "confirmed", "confidence": 0.9},
        {"text": "imported attack 2", "tier": "suspected", "confidence": 0.5},
        {"text": "", "tier": "confirmed"},
    ]
    added = bank.import_threats(entries)
    assert added == 2
    assert len(bank._confirmed) == 1  # noqa: SLF001
    assert len(bank._suspected) == 1  # noqa: SLF001


def test_export_import_roundtrip(bank: AdversarialMemoryBank) -> None:
    bank.add_threat("roundtrip 1", category="confirmed", confidence=0.9)
    bank.add_threat("roundtrip 2", category="suspected", confidence=0.6)
    exported = bank.export_threats(include_embeddings=False)

    emb = TextEmbedder(model_name="hash-fallback")
    b2 = AdversarialMemoryBank(embedder=emb, max_entries=100)
    added = b2.import_threats(exported)
    assert added == 2
