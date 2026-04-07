"""
Adversarial memory with confirmed vs suspected tiers, deduplication, and decay.

Uses NumPy cosine similarity for search, with optional hnswlib acceleration.
Thread-safe via threading.Lock.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import pickle
import threading
import time
from typing import Dict, List, Optional, Tuple

import numpy as np

from agent_immune.memory.embedder import TextEmbedder
from agent_immune.memory.entry import AdversarialEntry, new_entry, text_hash

try:
    import hnswlib

    _HAS_HNSW = True
except ImportError:  # pragma: no cover
    _HAS_HNSW = False

logger = logging.getLogger("agent_immune.memory.bank")

_SCHEMA_VERSION = 1
_HNSW_REBUILD_THRESHOLD = 64


class AdversarialMemoryBank:
    """Semantic store of known attacks with inner-product (cosine) search on L2-normalized vectors."""

    _fallback_quality_warned: bool = False

    def __init__(
        self,
        embedder: TextEmbedder,
        embedding_dim: Optional[int] = None,
        max_entries: int = 10000,
    ) -> None:
        """
        Initialize memory bank.

        Args:
            embedder: TextEmbedder used for queries and inserts.
            embedding_dim: Optional fixed dimension; inferred on first use if omitted.
            max_entries: Maximum total entries (60% confirmed cap, 40% suspected cap).

        Returns:
            None.

        Raises:
            None.
        """
        self._embedder = embedder
        self._dim = embedding_dim
        self._max_entries = max_entries
        self._confirmed: List[AdversarialEntry] = []
        self._suspected: List[AdversarialEntry] = []
        self._by_hash: Dict[str, AdversarialEntry] = {}
        self._lock = threading.Lock()
        self._hnsw_index: object | None = None
        self._hnsw_id_map: List[AdversarialEntry] = []
        self._hnsw_dirty = 0

    def _ensure_dim(self, vec: np.ndarray) -> None:
        if self._dim is None:
            self._dim = int(vec.shape[-1])

    def _rebuild_hnsw(self) -> None:
        """Rebuild the HNSW index from all entries with embeddings."""
        if not _HAS_HNSW or self._dim is None:
            return
        all_entries = [e for e in self._confirmed + self._suspected if e.embedding is not None]
        if not all_entries:
            self._hnsw_index = None
            self._hnsw_id_map = []
            self._hnsw_dirty = 0
            return
        dim = self._dim
        idx = hnswlib.Index(space="cosine", dim=dim)
        idx.init_index(max_elements=max(len(all_entries) * 2, 256), ef_construction=100, M=16)
        idx.set_ef(50)
        vecs = np.stack([e.embedding for e in all_entries]).astype(np.float32)
        idx.add_items(vecs, list(range(len(all_entries))))
        self._hnsw_index = idx
        self._hnsw_id_map = list(all_entries)
        self._hnsw_dirty = 0
        logger.debug("rebuilt HNSW index with %d entries", len(all_entries))

    def _hnsw_add_entry(self, entry: AdversarialEntry) -> None:
        """Incrementally add to HNSW; trigger rebuild after threshold."""
        if not _HAS_HNSW or entry.embedding is None or self._dim is None:
            return
        self._hnsw_dirty += 1
        if self._hnsw_dirty >= _HNSW_REBUILD_THRESHOLD or self._hnsw_index is None:
            self._rebuild_hnsw()

    def _search_hnsw(self, q: np.ndarray, k: int) -> List[Tuple[float, AdversarialEntry]]:
        """Search using HNSW index; returns (similarity, entry) pairs."""
        if self._hnsw_index is None or not self._hnsw_id_map:
            return []
        actual_k = min(k, len(self._hnsw_id_map))
        if actual_k == 0:
            return []
        qn = q.reshape(1, -1).astype(np.float32)
        labels, distances = self._hnsw_index.knn_query(qn, k=actual_k)
        results = []
        for label, dist in zip(labels[0], distances[0]):
            if 0 <= label < len(self._hnsw_id_map):
                sim = 1.0 - float(dist)
                results.append((sim, self._hnsw_id_map[label]))
        return results

    def _search_numpy(
        self,
        entries: List[AdversarialEntry],
        q: np.ndarray,
        k: int,
    ) -> List[Tuple[float, AdversarialEntry]]:
        if not entries:
            return []
        valid = [(i, e) for i, e in enumerate(entries) if e.embedding is not None]
        if not valid:
            return []
        mat = np.stack([e.embedding for _, e in valid]).astype(np.float32)
        mat /= np.linalg.norm(mat, axis=1, keepdims=True) + 1e-9
        qn = q.reshape(1, -1)
        qn /= np.linalg.norm(qn) + 1e-9
        sims = (mat @ qn.T).flatten()
        order = np.argsort(-sims)[:k]
        return [(float(sims[row]), valid[row][1]) for row in order]

    def add_threat(
        self,
        text: str,
        category: str = "suspected",
        confidence: float = 0.5,
    ) -> Optional[str]:
        """
        Add or update a threat string in memory.

        Args:
            text: Attack or suspicious text to remember.
            category: "confirmed" or "suspected".
            confidence: Confidence score in [0, 1].

        Returns:
            Entry id if stored, or None if evicted entirely.
        """
        _id, _ = self._add_threat_internal(text, category, confidence)
        return _id

    def add_threat_batch(
        self,
        texts: List[str],
        category: str = "suspected",
        confidence: float = 0.5,
    ) -> List[Tuple[Optional[str], bool]]:
        """
        Bulk-add threat strings to memory.

        Args:
            texts: List of attack text strings.
            category: "confirmed" or "suspected".
            confidence: Confidence score for all entries.

        Returns:
            List of (entry_id, is_new) tuples, one per input text.
        """
        results: List[Tuple[Optional[str], bool]] = []
        for text in texts:
            text = text.strip()
            if not text:
                results.append((None, False))
                continue
            results.append(self._add_threat_internal(text, category, confidence))
        return results

    def _add_threat_internal(
        self,
        text: str,
        category: str,
        confidence: float,
    ) -> tuple[Optional[str], bool]:
        """Returns (entry_id, is_new)."""
        tier = "confirmed" if category == "confirmed" else "suspected"
        h = text_hash(text)
        vec = self._embedder.encode(text)
        self._ensure_dim(vec)

        with self._lock:
            if h in self._by_hash:
                existing = self._by_hash[h]
                existing.times_matched += 1
                existing.last_seen = time.time()
                existing.confidence = max(existing.confidence, confidence)
                if tier == "confirmed" and existing.tier == "suspected":
                    self._suspected.remove(existing)
                    existing.tier = "confirmed"
                    self._confirmed.append(existing)
                self._evict_if_needed()
                return existing.id, False

            entry = new_entry(text, tier=tier, confidence=confidence, embedding=vec)
            self._by_hash[h] = entry
            if tier == "confirmed":
                self._confirmed.append(entry)
            else:
                self._suspected.append(entry)
            self._hnsw_add_entry(entry)
            self._evict_if_needed()
            return entry.id, True

    def query_similarity(self, text: str, k: int = 3) -> Tuple[float, List[str], List[str]]:
        """
        Find nearest stored threats by cosine similarity.

        Args:
            text: Query text.
            k: Number of neighbors per tier to consider.

        Returns:
            Tuple of (max_similarity, matched_text_snippets, matched_entry_ids).

        Raises:
            None.
        """
        q = self._embedder.encode(text)
        self._ensure_dim(q)
        if (
            not AdversarialMemoryBank._fallback_quality_warned
            and hasattr(self._embedder, "using_fallback")
            and self._embedder.using_fallback
            and (self._confirmed or self._suspected)
        ):
            logger.warning(
                "Memory bank has entries but embedder is using hash fallback. "
                "Similarity matching will be unreliable. "
                "Install sentence-transformers for production use."
            )
            AdversarialMemoryBank._fallback_quality_warned = True
        with self._lock:
            max_sim = 0.0
            texts_out: List[str] = []
            ids_out: List[str] = []
            if self._hnsw_index is not None and self._hnsw_id_map:
                for sim, ent in self._search_hnsw(q, k * 2):
                    max_sim = max(max_sim, sim)
                    texts_out.append(ent.text[:200])
                    ids_out.append(ent.id)
            else:
                for sim, ent in self._search_numpy(self._confirmed, q, k):
                    max_sim = max(max_sim, sim)
                    texts_out.append(ent.text[:200])
                    ids_out.append(ent.id)
                for sim, ent in self._search_numpy(self._suspected, q, k):
                    max_sim = max(max_sim, sim)
                    texts_out.append(ent.text[:200])
                    ids_out.append(ent.id)
            return max_sim, texts_out, ids_out

    def max_similarity_by_tier(self, text: str) -> Tuple[float, float]:
        """
        Return max cosine similarity against confirmed-only and suspected-only entries.

        Args:
            text: Query string.

        Returns:
            (max_confirmed_sim, max_suspected_sim).

        Raises:
            None.
        """
        q = self._embedder.encode(text)
        self._ensure_dim(q)
        with self._lock:
            mc = 0.0
            ms = 0.0
            if self._confirmed:
                sims = self._search_numpy(self._confirmed, q, len(self._confirmed))
                mc = max((s for s, _ in sims), default=0.0)
            if self._suspected:
                sims = self._search_numpy(self._suspected, q, len(self._suspected))
                ms = max((s for s, _ in sims), default=0.0)
            return mc, ms

    def record_query_match(self, text: str, threshold: float = 0.75) -> None:
        """
        If query is similar enough to a stored entry, increment that entry's match count.

        Args:
            text: Query text.
            threshold: Minimum cosine similarity to count as a match.

        Returns:
            None.

        Raises:
            None.
        """
        q = self._embedder.encode(text)
        self._ensure_dim(q)
        with self._lock:
            best: Optional[AdversarialEntry] = None
            best_sim = 0.0
            for e in self._confirmed + self._suspected:
                if e.embedding is None:
                    continue
                v = e.embedding.astype(np.float32)
                v = v / (np.linalg.norm(v) + 1e-9)
                qq = q / (np.linalg.norm(q) + 1e-9)
                sim = float(np.dot(qq, v))
                if sim > best_sim:
                    best_sim = sim
                    best = e
            if best is not None and best_sim >= threshold:
                best.times_matched += 1
                best.last_seen = time.time()
            self.promote_from_matches()

    def decay_suspected(self, decay_rate: float = 0.995) -> None:
        """
        Apply decay to suspected entries that were never matched; drop weak entries.

        Args:
            decay_rate: Multiplicative decay per cycle for unmatched suspected entries.

        Returns:
            None.

        Raises:
            None.
        """
        with self._lock:
            kept: List[AdversarialEntry] = []
            for e in self._suspected:
                if e.times_matched == 0:
                    e.decay_weight *= decay_rate
                else:
                    e.decay_weight = min(1.0, e.decay_weight * 1.01)
                if e.decay_weight >= 0.10:
                    kept.append(e)
                else:
                    self._by_hash.pop(e.text_hash, None)
            self._suspected = kept

    def _evict_if_needed(self) -> None:
        total = len(self._confirmed) + len(self._suspected)
        if total <= self._max_entries:
            return
        max_c = int(self._max_entries * 0.6)
        max_s = self._max_entries - max_c

        def priority(e: AdversarialEntry) -> float:
            recency = min(1.0, e.last_seen / (time.time() + 1.0))
            return (
                e.confidence * 0.35
                + min(10, e.times_matched) * 0.10
                + e.decay_weight * 0.25
                + recency * 0.30
            )

        while len(self._confirmed) > max_c:
            victim = min(self._confirmed, key=priority)
            self._confirmed.remove(victim)
            self._by_hash.pop(victim.text_hash, None)
        while len(self._suspected) > max_s:
            victim = min(self._suspected, key=priority)
            self._suspected.remove(victim)
            self._by_hash.pop(victim.text_hash, None)

    def promote_from_matches(self) -> None:
        """Promote suspected entries that matched often enough."""
        promoted: List[AdversarialEntry] = []
        remain: List[AdversarialEntry] = []
        for e in self._suspected:
            if e.times_matched >= 3 and e.confidence >= 0.70:
                e.tier = "confirmed"
                promoted.append(e)
            else:
                remain.append(e)
        self._suspected = remain
        self._confirmed.extend(promoted)

    def save(self, path: str, signing_key: Optional[str] = None) -> None:
        """
        Persist bank state to disk via pickle with optional HMAC integrity check.

        Args:
            path: File path to write.
            signing_key: If provided, an HMAC-SHA256 signature is prepended to the file
                         for tamper detection on load.

        Returns:
            None.

        Raises:
            OSError: On I/O errors.
        """
        with self._lock:
            payload = {
                "version": _SCHEMA_VERSION,
                "dim": self._dim,
                "confirmed": [e.to_dict() for e in self._confirmed],
                "suspected": [e.to_dict() for e in self._suspected],
            }
        data = pickle.dumps(payload)
        with open(path, "wb") as f:
            if signing_key is not None:
                sig = hmac.new(signing_key.encode(), data, hashlib.sha256).digest()
                f.write(sig)
            f.write(data)

    def load(self, path: str, signing_key: Optional[str] = None) -> None:
        """
        Load bank state from pickle with optional HMAC verification.

        Args:
            path: File path to read.
            signing_key: If provided, verifies the HMAC-SHA256 signature and rejects
                         tampered files. Must match the key used during save().

        Returns:
            None.

        Raises:
            OSError: On I/O errors.
            ValueError: On schema mismatch or HMAC verification failure.
        """
        with open(path, "rb") as f:
            raw = f.read()
        if signing_key is not None:
            if len(raw) < 32:
                raise ValueError("file too short: missing HMAC signature")
            sig, data = raw[:32], raw[32:]
            expected = hmac.new(signing_key.encode(), data, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise ValueError("HMAC verification failed: file may be tampered")
        else:
            data = raw
            logger.warning("loading bank without HMAC verification; use signing_key for tamper detection")
        payload = pickle.loads(data)  # noqa: S301
        if not isinstance(payload, dict) or payload.get("version") != _SCHEMA_VERSION:
            raise ValueError("unsupported bank snapshot schema")
        with self._lock:
            self._dim = payload.get("dim")
            self._confirmed = [AdversarialEntry.from_dict(d) for d in payload["confirmed"]]
            self._suspected = [AdversarialEntry.from_dict(d) for d in payload["suspected"]]
            self._by_hash = {e.text_hash: e for e in self._confirmed + self._suspected}
            self._rebuild_hnsw()

    def save_json(self, path: str) -> None:
        """
        Persist bank state as human-readable JSON. Safe — no pickle deserialization risks.

        Args:
            path: File path to write (.json recommended).
        """
        with self._lock:
            payload = {
                "version": _SCHEMA_VERSION,
                "dim": self._dim,
                "confirmed": [e.to_dict() for e in self._confirmed],
                "suspected": [e.to_dict() for e in self._suspected],
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def load_json(self, path: str) -> None:
        """
        Load bank state from JSON file.

        Args:
            path: File path to read.

        Raises:
            OSError: On I/O errors.
            ValueError: On schema mismatch.
        """
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, dict) or payload.get("version") != _SCHEMA_VERSION:
            raise ValueError("unsupported bank snapshot schema")
        with self._lock:
            self._dim = payload.get("dim")
            self._confirmed = [AdversarialEntry.from_dict(d) for d in payload["confirmed"]]
            self._suspected = [AdversarialEntry.from_dict(d) for d in payload["suspected"]]
            self._by_hash = {e.text_hash: e for e in self._confirmed + self._suspected}
            self._rebuild_hnsw()

    def export_threats(self, include_embeddings: bool = False) -> list[dict]:
        """
        Export all entries as a portable list of dicts for threat intelligence sharing.

        Args:
            include_embeddings: If True, include embedding vectors (large).
                                If False, only text/metadata are exported.

        Returns:
            List of dicts, one per stored threat.
        """
        with self._lock:
            entries = self._confirmed + self._suspected
        out = []
        for e in entries:
            d = e.to_dict()
            if not include_embeddings:
                d.pop("embedding", None)
            out.append(d)
        return out

    def import_threats(self, entries: list[dict]) -> int:
        """
        Import threats from a portable list of dicts (e.g. from another bank's export).

        Re-embeds text for entries that lack embedding vectors.

        Args:
            entries: List of dicts with at minimum ``text`` and ``tier`` keys.

        Returns:
            Number of new entries added.
        """
        added = 0
        for d in entries:
            text = d.get("text", "").strip()
            if not text:
                continue
            tier = d.get("tier", "suspected")
            confidence = float(d.get("confidence", 0.5))
            _, is_new = self._add_threat_internal(text, category=tier, confidence=confidence)
            if is_new:
                added += 1
        return added
