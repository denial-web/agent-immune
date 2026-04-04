"""
Adversarial memory entry types and serialization helpers.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np


def text_hash(text: str) -> str:
    """Return SHA-256 hex digest of normalized text."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


@dataclass
class AdversarialEntry:
    """Single stored adversarial or suspicious prompt embedding record."""

    id: str
    text: str
    text_hash: str
    tier: str  # "confirmed" | "suspected"
    confidence: float
    times_matched: int = 0
    decay_weight: float = 1.0
    last_seen: float = field(default_factory=time.time)
    embedding: Optional[np.ndarray] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize entry to a JSON-friendly dict (embedding as list)."""
        emb: Optional[List[float]] = None
        if self.embedding is not None:
            emb = self.embedding.astype(np.float32).tolist()
        return {
            "id": self.id,
            "text": self.text,
            "text_hash": self.text_hash,
            "tier": self.tier,
            "confidence": self.confidence,
            "times_matched": self.times_matched,
            "decay_weight": self.decay_weight,
            "last_seen": self.last_seen,
            "embedding": emb,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AdversarialEntry":
        """Deserialize entry from dict."""
        emb = d.get("embedding")
        arr = np.array(emb, dtype=np.float32) if emb is not None else None
        return AdversarialEntry(
            id=d["id"],
            text=d["text"],
            text_hash=d["text_hash"],
            tier=d["tier"],
            confidence=float(d["confidence"]),
            times_matched=int(d["times_matched"]),
            decay_weight=float(d["decay_weight"]),
            last_seen=float(d["last_seen"]),
            embedding=arr,
        )


def new_entry(
    text: str,
    tier: str,
    confidence: float,
    embedding: np.ndarray,
) -> AdversarialEntry:
    """Factory for a new AdversarialEntry with fresh id and hash."""
    return AdversarialEntry(
        id=str(uuid.uuid4()),
        text=text,
        text_hash=text_hash(text),
        tier=tier,
        confidence=confidence,
        embedding=embedding.astype(np.float32),
    )
