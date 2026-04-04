"""
Lazy-loaded text embedder using sentence-transformers when available, with deterministic test fallback.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import List, Optional

import numpy as np

logger = logging.getLogger("agent_immune.memory.embedder")

_EMBED_DIM_FALLBACK = 384


def _hash_embed(text: str) -> np.ndarray:
    """Deterministic pseudo-embedding for tests without sentence-transformers."""
    digest = hashlib.sha256(text.encode()).digest()
    rng = np.random.RandomState(int.from_bytes(digest[:4], "big"))
    vec = rng.randn(_EMBED_DIM_FALLBACK).astype(np.float32)
    vec /= np.linalg.norm(vec) + 1e-9
    return vec


class TextEmbedder:
    """Encode text to L2-normalized float32 vectors."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        """
        Create embedder; model loads on first encode.

        Args:
            model_name: sentence-transformers model id.

        Returns:
            None.

        Raises:
            None.
        """
        self._model_name = model_name
        self._model: object | str | None = None
        self._dim: Optional[int] = None
        self._init_lock = threading.Lock()

    def encode(self, text: str) -> np.ndarray:
        """
        Encode a single string to a normalized vector.

        Args:
            text: Input text.

        Returns:
            float32 numpy vector of shape (dimension,).

        Raises:
            RuntimeError: If encoding fails unexpectedly.
        """
        return self.encode_batch([text])[0]

    def encode_batch(self, texts: List[str]) -> np.ndarray:
        """
        Encode multiple strings.

        Args:
            texts: Non-empty list of strings.

        Returns:
            float32 array of shape (len(texts), dimension).

        Raises:
            RuntimeError: If the backend fails.
        """
        if not texts:
            raise ValueError("texts must be non-empty")
        if self._model is None:
            with self._init_lock:
                if self._model is None:
                    try:
                        from sentence_transformers import SentenceTransformer

                        self._model = SentenceTransformer(self._model_name)
                        logger.info("loaded sentence-transformers model=%s", self._model_name)
                    except Exception as exc:
                        logger.warning("sentence-transformers unavailable (%s); using hash fallback", exc)
                        self._model = "fallback"
        if self._model == "fallback":
            return np.stack([_hash_embed(t) for t in texts], axis=0)
        encode_fn = getattr(self._model, "encode")
        out = encode_fn(texts, normalize_embeddings=True)
        arr = np.asarray(out, dtype=np.float32)
        if self._dim is None:
            self._dim = int(arr.shape[-1])
        norms = np.linalg.norm(arr, axis=1, keepdims=True) + 1e-9
        arr = arr / norms
        return arr

    @property
    def dimension(self) -> int:
        """
        Return embedding dimension after a probe encode.

        Args:
            None.

        Returns:
            Vector dimension.

        Raises:
            None.
        """
        if self._dim is not None:
            return self._dim
        _ = self.encode("dimension probe")
        return int(self._dim or _EMBED_DIM_FALLBACK)
