"""Semantic adversarial memory (optional sentence-transformers + FAISS)."""

from agent_immune.memory.bank import AdversarialMemoryBank
from agent_immune.memory.embedder import TextEmbedder

__all__ = ["AdversarialMemoryBank", "TextEmbedder"]
