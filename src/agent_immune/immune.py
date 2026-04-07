"""
AdaptiveImmuneSystem orchestrates normalization, decomposition, memory, trajectory, and scoring.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time as _time
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Protocol, runtime_checkable

import numpy as np

from agent_immune.core.accumulator import SessionAccumulatorRegistry
from agent_immune.core.decomposer import InputDecomposer
from agent_immune.core.models import OutputScanResult, SecurityPolicy, ThreatAction, ThreatAssessment
from agent_immune.core.normalizer import InputNormalizer
from agent_immune.core.output_scanner import OutputScanner
from agent_immune.core.scorer import ThreatScorer
from agent_immune.rate_limiter import CircuitBreaker

if TYPE_CHECKING:
    from agent_immune.memory.bank import AdversarialMemoryBank

logger = logging.getLogger("agent_immune.immune")


@runtime_checkable
class Embedder(Protocol):
    """Protocol for text embedding backends."""

    def encode(self, text: str) -> np.ndarray: ...


class AdaptiveImmuneSystem:
    """
    Main API for agent-immune.

    Usage:
        immune = AdaptiveImmuneSystem()
        assessment = immune.assess("user text", session_id="s1")
        immune.learn("attack text", category="confirmed", confidence=0.95)
    """

    def __init__(
        self,
        embedder: Optional[Embedder] = None,
        bank: Optional[AdversarialMemoryBank] = None,
        policy: Optional[SecurityPolicy] = None,
        metrics: Optional[object] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        """
        Create orchestrator.

        Args:
            embedder: Optional Embedder (e.g. TextEmbedder); if None, memory features are disabled.
            bank: Optional AdversarialMemoryBank; if None but embedder set, a new bank is created.
            policy: Optional SecurityPolicy with tunable thresholds; uses defaults if None.
            metrics: Optional MetricsCollector for observability; if None, no metrics are emitted.
            circuit_breaker: Optional CircuitBreaker for rate limiting; if None, no rate limiting.
        """
        self._policy = policy or SecurityPolicy()
        self._normalizer = InputNormalizer()
        self._decomposer = InputDecomposer(
            detect_indirect_injection=self._policy.detect_indirect_injection,
        )
        self._output_scanner = OutputScanner(config=self._policy.output_scanner_config)
        self._scorer = ThreatScorer(policy=self._policy)
        self._accumulators = SessionAccumulatorRegistry(max_sessions=self._policy.max_sessions)
        self._embedder = embedder
        self._bank = bank
        self._metrics = metrics
        self._breaker = circuit_breaker
        if embedder is not None and bank is None:
            from agent_immune.memory.bank import AdversarialMemoryBank

            self._bank = AdversarialMemoryBank(embedder)
        self._cycles = 0

    @property
    def policy(self) -> SecurityPolicy:
        """The active security policy."""
        return self._policy

    def assess(self, text: str, session_id: str = "default") -> ThreatAssessment:
        """
        Assess user or tool input text.

        Args:
            text: Raw input string.
            session_id: Session key for trajectory tracking.

        Returns:
            ThreatAssessment with scores and recommended action.
        """
        if self._breaker is not None and self._breaker.is_open(session_id):
            logger.warning("circuit open for session=%s — fast-deny", session_id)
            return ThreatAssessment(
                threat_score=1.0,
                action=ThreatAction.BLOCK,
                pattern_score=0.0,
                memory_score=0.0,
                trajectory_score=1.0,
                session_id=session_id,
                feedback=["circuit_breaker: session rate-limited"],
            )

        t0 = _time.monotonic()
        norm = self._normalizer.normalize(text)
        decomp = self._decomposer.decompose(norm)

        pattern_score = float(decomp.injection_score)
        memory_score = 0.0
        memory_matches: List[str] = []
        max_mem = 0.0
        max_confirmed = 0.0
        if self._bank is not None:
            max_sim, snippets, _ = self._bank.query_similarity(norm.normalized, k=3)
            memory_score = min(1.0, float(max_sim))
            max_mem = memory_score
            memory_matches = snippets
            mc, _ms = self._bank.max_similarity_by_tier(norm.normalized)
            max_confirmed = min(1.0, float(mc))
            if max_sim >= 0.75:
                self._bank.record_query_match(norm.normalized, threshold=0.75)

        acc = self._accumulators.get(session_id)
        trajectory_score = acc.update(pattern_score)
        is_esc = acc.is_escalating()
        hist = acc.history_score

        confirmed_hit = max_confirmed >= 0.90
        assessment = self._scorer.score(
            pattern_score=pattern_score,
            memory_score=memory_score,
            trajectory_score=min(1.0, trajectory_score),
            normalization_suspicion=float(norm.suspicion_from_normalization),
            is_escalating=is_esc,
            pattern_hits=len(decomp.all_hits),
            memory_matches=memory_matches,
            max_memory_similarity=max(max_mem, max_confirmed),
            confirmed_memory_hit=confirmed_hit,
            decomposition=decomp,
            session_id=session_id,
            history_score=hist,
        )
        assessment = assessment.model_copy(update={"normalization": norm})

        self._cycles += 1
        if self._cycles % 100 == 0 and self._bank is not None:
            self.decay_memory()

        latency_ms = (_time.monotonic() - t0) * 1000.0
        if self._breaker is not None and assessment.action == ThreatAction.BLOCK:
            self._breaker.record_block(session_id)
        if self._metrics is not None:
            self._metrics.record_assessment(assessment, latency_ms=latency_ms)
        logger.debug("assess session=%s action=%s latency=%.1fms", session_id, assessment.action, latency_ms)
        return assessment

    def assess_output(self, text: str, session_id: str = "default") -> OutputScanResult:
        """
        Assess model or tool output for exfiltration.

        Args:
            text: Output string.
            session_id: Session used to optionally bump trajectory on high exfiltration.

        Returns:
            OutputScanResult.

        Raises:
            None.
        """
        result = self._output_scanner.scan(text)
        blocked = self.output_blocks(result)
        if result.exfiltration_score >= 0.5:
            acc = self._accumulators.get(f"__output__{session_id}")
            acc.update(min(1.0, result.exfiltration_score))
        if self._metrics is not None:
            self._metrics.record_output_scan(result, blocked=blocked)
        logger.debug("assess_output session=%s score=%s", session_id, result.exfiltration_score)
        return result

    def output_blocks(self, scan: OutputScanResult, threshold: Optional[float] = None) -> bool:
        """
        Return True if output scan should be treated as blocking.

        Args:
            scan: Result from assess_output.
            threshold: Exfiltration score threshold for block. Defaults to policy.output_block_threshold.

        Returns:
            True if output should not be delivered as-is.

        Raises:
            None.
        """
        t = threshold if threshold is not None else self._policy.output_block_threshold
        return scan.exfiltration_score >= t

    def learn(self, text: str, category: str = "suspected", confidence: float = 0.5) -> Optional[str]:
        """
        Add a confirmed or suspected attack to memory.

        Args:
            text: Attack text to store.
            category: "confirmed" or "suspected".
            confidence: Confidence in [0, 1].

        Returns:
            Entry id if stored, else None.

        Raises:
            None.
        """
        if self._bank is None:
            logger.warning("learn called without memory bank")
            return None
        entry_id = self._bank.add_threat(text, category=category, confidence=confidence)
        if entry_id is not None and self._metrics is not None:
            self._metrics.record_learn()
        return entry_id

    def train_from_corpus(
        self,
        attacks: list[str],
        category: str = "confirmed",
        confidence: float = 0.90,
    ) -> int:
        """
        Bulk-load a list of known attack strings into adversarial memory.

        This bootstraps the memory bank from a labeled dataset, public corpus,
        or incident log so that semantically similar future attacks are caught
        even when regex patterns miss them.

        Args:
            attacks: List of attack text strings to memorize.
            category: "confirmed" or "suspected" tier for all entries.
            confidence: Confidence score applied to each entry.

        Returns:
            Number of new entries stored (duplicates are updated, not counted).
        """
        if self._bank is None:
            from agent_immune.memory.embedder import TextEmbedder
            from agent_immune.memory.bank import AdversarialMemoryBank

            self._embedder = TextEmbedder()
            self._bank = AdversarialMemoryBank(self._embedder)
        results = self._bank.add_threat_batch(attacks, category=category, confidence=confidence)
        new_count = sum(1 for entry_id, is_new in results if is_new and entry_id is not None)
        logger.info("train_from_corpus: %d new entries from %d inputs as %s", new_count, len(attacks), category)
        return new_count

    def load_default_corpus(self) -> int:
        """
        Load the built-in curated attack corpus into semantic memory.

        Provides instant protection against 50 common attack patterns across
        11 languages and multiple categories (injection, exfiltration, indirect)
        without requiring any training data from the user.

        Returns:
            Number of new entries stored.
        """
        corpus_path = Path(__file__).parent / "corpus" / "default_attacks.json"
        with open(corpus_path, encoding="utf-8") as f:
            entries = json.load(f)
        attacks = [e["text"] for e in entries]
        return self.train_from_corpus(attacks, category="confirmed", confidence=0.90)

    def decay_memory(self) -> None:
        """
        Run decay on suspected memory entries.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        if self._bank is not None:
            self._bank.decay_suspected()

    def save(self, path: str, *, format: str = "json") -> None:
        """
        Persist adversarial memory bank.

        Args:
            path: Destination file path.
            format: ``"json"`` (default, safe) or ``"pickle"`` (legacy).
        """
        if self._bank is None:
            return
        if format == "json":
            self._bank.save_json(path)
        else:
            self._bank.save(path)

    def load(self, path: str, *, format: str = "json") -> None:
        """
        Load adversarial memory bank snapshot.

        Args:
            path: Source file path.
            format: ``"json"`` (default) or ``"pickle"`` (legacy).
        """
        if self._bank is None:
            return
        if format == "json":
            self._bank.load_json(path)
        else:
            self._bank.load(path)

    def export_threats(self, include_embeddings: bool = False) -> list[dict]:
        """
        Export all stored threats as portable dicts for sharing.

        Args:
            include_embeddings: Include embedding vectors (large).

        Returns:
            List of threat dicts, or empty list if no bank.
        """
        if self._bank is None:
            return []
        return self._bank.export_threats(include_embeddings=include_embeddings)

    def import_threats(self, entries: list[dict]) -> int:
        """
        Import threats from a portable list (e.g. from another instance's export).

        Auto-initializes the memory bank if needed.

        Args:
            entries: List of dicts with at minimum ``text`` and ``tier`` keys.

        Returns:
            Number of new entries added.
        """
        if self._bank is None:
            from agent_immune.memory.embedder import TextEmbedder
            from agent_immune.memory.bank import AdversarialMemoryBank

            self._embedder = TextEmbedder()
            self._bank = AdversarialMemoryBank(self._embedder)
        return self._bank.import_threats(entries)

    def reset_session(self, session_id: str) -> None:
        """
        Reset trajectory state for a session.

        Args:
            session_id: Session to clear.

        Returns:
            None.

        Raises:
            None.
        """
        self._accumulators.reset(session_id)

    def get_clean_text(self, assessment: ThreatAssessment) -> str:
        """
        Return sanitized text from a prior assessment.

        Args:
            assessment: Prior ThreatAssessment with decomposition.

        Returns:
            Cleaned text or original empty string.

        Raises:
            None.
        """
        if assessment.decomposition is None:
            return ""
        return assessment.decomposition.clean_text

    # ------------------------------------------------------------------
    # Async API — non-blocking wrappers for use in async agent frameworks
    # ------------------------------------------------------------------

    async def assess_async(self, text: str, session_id: str = "default") -> ThreatAssessment:
        """Async version of :meth:`assess`. Runs CPU-bound work in a thread."""
        return await asyncio.to_thread(self.assess, text, session_id)

    async def assess_output_async(self, text: str, session_id: str = "default") -> OutputScanResult:
        """Async version of :meth:`assess_output`."""
        return await asyncio.to_thread(self.assess_output, text, session_id)

    async def learn_async(self, text: str, category: str = "suspected", confidence: float = 0.5) -> Optional[str]:
        """Async version of :meth:`learn`."""
        return await asyncio.to_thread(self.learn, text, category, confidence)

    async def train_from_corpus_async(
        self,
        attacks: list[str],
        category: str = "confirmed",
        confidence: float = 0.90,
    ) -> int:
        """Async version of :meth:`train_from_corpus`."""
        return await asyncio.to_thread(self.train_from_corpus, attacks, category, confidence)
