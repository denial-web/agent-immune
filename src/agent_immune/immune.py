"""
AdaptiveImmuneSystem orchestrates normalization, decomposition, memory, trajectory, and scoring.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from agent_immune.core.accumulator import SessionAccumulatorRegistry
from agent_immune.core.decomposer import InputDecomposer
from agent_immune.core.models import OutputScanResult, ThreatAssessment
from agent_immune.core.normalizer import InputNormalizer
from agent_immune.core.output_scanner import OutputScanner
from agent_immune.core.scorer import ThreatScorer

logger = logging.getLogger("agent_immune.immune")


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
        embedder: Optional[object] = None,
        bank: Optional[object] = None,
    ) -> None:
        """
        Create orchestrator.

        Args:
            embedder: Optional TextEmbedder; if None, memory features are disabled.
            bank: Optional AdversarialMemoryBank; if None but embedder set, a new bank is created.

        Returns:
            None.

        Raises:
            None.
        """
        self._normalizer = InputNormalizer()
        self._decomposer = InputDecomposer()
        self._output_scanner = OutputScanner()
        self._scorer = ThreatScorer()
        self._accumulators = SessionAccumulatorRegistry()
        self._embedder = embedder
        self._bank = bank
        if embedder is not None and bank is None:
            from agent_immune.memory.bank import AdversarialMemoryBank

            self._bank = AdversarialMemoryBank(embedder)  # type: ignore[arg-type]
        self._cycles = 0

    def assess(self, text: str, session_id: str = "default") -> ThreatAssessment:
        """
        Assess user or tool input text.

        Args:
            text: Raw input string.
            session_id: Session key for trajectory tracking.

        Returns:
            ThreatAssessment with scores and recommended action.

        Raises:
            None.
        """
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
            pattern_hits=len(decomp.injection_hits) + len(decomp.delimiter_hits),
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
        logger.debug("assess session=%s action=%s", session_id, assessment.action)
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
        if result.exfiltration_score >= 0.5:
            acc = self._accumulators.get(f"__output__{session_id}")
            acc.update(min(1.0, result.exfiltration_score))
        logger.debug("assess_output session=%s score=%s", session_id, result.exfiltration_score)
        return result

    def output_blocks(self, scan: OutputScanResult, threshold: float = 0.72) -> bool:
        """
        Return True if output scan should be treated as blocking.

        Args:
            scan: Result from assess_output.
            threshold: Exfiltration score threshold for block.

        Returns:
            True if output should not be delivered as-is.

        Raises:
            None.
        """
        return scan.exfiltration_score >= threshold

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
        return self._bank.add_threat(text, category=category, confidence=confidence)

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
            Number of entries actually stored (deduplicated).
        """
        if self._bank is None:
            from agent_immune.memory.embedder import TextEmbedder
            from agent_immune.memory.bank import AdversarialMemoryBank

            self._embedder = TextEmbedder()
            self._bank = AdversarialMemoryBank(self._embedder)
        stored = 0
        for text in attacks:
            text = text.strip()
            if not text:
                continue
            entry_id = self._bank.add_threat(text, category=category, confidence=confidence)
            if entry_id is not None:
                stored += 1
        logger.info("train_from_corpus: stored %d/%d attacks as %s", stored, len(attacks), category)
        return stored

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

    def save(self, path: str) -> None:
        """
        Persist adversarial memory bank.

        Args:
            path: Destination file path.

        Returns:
            None.

        Raises:
            OSError: On I/O errors.
        """
        if self._bank is None:
            return
        self._bank.save(path)

    def load(self, path: str) -> None:
        """
        Load adversarial memory bank snapshot.

        Args:
            path: Source file path.

        Returns:
            None.

        Raises:
            OSError, ValueError: On failure.
        """
        if self._bank is None:
            return
        self._bank.load(path)

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
