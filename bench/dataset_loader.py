"""
Load benchmark datasets: optional HuggingFace PINT/JailbreakBench, or local tests/attacks JSON.

Attribution: record dataset names and licenses in docs/benchmarks.md when using public corpora.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger("agent_immune.bench.dataset_loader")

_REPO_ATTACKS = Path(__file__).resolve().parent.parent / "tests" / "attacks"


@dataclass
class LabeledRow:
    """Single labeled prompt for benchmark."""

    text: str
    label: int  # 1 = malicious / injection-related, 0 = benign


def load_local_corpus() -> List[LabeledRow]:
    """
    Load hand-authored JSON files under tests/attacks as a single benchmark set.

    Args:
        None.

    Returns:
        List of LabeledRow.

    Raises:
        OSError: If files are missing.
    """
    rows: List[LabeledRow] = []
    mapping = [
        ("injection_attacks.json", 1),
        ("exfiltration_attacks.json", 1),
        ("encoding_bypass_attacks.json", 1),
        ("benign_inputs.json", 0),
    ]
    for fname, label in mapping:
        path = _REPO_ATTACKS / fname
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            if "text" not in item:
                continue
            rows.append(LabeledRow(text=item["text"], label=label))
    kpath = _REPO_ATTACKS / "khmer_mixed_attacks.json"
    with open(kpath, encoding="utf-8") as f:
        kdata = json.load(f)
    for item in kdata:
        if "text" not in item:
            continue
        if "expected_min_score" in item:
            rows.append(LabeledRow(text=item["text"], label=1))
        else:
            rows.append(LabeledRow(text=item["text"], label=0))
    logger.info("loaded %s local benchmark rows", len(rows))
    return rows


def try_load_pint_sample(max_rows: int = 500) -> Optional[List[LabeledRow]]:
    """
    Try to load a sample of the Lakera PINT benchmark via HuggingFace `datasets`.

    Args:
        max_rows: Cap rows to keep runs fast.

    Returns:
        Rows or None if datasets unavailable / load fails.

    Raises:
        None.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        logger.warning("datasets not installed; skipping PINT")
        return None
    try:
        ds = load_dataset("lakera/pint-benchmark", split="train")
    except Exception as exc:
        logger.warning("PINT load failed: %s", exc)
        return None
    rows: List[LabeledRow] = []
    for i, item in enumerate(ds):
        if i >= max_rows:
            break
        text = str(item.get("text") or item.get("prompt") or "")
        label = int(item.get("label", item.get("is_injection", 0)))
        rows.append(LabeledRow(text=text, label=label))
    return rows


def iter_all_sources() -> Iterator[LabeledRow]:
    """Yield rows from PINT sample if available, else local corpus only."""
    pint = try_load_pint_sample()
    if pint:
        yield from pint
    yield from load_local_corpus()
