"""
Run lightweight benchmarks: precision/recall/F1 on labeled rows, plus rough latency.

Usage: PYTHONPATH=src python bench/run_benchmarks.py
"""

from __future__ import annotations

import json
import logging
import statistics
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from agent_immune import AdaptiveImmuneSystem, ThreatAction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent_immune.bench")

from bench.dataset_loader import load_local_corpus, try_load_pint_sample  # noqa: E402


def _predict_malicious(immune: AdaptiveImmuneSystem, text: str) -> bool:
    a = immune.assess(text)
    return a.action in (ThreatAction.BLOCK, ThreatAction.REVIEW, ThreatAction.SANITIZE)


def main() -> None:
    immune = AdaptiveImmuneSystem()
    rows = load_local_corpus()
    pint = try_load_pint_sample(max_rows=300)
    if pint:
        rows = pint + rows
        logger.info("combined PINT sample + local: %s rows", len(rows))

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    for row in rows:
        t0 = time.perf_counter()
        pred = _predict_malicious(immune, row.text)
        latencies.append(time.perf_counter() - t0)
        if row.label == 1 and pred:
            tp += 1
        elif row.label == 1 and not pred:
            fn += 1
        elif row.label == 0 and pred:
            fp += 1
        else:
            tn += 1

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    out = {
        "rows": len(rows),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "latency_p50_ms": round(statistics.median(latencies) * 1000, 3),
    }
    print(json.dumps(out, indent=2))

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / "last_run.json").write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
