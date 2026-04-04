"""
Memory-powered benchmark: proves that a small training set of learned attacks
dramatically lifts recall on semantically similar unseen attacks.

Protocol:
  1. Baseline — regex-only assess() on the full deepset corpus.
  2. For each training fraction (5%, 10%, 20%, 50%):
     a. Sample that fraction of missed injections as the "incident log".
     b. train_from_corpus() with those samples.
     c. Re-evaluate the FULL corpus (including the training slice).
     d. Record precision, recall, F1, FPR with the held-out lift separated.

Usage:
    pip install -e ".[memory,dev]" && pip install datasets
    PYTHONPATH=src python bench/run_memory_benchmark.py

Requires sentence-transformers for real semantic similarity.
"""

from __future__ import annotations

import json
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for p in [str(_ROOT), str(_ROOT / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agent_immune import AdaptiveImmuneSystem, ThreatAction
from agent_immune.memory.embedder import TextEmbedder
from agent_immune.memory.bank import AdversarialMemoryBank
from bench.dataset_loader import LabeledRow, load_local_corpus, try_load_deepset

SEED = 42
TRAIN_FRACTIONS = [0.0, 0.05, 0.10, 0.20, 0.50]


@dataclass
class EvalResult:
    stage: str
    train_fraction: float
    train_count: int
    rows: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fpr: float
    held_out_recall: float
    latency_p50_ms: float


def _is_flagged(immune: AdaptiveImmuneSystem, text: str) -> bool:
    a = immune.assess(text, session_id="bench")
    immune.reset_session("bench")
    return a.action in (ThreatAction.BLOCK, ThreatAction.REVIEW, ThreatAction.SANITIZE)


def _evaluate(
    immune: AdaptiveImmuneSystem,
    rows: list[LabeledRow],
    stage: str,
    train_frac: float,
    train_count: int,
    trained_texts: set[str] | None = None,
) -> EvalResult:
    tp = fp = tn = fn = 0
    held_tp = held_fn = 0
    latencies: list[float] = []

    for row in rows:
        t0 = time.perf_counter()
        pred = _is_flagged(immune, row.text)
        latencies.append(time.perf_counter() - t0)

        if row.label == 1 and pred:
            tp += 1
        elif row.label == 1 and not pred:
            fn += 1
        elif row.label == 0 and pred:
            fp += 1
        else:
            tn += 1

        is_held_out = trained_texts is not None and row.text not in trained_texts
        if row.label == 1 and is_held_out:
            if pred:
                held_tp += 1
            else:
                held_fn += 1

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    held_rec = held_tp / (held_tp + held_fn) if (held_tp + held_fn) else 0.0

    latencies.sort()
    p50 = latencies[len(latencies) // 2] * 1000 if latencies else 0

    return EvalResult(
        stage=stage,
        train_fraction=train_frac,
        train_count=train_count,
        rows=len(rows),
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        fpr=round(fpr, 4),
        held_out_recall=round(held_rec, 4),
        latency_p50_ms=round(p50, 2),
    )


def _collect_missed(
    immune: AdaptiveImmuneSystem,
    rows: list[LabeledRow],
) -> list[str]:
    """Return injection texts that regex-only assess() missed."""
    missed: list[str] = []
    for row in rows:
        if row.label == 1 and not _is_flagged(immune, row.text):
            missed.append(row.text)
    return missed


def main() -> None:
    print("=" * 72)
    print("MEMORY-POWERED BENCHMARK")
    print("=" * 72)

    deepset = try_load_deepset()
    local = load_local_corpus()

    if not deepset:
        print("\n[!] deepset/prompt-injections unavailable.")
        print("    pip install datasets   # then re-run")
        print("    Falling back to local-only evaluation.\n")
        corpus = local
        corpus_name = "local"
    else:
        corpus = deepset + local
        corpus_name = "deepset+local"

    injections = [r for r in corpus if r.label == 1]
    benign = [r for r in corpus if r.label == 0]
    print(f"\nCorpus: {len(corpus)} rows ({len(injections)} injections, {len(benign)} benign)")

    results: list[EvalResult] = []
    rng = random.Random(SEED)

    baseline_immune = AdaptiveImmuneSystem()
    print("\n--- Baseline (regex-only, no memory) ---")
    baseline = _evaluate(baseline_immune, corpus, "baseline", 0.0, 0)
    results.append(baseline)
    _print_row(baseline)

    missed = _collect_missed(baseline_immune, corpus)
    print(f"\nMissed injections (false negatives): {len(missed)}")
    if not missed:
        print("Nothing missed — memory benchmark has nothing to train on.")
        _save_results(results, corpus_name)
        return

    for frac in TRAIN_FRACTIONS:
        if frac == 0.0:
            continue

        n_train = max(1, int(len(missed) * frac))
        train_sample = rng.sample(missed, n_train)
        trained_set = set(train_sample)

        embedder = TextEmbedder()
        bank = AdversarialMemoryBank(embedder)
        immune = AdaptiveImmuneSystem(embedder=embedder, bank=bank)

        immune.train_from_corpus(train_sample, category="confirmed", confidence=0.90)

        stage = f"memory_{int(frac * 100)}pct"
        print(f"\n--- {int(frac * 100)}% training ({n_train} attacks learned) ---")
        res = _evaluate(immune, corpus, stage, frac, n_train, trained_set)
        results.append(res)
        _print_row(res)

    _save_results(results, corpus_name)

    print("\n" + "=" * 72)
    print("SUMMARY TABLE")
    print("=" * 72)
    _print_summary_table(results)


def _print_row(r: EvalResult) -> None:
    print(f"  Precision: {r.precision:.3f}  Recall: {r.recall:.3f}  "
          f"F1: {r.f1:.3f}  FPR: {r.fpr:.3f}  "
          f"Held-out recall: {r.held_out_recall:.3f}  "
          f"p50: {r.latency_p50_ms:.2f} ms")


def _print_summary_table(results: list[EvalResult]) -> None:
    header = f"{'Stage':<22} {'Train':>5} {'Prec':>6} {'Recall':>6} {'F1':>6} {'FPR':>5} {'Held-out':>8} {'p50 ms':>7}"
    print(header)
    print("-" * len(header))
    for r in results:
        train_str = f"{r.train_count}" if r.train_count else "-"
        print(f"{r.stage:<22} {train_str:>5} {r.precision:>6.3f} {r.recall:>6.3f} "
              f"{r.f1:>6.3f} {r.fpr:>5.3f} {r.held_out_recall:>8.3f} {r.latency_p50_ms:>7.2f}")


def _save_results(results: list[EvalResult], corpus_name: str) -> None:
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    data = {
        "corpus": corpus_name,
        "seed": SEED,
        "results": [asdict(r) for r in results],
    }
    path = out_dir / "memory_benchmark.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\nResults saved to {path}")


if __name__ == "__main__":
    main()
