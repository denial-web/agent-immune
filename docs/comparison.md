# Comparison (conceptual)

| Approach | Strengths | agent-immune |
|----------|-----------|----------------|
| Rule-only governance (e.g. Agent OS `blocked_patterns`) | Fast, deterministic, auditable | Complements: adds semantic memory + trajectory |
| DeBERTa classifiers (e.g. prompt-shield style) | Strong offline accuracy on similar distributions | Lighter default; optional embeddings; learns from your incidents |
| Embedding drift (ZEDD / AgentShield) | Zero-shot semantic signal | Adds **persistent** memory + multi-turn escalation |
| Red-team scanners (e.g. AgentSeal) | Broad probe libraries | Runtime middleware, not a replacement for periodic audits |

Published third-party numbers (prompt-shield, AgentShield, etc.) are measured on their datasets and models; run `python bench/run_benchmarks.py` for **your** combined local (+ optional PINT sample) metrics.
