# Benchmarks

## Local runner

From the repository root:

```bash
python bench/run_benchmarks.py
```

This scores the **combined** labeled set (optional HuggingFace PINT sample if `pip install datasets` succeeds, plus all `tests/attacks/*.json` files with heuristic labels).

Results are written to `bench/results/last_run.json` (directory gitignored).

## Interpreting metrics

- **Precision / FPR** — sensitive deployments should watch false positives on `benign_inputs.json`.
- **Recall** — raises when attack JSON rows are scored as `allow` with sanitize/review/block disabled; tighten patterns or add memory entries.
- **Latency** — `latency_p50_ms` is for `AdaptiveImmuneSystem.assess` only (core path); memory mode requires embedding model load and NumPy cosine search (~20 ms/query).

## Current results

### Regex-only baseline

| Dataset | Rows | Precision | Recall | F1 | FPR |
|---------|------|-----------|--------|----|-----|
| Local corpus | 185 | 1.000 | 0.902 | **0.949** | 0.0 |
| deepset/prompt-injections | 662 | 1.000 | 0.342 | 0.510 | 0.0 |
| Combined | 847 | 1.000 | 0.521 | 0.685 | 0.0 |

### With adversarial memory (50% training)

| Metric | Value |
|--------|-------|
| F1 | **0.865** |
| Recall | 0.762 |
| Held-out recall | **0.701** |
| FPR | 0.000 |

Run `python bench/run_memory_benchmark.py` for the full training-fraction sweep.

## External datasets

- **deepset/prompt-injections** — English + German labeled prompts; 263 injections + 399 benign. `pip install datasets` to enable.
- **Lakera PINT** — `datasets` loader in `bench/dataset_loader.py`; verify license before redistributing snapshots.
- **JailbreakBench** — can be wired similarly; not enabled by default to keep CI offline-friendly.

Document any new dataset in this file with citation and license.
