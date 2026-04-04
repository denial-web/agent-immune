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
- **Latency** — `latency_p50_ms` is for `AdaptiveImmuneSystem.assess` only (core path); memory mode requires embedding model load and FAISS/NumPy search.

## External datasets

- **Lakera PINT** — `datasets` loader in `bench/dataset_loader.py`; verify license before redistributing snapshots.
- **JailbreakBench** — can be wired similarly; not enabled by default to keep CI offline-friendly.

Document any new dataset in this file with citation and license.
