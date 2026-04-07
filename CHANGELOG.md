# Changelog

All notable changes to agent-immune are documented here.

## [0.2.0] — 2026-04-07

### Added

- **Multilingual injection detection** — 12 new patterns for Chinese, Japanese, Korean, Arabic, and Hindi. Total: 11 languages.
- **Generalized script-mixing detector** — any non-Latin script (CJK, Arabic, Devanagari, Hangul) mixed with English imperatives now triggers detection (previously Khmer-only).
- **Indirect injection patterns** — HTML comment injection, markdown comment injection, confused deputy attacks, URL-embedded payloads. Gated behind `SecurityPolicy.detect_indirect_injection` flag.
- **Configurable output scanner** — new `OutputScannerConfig` model with per-category weights (PII, credentials, base64, hex, etc.). Passed via `SecurityPolicy.output_scanner_config`.
- **Reduced false positives** — output scanner now exempts SHA-256/512 hex hashes, requires threat keywords in decoded base64, and distinguishes bare JWT tokens from documented examples.
- **Optional ANN index** — `hnswlib`-backed HNSW index for memory bank search, reducing query time from O(n) to O(log n). Install via `pip install 'agent-immune[fast-memory]'`. Falls back to NumPy when not installed.
- **Public batch API** — `AdversarialMemoryBank.add_threat_batch()` for bulk loading. `train_from_corpus` now uses the public API instead of private internals.
- **MCP server memory** — `build_mcp()` now initializes with a working embedder and memory bank. `learn_threat` actually stores patterns. Fallback embedder status surfaced in tool responses.
- **Fallback embedder warnings** — `TextEmbedder.using_fallback` property; logs WARNING when hash-based fallback is active. Memory bank warns about degraded matching quality.

### Changed

- `DecompositionResult` now includes `indirect_hits` field.
- Volume anomaly condition in output scanner explicitly parenthesized for clarity.
- Test fixtures diversified: replaced 46 repetitive jailbreak variants with 28 genuinely distinct attack patterns across multiple categories and languages.
- Russian injection pattern updated to handle post-homoglyph-normalization text.

### Fixed

- MCP `learn_threat` tool now correctly stores entries (was silently returning `stored: false` due to missing memory bank).

### Stats

- **181 tests**, 0 lint errors, 11 languages supported.

## [0.1.1] — 2026-04-07

### Added

- **MCP server** now included in PyPI package — `pip install 'agent-immune[mcp]'` works from PyPI.
- **PyPI publish workflow** — auto-publishes on GitHub release via trusted publishing.
- **CI tests MCP** on Python 3.12+ (skips gracefully on 3.9).
- **`py.typed`** marker file for PEP 561 typed package support.
- **`CONTRIBUTING.md`** and **`SECURITY.md`** for open-source best practices.
- **`glama.json`** for Glama marketplace integration.
- Glama badge in README.

## [0.1.0] — 2026-04-04

### Added

- **Circuit breaker / rate limiter** — per-session sliding-window rate limiter that auto-denies sessions exceeding block thresholds; wired into `assess()` for zero-cost fast-deny.
- **Prompt hardening module** — `PromptHardener` with system prompt role-lock, user input sandboxing, and output guard self-check. Composable `harden_messages()` for standard message lists.
- **JSON persistence** — `save_json()` / `load_json()` on memory bank; `immune.save()` / `immune.load()` default to JSON. Safe, human-readable, no pickle risks.
- **Threat intelligence sharing** — `export_threats()` / `import_threats()` for cross-instance threat portability.
- **Observability** — `MetricsCollector` with counters (assessments, blocks, reviews, output scans, learns) and latency tracking (avg + max). Structured JSON event logging via `agent_immune.events` logger. `configure_json_logging()` helper.
- **Configurable SecurityPolicy** — frozen Pydantic model with tunable thresholds for all detection bands, memory overrides, escalation, and session limits.
- **Async API** — `assess_async`, `assess_output_async`, `learn_async`, `train_from_corpus_async` via `asyncio.to_thread()`. MCP middleware supports `use_async=True`.
- **CLI** — `python -m agent_immune assess` / `scan-output` with JSON output, stdin piping.
- **MCP server** — `python -m agent_immune serve` with `--transport` (`stdio`, `sse`, `streamable-http`, `http`) and `--port`; tools `assess_input`, `assess_output`, `learn_threat`, `harden_prompt`, `get_metrics`. Optional extra: `pip install 'agent-immune[mcp]'`.
- **LRU session eviction** — `SessionAccumulatorRegistry` caps tracked sessions to prevent unbounded memory growth.
- **HMAC persistence** — optional HMAC-SHA256 signing for pickle-based bank snapshots.
- **Decomposer hit bucketing** — `exfiltration_hits`, `secret_hits`, `escalation_hits` properly routed to their own categories.
- **GitHub Actions CI** — lint + test on Python 3.9/3.11/3.13, benchmark run on 3.11.
- **Multilingual patterns** — injection detection for English, German, Spanish, French, Croatian, and Russian.
- **Benchmarks** — regex-only baseline + adversarial memory benchmark against deepset/prompt-injections (F1: 0.685 → 0.865 with 92 learned attacks).
- **Six demo scripts** — standalone scoring, semantic catch, escalation, AGT hooks, learning loop, encoding bypass.
- **179 tests, 94% coverage**.

### Core modules

- `InputNormalizer` — zero-width stripping, homoglyph folding, base64/ROT13 decoding, HTML/markdown stripping.
- `InputDecomposer` — weighted regex families with quoted-region down-weighting and Khmer heuristic.
- `AdversarialMemoryBank` — sentence-transformer embeddings + NumPy cosine search, confirmed/suspected tiers, dedup, decay.
- `ThreatAccumulator` — per-session EMA with escalation detection and history signal.
- `ThreatScorer` — weighted blend with pattern floor to prevent memory suppression.
- `OutputScanner` — PII, credentials, system prompt leak, encoded payloads, volume anomaly detection.

### Adapters

- **AGT** — `ImmunePolicyEvaluator` and `ImmuneIntegration` for Microsoft Agent OS.
- **LangChain** — `ImmuneCallbackHandler` callback handler.
- **MCP** — `ImmuneMCPMiddleware` for JSON-shaped message interception.
