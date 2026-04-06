# Changelog

All notable changes to agent-immune are documented here.

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
