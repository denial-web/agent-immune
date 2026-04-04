# Architecture

agent-immune sits between an agent application and tool execution, scoring **inputs** (user messages, tool arguments) and **outputs** (LLM replies, tool results).

## Data flow

1. **InputNormalizer** — strips zero-width characters, folds common homoglyphs, normalizes fullwidth ASCII, strips HTML-like tags (without removing ChatML tokens), optional base64 decoding when decoded text matches threat keywords, light markdown fence stripping, spaced-letter collapse.
2. **InputDecomposer** — runs weighted regex families (injection, exfiltration, secret, escalation, delimiters) on normalized text; applies quoted-region down-weighting; Khmer + English keyword mixing heuristic; multilingual injection patterns (English, German, Spanish, French, Croatian, Russian); emits `DecompositionResult` with `[REDACTED]` clean text.
3. **AdversarialMemoryBank** (optional) — sentence-transformer embeddings + NumPy cosine similarity search; confirmed vs suspected tiers; deduplication, decay, and thread-safe operations.
4. **ThreatAccumulator** — per-session EMA and escalation detection across turns; independent history signal blending session-max and block frequency.
5. **ThreatScorer** — weighted blend: `raw = pattern * 0.28 + memory * 0.28 + trajectory * 0.16 + normalization * 0.12 + escalation * 0.08 + history * 0.08`. Pattern floor (`0.28 + 0.62 * pattern_score`) applied when `pattern_score >= 0.25`, ensuring patterns alone always flag threats; memory is purely additive lift. All thresholds are configurable via `SecurityPolicy`.
6. **OutputScanner** — heuristic scan for PII, credentials, prompt-leak phrases, encoded blobs, and bulky structured output.

## SecurityPolicy

All detection thresholds are configurable via a frozen Pydantic model:

- `allow_threshold`, `sanitize_threshold`, `review_threshold` — action band boundaries
- `output_block_threshold` — exfiltration score that blocks output delivery
- `memory_confirm_threshold`, `memory_review_threshold` — similarity overrides
- `escalation_upgrade` — toggle escalation detection action upgrade
- `max_sessions` — LRU cap on session accumulator registry

## Async API

All core methods (`assess`, `assess_output`, `learn`, `train_from_corpus`) have `*_async` variants that wrap CPU-bound work in `asyncio.to_thread()`, keeping the event loop responsive in async agent frameworks.

## Persistence

- **JSON** (default) — `save_json()` / `load_json()` on `AdversarialMemoryBank`; exposed as `immune.save(path)` / `immune.load(path)`. Human-readable, no pickle deserialization risks.
- **Pickle** (legacy) — `save(path, format="pickle")` / `load(path, format="pickle")`. Supports optional HMAC-SHA256 signing for tamper detection.
- **Threat export/import** — `export_threats()` returns portable dicts (optionally with embeddings); `import_threats()` ingests them and re-embeds text that lacks vectors. Enables cross-instance threat intelligence sharing.

## Observability

- **MetricsCollector** (`observability.py`) — thread-safe in-process counters: assessment totals, block/review/allow breakdown, output scan counts, learn events, latency (avg + max). Attach via `AdaptiveImmuneSystem(metrics=collector)`.
- **Structured events** — `emit_event()` writes JSON payloads to the `agent_immune.events` logger. Each `assess()` and `assess_output()` call emits an event with action, scores, session_id, and latency.
- **JSON logging** — `configure_json_logging()` sets up a stderr JSON formatter on the `agent_immune` logger hierarchy.

## Adapters

- **AGT** (`adapters/agt.py`) — `ImmunePolicyEvaluator` and `ImmuneIntegration` with `pre_execute` / `post_execute` semantics aligned with Microsoft Agent OS patterns.
- **LangChain** — `ImmuneCallbackHandler.build()` returns a `BaseCallbackHandler` subclass.
- **MCP** — `ImmuneMCPMiddleware.intercept` for JSON-shaped messages. Supports `use_async=True` for non-blocking embedding.
