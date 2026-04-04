# Architecture

agent-immune sits between an agent application and tool execution, scoring **inputs** (user messages, tool arguments) and **outputs** (LLM replies, tool results).

## Data flow

1. **InputNormalizer** — strips zero-width characters, folds common homoglyphs, normalizes fullwidth ASCII, strips HTML-like tags (without removing ChatML tokens), optional base64 decoding when decoded text matches threat keywords, light markdown fence stripping, spaced-letter collapse.
2. **InputDecomposer** — runs weighted regex families (injection, exfiltration, secret, escalation, delimiters) on normalized text; applies quoted-region down-weighting; Khmer + English keyword mixing heuristic; multilingual injection patterns (English, German, Spanish, French, Croatian, Russian); emits `DecompositionResult` with `[REDACTED]` clean text.
3. **AdversarialMemoryBank** (optional) — sentence-transformer embeddings + NumPy cosine similarity search; confirmed vs suspected tiers; deduplication, decay, and thread-safe operations.
4. **ThreatAccumulator** — per-session EMA and escalation detection across turns; independent history signal blending session-max and block frequency.
5. **ThreatScorer** — weighted blend: `raw = pattern * 0.28 + memory * 0.28 + trajectory * 0.16 + normalization * 0.12 + escalation * 0.08 + history * 0.08`. Pattern floor (`0.28 + 0.62 * pattern_score`) applied when `pattern_score >= 0.25`, ensuring patterns alone always flag threats; memory is purely additive lift. Threshold actions: allow / sanitize / review / block.
6. **OutputScanner** — heuristic scan for PII, credentials, prompt-leak phrases, encoded blobs, and bulky structured output.

## Adapters

- **AGT** (`adapters/agt.py`) — `ImmunePolicyEvaluator` and `ImmuneIntegration` with `pre_execute` / `post_execute` semantics aligned with Microsoft Agent OS patterns.
- **LangChain** — `ImmuneCallbackHandler.build()` returns a `BaseCallbackHandler` subclass.
- **MCP** — `ImmuneMCPMiddleware.intercept` for JSON-shaped messages.
