# Architecture

agent-immune sits between an agent application and tool execution, scoring **inputs** (user messages, tool arguments) and **outputs** (LLM replies, tool results).

## Data flow

1. **InputNormalizer** — strips zero-width characters, folds common homoglyphs, normalizes fullwidth ASCII, strips HTML-like tags (without removing ChatML tokens), optional base64 decoding when decoded text matches threat keywords, light markdown fence stripping, spaced-letter collapse.
2. **InputDecomposer** — runs weighted regex families (injection, exfiltration, secret, escalation, delimiters) on normalized text; applies quoted-region down-weighting; Khmer + English keyword mixing heuristic; emits `DecompositionResult` with `[REDACTED]` clean text.
3. **AdversarialMemoryBank** (optional) — sentence-transformer embeddings + FAISS or NumPy cosine search; confirmed vs suspected tiers; deduplication and decay.
4. **ThreatAccumulator** — per-session EMA and escalation detection across turns.
5. **ThreatScorer** — weighted blend of pattern, memory, trajectory, normalization suspicion; pattern floor when memory is cold; threshold actions (allow / sanitize / review / block).
6. **OutputScanner** — heuristic scan for PII, credentials, prompt-leak phrases, encoded blobs, and bulky structured output.

## Adapters

- **AGT** (`adapters/agt.py`) — `ImmunePolicyEvaluator` and `ImmuneIntegration` with `pre_execute` / `post_execute` semantics aligned with Microsoft Agent OS patterns.
- **LangChain** — `ImmuneCallbackHandler.build()` returns a `BaseCallbackHandler` subclass.
- **MCP** — `ImmuneMCPMiddleware.intercept` for JSON-shaped messages.
