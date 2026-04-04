# Threat model

## In scope (v0.1)

- Prompt-injection and role-manipulation phrasing (regex + normalization).
- Exfiltration-style instructions (email, external forwarding, dataset relay language).
- Credential and secret solicitation patterns; inline `password=` style literals in mixed-language text.
- Obfuscation that normalizes to the above (homoglyphs, spacing, fullwidth, some base64-wrapped payloads).
- Session-level escalation when individual turns stay below a hard block but trend upward.
- Output-side credential / PII / prompt-leak heuristics and large structured blobs.

## Out of scope

- Guaranteed safety against a determined adaptive attacker with full model control.
- Binary malware analysis or non-text modalities.
- Policy enforcement for database row-level security (use Microsoft AGT or your app layer).
- Training-time hardening (planned under `agent-immune[hardener]`).

## Limitations

- Scores are heuristics; tune thresholds per product and locale.
- Semantic memory quality depends on the embedding model and attack diversity in the bank.
- Competitor benchmarks (e.g. full PINT) require optional `datasets` and are not identical to production traffic.
