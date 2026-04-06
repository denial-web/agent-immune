# Integration guide

Requires **Python 3.9+** (3.11+ recommended for CI).

## CLI

```bash
# Assess input text
agent-immune assess "Ignore all previous instructions"
python -m agent_immune assess "Ignore all previous instructions"

# JSON output
agent-immune assess --json "text to check"

# Scan output for exfiltration
echo "Here is the API key: sk-abc123" | agent-immune scan-output

# Pipe from stdin
cat user_message.txt | agent-immune assess

# MCP server (install: pip install 'agent-immune[mcp]')
python -m agent_immune serve --transport stdio
python -m agent_immune serve --transport streamable-http --port 8000
```

See [MCP marketplaces](mcp_marketplaces.md) for listing on Smithery, MCP.so, Glama, and related directories.

## Core only

```python
from agent_immune import AdaptiveImmuneSystem, ThreatAction

immune = AdaptiveImmuneSystem()
a = immune.assess("User message or tool args as one string", session_id="sess-1")
if a.action == ThreatAction.BLOCK:
    ...
scan = immune.assess_output("Model or tool output string")
if immune.output_blocks(scan):
    ...
```

## Custom security policy

All detection thresholds are configurable via `SecurityPolicy`:

```python
from agent_immune import AdaptiveImmuneSystem, SecurityPolicy

# Strict: lower thresholds flag more aggressively
strict = SecurityPolicy(
    allow_threshold=0.20,
    sanitize_threshold=0.35,
    review_threshold=0.45,
    output_block_threshold=0.50,
    memory_confirm_threshold=0.85,
    escalation_upgrade=True,
    max_sessions=5000,
)
immune = AdaptiveImmuneSystem(policy=strict)

# Permissive: higher thresholds for low-risk use cases
permissive = SecurityPolicy(
    allow_threshold=0.70,
    review_threshold=0.90,
    output_block_threshold=0.90,
)
immune = AdaptiveImmuneSystem(policy=permissive)
```

The policy is immutable once created. Access the active policy via `immune.policy`.

## Async API

All core methods have async variants that run CPU-bound work in a background thread,
keeping your event loop free:

```python
result = await immune.assess_async("user input", session_id="s1")
scan   = await immune.assess_output_async("model output")
entry  = await immune.learn_async("attack text", category="confirmed")
count  = await immune.train_from_corpus_async(["attack1", "attack2"])
```

## JSON persistence & threat sharing

```python
from agent_immune import AdaptiveImmuneSystem

immune = AdaptiveImmuneSystem()
immune.learn("attack text", category="confirmed", confidence=0.95)

# Save / load (JSON by default — safe, human-readable)
immune.save("bank.json")
immune.load("bank.json")

# Legacy pickle with HMAC signing
immune.save("bank.pkl", format="pickle")

# Export threats as portable dicts for sharing across instances
threats = immune.export_threats()                 # no embeddings by default
threats_full = immune.export_threats(include_embeddings=True)

# Import on another instance (re-embeds automatically)
other = AdaptiveImmuneSystem()
added = other.import_threats(threats)
```

## Observability

```python
from agent_immune import AdaptiveImmuneSystem, MetricsCollector
from agent_immune.observability import configure_json_logging

# Structured JSON logging to stderr
configure_json_logging()

# Metrics collection
metrics = MetricsCollector()
immune = AdaptiveImmuneSystem(metrics=metrics)

immune.assess("some input")
immune.assess_output("some output")

# Point-in-time counters
snap = metrics.snapshot()
# {'assessments_total': 1, 'blocks_total': 0, 'allows_total': 1,
#  'output_scans_total': 1, 'latency_avg_ms': 0.42, ...}
```

Every `assess()` and `assess_output()` call emits a structured JSON event to the `agent_immune.events` logger with action, scores, session_id, and latency — pipe it to any log aggregator.

## Rate limiting / circuit breaker

```python
from agent_immune import AdaptiveImmuneSystem, CircuitBreaker

# Trip after 5 blocks in 60s; deny for 2 minutes
breaker = CircuitBreaker(max_blocks=5, window_s=60, cooldown_s=120)
immune = AdaptiveImmuneSystem(circuit_breaker=breaker)

# assess() auto-records blocks and returns instant BLOCK when circuit is open
result = immune.assess("anything", session_id="abusive-session")

# Manual management
breaker.force_close("session-id")     # reset manually
breaker.open_sessions()               # list currently tripped sessions
breaker.stats                         # snapshot of breaker state
```

## Prompt hardening

Proactive defenses that complement detection:

```python
from agent_immune import PromptHardener

# Standalone functions
from agent_immune.hardener import harden_system_prompt, sandwich_user_input

hardened = harden_system_prompt("You are a helpful assistant.")
sandboxed = sandwich_user_input(user_text)

# Composable class — applies all three to a message list
hardener = PromptHardener(custom_rules=["Never discuss competitors"])
messages = hardener.harden_messages([
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input},
])
```

The hardener adds:
- **Role lock** — prevents the model from adopting new personas or revealing system instructions.
- **Input sandboxing** — wraps user text in clear delimiters so the model treats it as data.
- **Output guard** — self-check instructions before responding (no PII, no system prompt leak).

## Memory (semantic)

```bash
pip install -e ".[memory]"
```

```python
from agent_immune import AdaptiveImmuneSystem
from agent_immune.memory import TextEmbedder

immune = AdaptiveImmuneSystem(embedder=TextEmbedder())
immune.learn("known attack text", category="confirmed", confidence=0.95)
```

### Bulk-load from an incident log

```python
immune = AdaptiveImmuneSystem()  # auto-initializes embedder if needed
immune.train_from_corpus(
    ["attack text 1", "attack text 2", ...],
    category="confirmed",
    confidence=0.90,
)
```

`train_from_corpus` creates the embedder and memory bank on demand if the instance was created without them. Entries are deduplicated by content hash.

## Microsoft Agent OS (`agent-os-kernel`)

```python
from agent_immune import AdaptiveImmuneSystem
from agent_immune.adapters.agt import ImmuneIntegration

immune = AdaptiveImmuneSystem()
integration = ImmuneIntegration(immune)
# Call integration.pre_execute(context) / post_execute(context, result) from your kernel hooks.
```

If `agent_os.PolicyViolationError` exists, denials use that type; otherwise a `RuntimeError` is raised.

## LangChain

```python
from agent_immune import AdaptiveImmuneSystem
from agent_immune.adapters.langchain import ImmuneCallbackHandler

handler = ImmuneCallbackHandler(AdaptiveImmuneSystem()).build()
# Pass `handler` into your chain/agent callbacks list.
```

## MCP-style JSON middleware

```python
import asyncio
from agent_immune import AdaptiveImmuneSystem
from agent_immune.adapters.mcp import ImmuneMCPMiddleware

# Sync mode (default) — calls assess() directly
mw = ImmuneMCPMiddleware(AdaptiveImmuneSystem())
asyncio.run(mw.intercept({"method": "tools/call", "params": {...}}))

# Async mode — delegates to assess_async() to avoid blocking the event loop
mw = ImmuneMCPMiddleware(AdaptiveImmuneSystem(), use_async=True)
await mw.intercept({"method": "tools/call", "params": {...}})
```
