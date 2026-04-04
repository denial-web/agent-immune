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
```

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

mw = ImmuneMCPMiddleware(AdaptiveImmuneSystem())
asyncio.run(mw.intercept({"method": "tools/call", "params": {...}}))
```
