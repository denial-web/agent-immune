# Integration guide

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
