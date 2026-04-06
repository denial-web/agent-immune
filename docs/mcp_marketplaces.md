# MCP server — marketplace distribution checklist

Run everything **locally**; no hosting is required. After `pip install 'agent-immune[mcp]'`, start the server:

```bash
python -m agent_immune serve --transport stdio
# or HTTP (e.g. for MCP Inspector / remote clients):
python -m agent_immune serve --transport streamable-http --port 8000
```

Tools exposed: `assess_input`, `assess_output`, `learn_threat`, `harden_prompt`, `get_metrics`.

---

## Wave 1 — list quickly (typically no lengthy review)

| Platform | What to do |
|----------|------------|
| **[Smithery.ai](https://smithery.ai/)** | Submit a new server at [smithery.ai/new](https://smithery.ai/new) with your MCP command (e.g. `python -m agent_immune serve --transport stdio` or HTTP URL if you expose streamable-http). |
| **[MCP.so](https://mcp.so/)** | Add the project to the community directory — submit the repo or server details as the site requests. |
| **[Glama.ai](https://glama.ai/)** | Submit your MCP server through their MCP listing flow with the same command/URL. |
| **[PulseMCP](https://www.pulsemcp.com/)** | Often indexes public GitHub repos automatically; ensure the README documents the MCP `serve` command so discovery metadata is clear. |

---

## Wave 2 — curated listings (review / verification)

| Platform | What to do |
|----------|------------|
| **Official MCP Registry** | Use the publisher tooling (`mcp-publisher` CLI per current registry docs), verify PyPI + GitHub, and follow the registry’s submission checklist. |
| **Cursor Marketplace** | Follow Cursor’s extension/plugin packaging (`plugin.json`, `marketplace.json`) and their submission process for marketplace listings. |
| **Claude Connectors Directory** | See [Anthropic’s MCP directory submission](https://claude.ai/) / official docs for OAuth and tool-annotation requirements if listing there. |

---

## README and badges

After each listing goes live, add the platform badge or “Available on …” link in the main `README.md` pointing to your canonical listing URL.
