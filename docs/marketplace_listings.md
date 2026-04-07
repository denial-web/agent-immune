# Marketplace listing content — v0.2.0

Use this as copy-paste material when updating or submitting listings.

---

## Short description (1 line)

Adaptive AI agent security: prompt injection detection in 11 languages, semantic memory, output scanning, rate limiting, and prompt hardening.

## Medium description (2-3 sentences)

agent-immune provides adaptive threat intelligence for AI agents. It detects prompt injections in 11 languages, learns from incidents via semantic memory, scans outputs for PII/credential leaks, and includes rate limiting and prompt hardening. Zero false positives on benchmark datasets; F1 improves 29% with memory.

## MCP server configuration (stdio)

```json
{
  "mcpServers": {
    "agent-immune": {
      "command": "python",
      "args": ["-m", "agent_immune", "serve", "--transport", "stdio"]
    }
  }
}
```

### With uvx (no pre-install needed)

```json
{
  "mcpServers": {
    "agent-immune": {
      "command": "uvx",
      "args": ["--from", "agent-immune[mcp]", "python", "-m", "agent_immune", "serve", "--transport", "stdio"]
    }
  }
}
```

## MCP tools

| Tool | Description |
|------|-------------|
| `assess_input` | Score user/tool input for injection, exfiltration, escalation (0.0–1.0) with action recommendation |
| `assess_output` | Scan model output for PII, credentials, prompt leaks, encoded payloads |
| `learn_threat` | Teach the adaptive memory a new attack pattern for future detection |
| `harden_prompt` | Apply role-lock, sandboxing, and output guard to a system prompt |
| `get_metrics` | Return runtime counters: assessments, blocks, reviews, latency |

## Key features for v0.2.0

- 11 languages: English, German, Spanish, French, Croatian, Russian, Chinese, Japanese, Korean, Arabic, Hindi
- Indirect injection detection: HTML comments, confused deputy, URL payloads
- Configurable output scanner with per-category weights
- Optional HNSW approximate nearest neighbor for fast memory search at scale
- MCP server with working semantic memory (learn → detect round-trip)
- Zero false positives, precision >= 99.1% across all benchmark configurations

## Links

- PyPI: https://pypi.org/project/agent-immune/
- GitHub: https://github.com/denial-web/agent-immune
- Docs: https://github.com/denial-web/agent-immune/tree/main/docs

---

## Platform-specific submission notes

### MCP.so (update existing listing)
1. Go to your server's edit page on mcp.so
2. Update the description with the medium description above
3. Update the server config JSON if needed

### Glama.ai (update existing listing)
Glama auto-syncs from GitHub. Ensure `glama.json` in your repo root is up to date.
The README changes will propagate automatically.

### Smithery.ai (new submission)
1. Go to https://smithery.ai/new
2. Enter GitHub URL: `https://github.com/denial-web/agent-immune`
3. Use the stdio config above
4. Description: use the medium description

### PulseMCP (auto-indexed)
PulseMCP indexes public GitHub repos. The updated README with MCP `serve` docs
should be picked up automatically. No manual submission needed.

### Official MCP Registry (new submission)
1. Fork https://github.com/modelcontextprotocol/servers
2. Add your server entry following the registry format
3. Open a PR with your server details
