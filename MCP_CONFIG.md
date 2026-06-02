# MCP Configuration Locations

Where to register the ZAP MCP server depending on which agent you're using.

## Claude Code

**File:** `~/.claude.json`

```json
{
  "mcpServers": {
    "zap": {
      "command": "/path/to/uv",
      "args": ["run", "/path/to/mcp-zap/zap_mcp.py"],
      "env": {}
    }
  }
}
```

Or via CLI:
```bash
claude mcp add zap uv run /path/to/mcp-zap/zap_mcp.py
```

---

## OpenOps

**File:** `~/.openops/.mcp.json`

```json
{
  "mcpServers": {
    "zap": {
      "command": "/path/to/uv",
      "args": ["run", "/path/to/mcp-zap/zap_mcp.py"]
    }
  }
}
```

---

## Project-level (any agent)

Drop a `.mcp.json` in your project root — most Claude-compatible agents pick this up automatically:

```json
{
  "mcpServers": {
    "zap": {
      "command": "/path/to/uv",
      "args": ["run", "/path/to/mcp-zap/zap_mcp.py"]
    }
  }
}
```

---

## Finding your `uv` path

```bash
which uv
```

Typical locations:
- macOS (Homebrew): `/opt/homebrew/bin/uv`
- macOS (uv installer): `~/.local/bin/uv`
- Linux: `~/.local/bin/uv`

## Local config files (gitignored)

These files live locally and are never committed:

| File | Purpose |
|---|---|
| `~/mcp-zap/.zap_api_key` | ZAP API key — auto-generated on first run |
| `~/mcp-zap/checklist_urls.txt` | Your target URLs for `zap_run_weekly_checklist` |
