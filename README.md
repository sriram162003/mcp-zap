# mcp-zap

An MCP (Model Context Protocol) server that exposes OWASP ZAP as tools for Claude Code.

## What it does

Lets Claude directly control ZAP for web security testing — no GUI needed. ZAP starts automatically in daemon mode when any tool is first called.

## Tools

| Tool | Description |
|---|---|
| `zap_version` | Confirm ZAP is running and get version |
| `zap_spider` | Crawl a URL and return all discovered links |
| `zap_active_scan` | Run a full vulnerability scan against a URL |
| `zap_get_alerts` | List all alerts with risk level and description |
| `zap_open_url` | Send ZAP to visit a URL (triggers passive scan) |
| `zap_sites` | List all sites in ZAP's sites tree |
| `zap_passive_scan_wait` | Wait for passive scanner queue to clear |
| `zap_shutdown` | Cleanly stop the ZAP daemon |

## Requirements

- [OWASP ZAP](https://www.zaproxy.org/) installed at `/Applications/ZAP.app`
- [uv](https://github.com/astral-sh/uv) (Python package manager)
- [Claude Code](https://claude.ai/code)

## Setup

1. Clone this repo:
   ```bash
   git clone https://github.com/sriram162003/mcp-zap
   ```

2. Register the MCP server with Claude Code:
   ```bash
   claude mcp add zap uv run /path/to/mcp-zap/zap_mcp.py
   ```

3. Restart Claude Code. ZAP will launch automatically when you first use a tool.

## Usage

Just ask Claude naturally:
- *"Spider https://example.com"*
- *"Run an active scan on https://example.com and show me the findings"*
- *"What alerts has ZAP found so far?"*

## Weekly checklist scan

To use `zap_run_weekly_checklist`, create a local file `~/mcp-zap/checklist_urls.txt` with your target URLs (one per line):

```
# checklist_urls.txt — gitignored, stays local
https://example.com
https://staging.example.com
```

This file is gitignored so your internal URLs never end up in the repo.

## Notes

- ZAP runs on port `8090` (to avoid conflicts with other local services on 8080)
- API key is persisted in `~/mcp-zap/.zap_api_key` (gitignored)
- Only use against targets you own or have explicit permission to test
