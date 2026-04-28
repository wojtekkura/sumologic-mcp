# Sumo Logic MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI clients (Claude Desktop, Cursor, etc.) to Sumo Logic SIEM and Cloud SOAR. It gives AI assistants direct access to:

- **Claim Incident** — fetch a SIEM Insight, assign analyst, set status to in-progress, find or create the linked Cloud SOAR incident, and return a structured triage view with IoC candidates, identities, and signal summaries
- **Attach Note** — attach a markdown note (rendered to HTML) to a Cloud SOAR incident

Built on the official [`mcp`](https://pypi.org/project/mcp/) Python SDK using `FastMCP`. Credentials are stored in Windows Credential Manager — no secrets in config files.

## Quick Start

### Install uv

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Requirements

- [uv](https://docs.astral.sh/uv/) installed
- Sumo Logic API credentials (access ID + access key) with SIEM and Cloud SOAR scopes
- Your Sumo Logic API region (e.g. `us1`, `us2`, `eu`, `de`, `au`, `jp`, `ca`, `in`)

## 1. Store your credentials in Windows Credential Manager

Sumo Logic requires two credentials (access ID and access key). Run these once in PowerShell:

```powershell
cmdkey /generic:"access_id@sumologic-mcp" /user:"access_id" /pass:"your-access-id-here"
cmdkey /generic:"access_key@sumologic-mcp" /user:"access_key" /pass:"your-access-key-here"
```

To verify:

```powershell
cmdkey /list:"access_id@sumologic-mcp"
cmdkey /list:"access_key@sumologic-mcp"
```

To remove:

```powershell
cmdkey /delete:"access_id@sumologic-mcp"
cmdkey /delete:"access_key@sumologic-mcp"
```

## 2. Configure Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sumologic": {
      "command": "uvx",
      "args": [
        "--from",
        "sumologic-mcp @ https://github.com/wojtekkura/sumologic-mcp/archive/refs/heads/main.tar.gz",
        "sumologic-mcp"
      ],
      "env": {
        "SUMO_API_REGION": "de",
        "ANALYST_USERNAME": "your-sumo-username",
        "SOAR_OWNER_ID": "your-numeric-owner-id"
      }
    }
  }
}
```

| Variable | Description |
|---|---|
| `SUMO_API_REGION` | Region code: `us1` `us2` `eu` `de` `au` `jp` `ca` `in` |
| `ANALYST_USERNAME` | Sumo username — used as SIEM assignee and default note author |
| `SOAR_OWNER_ID` | Numeric Cloud SOAR owner ID for created incidents |

Credentials are read automatically from Windows Credential Manager at startup — no secrets in the config file.

Restart Claude Desktop after saving the file.

## Available Tools

| Tool | Description |
|------|-------------|
| `claim_incident` | Fetch SIEM Insight, assign analyst, create/link SOAR incident, return structured triage view |
| `attach_note` | Attach a markdown note to a Cloud SOAR incident |

## License

MIT
