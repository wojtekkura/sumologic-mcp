# Sumo Logic MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI clients (Claude Desktop, Cursor, etc.) to Sumo Logic SIEM and Cloud SOAR. It gives AI assistants direct access to:

- **Claim Incident** — fetch a SIEM Insight, assign analyst, set status to in-progress, find or create the linked Cloud SOAR incident, and return a structured triage view with IoC candidates, identities, and signal summaries
- **Attach Note** — attach a markdown note (rendered to HTML) to a Cloud SOAR incident

Built on the official [`mcp`](https://pypi.org/project/mcp/) Python SDK using `FastMCP`. Credentials are stored in Windows Credential Manager — no secrets in config files.

## Quick Start

### Install uv

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Linux / macOS (bash/zsh):**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Requirements

- [uv](https://docs.astral.sh/uv/) installed
- Sumo Logic API credentials (access ID + access key) with SIEM and Cloud SOAR scopes
- Your Sumo Logic API region (e.g. `us1`, `us2`, `eu`, `de`, `au`, `jp`, `ca`, `in`)

## 1. Store your credentials

Sumo Logic requires two secrets (access ID + access key). Pick **one** of these
paths depending on your platform:

### Option A — System keyring (Windows / macOS / Linux desktop)

The secrets live in the OS-native keyring (Windows Credential Manager, macOS
Keychain, Linux libsecret) and are read automatically at startup.

**Windows (PowerShell):**

```powershell
cmdkey /generic:"access_id@sumologic-mcp" /user:"access_id" /pass:"your-access-id-here"
cmdkey /generic:"access_key@sumologic-mcp" /user:"access_key" /pass:"your-access-key-here"
```

> Note: `cmdkey` is the canonical Windows path. macOS / Linux desktop users
> can use the cross-platform `keyring` CLI instead (shipped with the
> `keyring` package): `keyring set sumologic-mcp access_id`.

**macOS / Linux desktop:**

```bash
keyring set sumologic-mcp access_id   # paste access ID, press Enter
keyring set sumologic-mcp access_key  # paste access key, press Enter
```

Or run the interactive helper (any OS):

```bash
uvx --from "sumologic-mcp @ https://github.com/wojtekkura/sumologic-mcp/archive/refs/heads/master.tar.gz" sumologic-mcp setup
```

### Option B — Environment variables (headless Linux, Docker, CI)

On a headless box with no D-Bus / unlocked keyring, set the secrets as env
vars in your MCP host config or shell. The `SUMO_ACCESS_ID` / `SUMO_ACCESS_KEY`
env vars win over any value in the keyring.

```bash
export SUMO_ACCESS_ID='your-access-id'
export SUMO_ACCESS_KEY='your-access-key'
```

## 2. Configure your MCP host

### Claude Desktop (Windows / macOS)

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "sumologic": {
      "command": "uvx",
      "args": [
        "--from",
        "sumologic-mcp @ https://github.com/wojtekkura/sumologic-mcp/archive/refs/heads/master.tar.gz",
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

### Headless Linux / Docker / any MCP client

Same shape, but inline the secrets via env vars (no keyring needed):

```json
{
  "mcpServers": {
    "sumologic": {
      "command": "uvx",
      "args": [
        "--from",
        "sumologic-mcp @ https://github.com/wojtekkura/sumologic-mcp/archive/refs/heads/master.tar.gz",
        "sumologic-mcp"
      ],
      "env": {
        "SUMO_ACCESS_ID": "your-access-id",
        "SUMO_ACCESS_KEY": "your-access-key",
        "SUMO_API_REGION": "de",
        "ANALYST_USERNAME": "your-sumo-username",
        "SOAR_OWNER_ID": "your-numeric-owner-id"
      }
    }
  }
}
```

| Variable | Required? | Description |
|---|---|---|
| `SUMO_ACCESS_ID` | If no keyring | Access ID secret. Overrides the keyring value when both are present. |
| `SUMO_ACCESS_KEY` | If no keyring | Access key secret. Overrides the keyring value when both are present. |
| `SUMO_API_REGION` | Yes | Region code: `us1` `us2` `eu` `de` `au` `jp` `ca` `in` |
| `ANALYST_USERNAME` | Yes | Sumo username — used as SIEM assignee and default note author |
| `SOAR_OWNER_ID` | Yes | Numeric Cloud SOAR owner ID for created incidents |

Restart the MCP host after saving the config.

## Available Tools

| Tool | Description |
|------|-------------|
| `claim_incident` | Fetch SIEM Insight, assign analyst, create/link SOAR incident, return structured triage view |
| `attach_note` | Attach a markdown note to a Cloud SOAR incident |

## License

MIT
