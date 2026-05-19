# CLAUDE.md — release & deployment guide

> Notes for Claude (and the human running it) on shipping a new version of
> `sumologic-mcp` to a Windows + Claude Desktop install. Read this every
> time a new tool or behavior change is being prepared for release.

## TL;DR — every release MUST do all three

1. **Bump `version` in `pyproject.toml`** (e.g. `0.2.0` → `0.2.1`). Skipping this
   poisons uv's `(name, version)`-keyed cache and every downstream
   `uv tool install --force --reinstall` silently reuses the old wheel.
2. **Merge to `master` via PR** (the existing project convention — see commit
   log; everything has landed as a squash merge).
3. **Sync into Claude Desktop's sandboxed install** on the consuming
   Windows machine (see "Sandbox sync" below). `uv tool install` alone is
   not enough.

## Why a plain `uv tool install` doesn't work on Windows Claude Desktop

> **Linux / macOS / non–Claude-Desktop hosts: skip the "Sandbox sync"
> section below.** The MSIX AppContainer that motivates it only exists
> on Windows Claude Desktop. Everywhere else, `uv tool install --force
> --reinstall` (after a version bump) is sufficient.


Claude Desktop ships as an MSIX-packaged AppContainer with package family
`Claude_pzs8sxrjxfjjc`. Windows transparently redirects `%APPDATA%` reads
from inside that AppContainer to a per-package shadow filesystem:

| Caller | Path it actually reads |
|---|---|
| Your normal PowerShell / `uv tool install` | `C:\Users\<you>\AppData\Roaming\uv\tools\sumologic-mcp\` |
| `sumologic-mcp.exe` spawned by Claude Desktop | `C:\Users\<you>\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\uv\tools\sumologic-mcp\` |

These are two different on-disk locations. `uv tool install --force
--reinstall` from a normal shell **cannot reach the sandboxed copy** —
the AppContainer token belongs to Claude Desktop. The sandboxed copy was
forked off the global install at some point and then never updated.

Symptom: Claude Desktop reports an outdated tool list (e.g. only 3 of 5
tools) even after the human has run `uv tool install --force --reinstall`
several times.

## Sandbox sync — the procedure that actually works

```powershell
# 1. Fully quit Claude Desktop (system tray → Quit; closing the window
#    is NOT enough — MCP servers are spawned at app startup).

# 2. Fetch the master tarball and extract.
$url     = "https://github.com/wojtekkura/sumologic-mcp/archive/refs/heads/master.tar.gz"
$tarball = "$env:TEMP\sumologic-mcp.tar.gz"
$extract = "$env:TEMP\sumologic-mcp-extract"
Invoke-WebRequest -Uri $url -OutFile $tarball -UseBasicParsing
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
New-Item -ItemType Directory $extract | Out-Null
tar -xzf $tarball -C $extract

# 3. Mirror src/sumologic_mcp/ into the sandboxed install and clear bytecode.
$src = "$extract\sumologic-mcp-master\src\sumologic_mcp"
$dst = "C:\Users\$env:USERNAME\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\uv\tools\sumologic-mcp\Lib\site-packages\sumologic_mcp"
Get-ChildItem -Path $dst -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
Copy-Item -Path "$src\*" -Destination $dst -Recurse -Force

# 4. Verify server.py hash matches the tarball (sanity check).
Get-FileHash "$dst\server.py" -Algorithm SHA256
Get-FileHash "$src\server.py" -Algorithm SHA256

# 5. Relaunch Claude Desktop.
```

The Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json`)
should keep `"command": "sumologic-mcp"`. The `env:` block must still
provide `SUMO_API_REGION`, `ANALYST_USERNAME`, `SOAR_OWNER_ID`.

## Adding a new MCP tool — the 4-step pattern

Established by `claim_incident` / `attach_note` / `list_new_insights` /
`add_insight_comment` / `resolve_insight`:

1. **Add the REST verb to the client** in `src/sumologic_mcp/clients/siem.py`
   (or `soar.py`). Use the existing `_get`/`_put`/`_post`/`_patch` helpers —
   they raise on `!resp.ok`.
2. **Create `src/sumologic_mcp/tools/<name>.py`** with one function. The
   type-annotated signature plus the Google-style docstring become the
   MCP tool schema that Claude sees — be specific.
3. **Register in `src/sumologic_mcp/server.py`**: import the function and
   call `mcp.add_tool(<name>)`.
4. **Add tests under `tests/unit/`** — `test_clients.py` for the REST shape
   (mock `session.get`/`post`/`put`), `test_tools.py` for the tool's
   orchestration (`@patch("sumologic_mcp.tools.<name>.state")`).

## Pre-merge checks (project has no CI today — run locally)

```powershell
uv run --extra dev ruff check src tests
uv run --extra dev mypy src
uv run --extra dev pytest tests/unit -q
```

All three must pass. `ruff format` is NOT enforced — the existing master
has pre-existing line-wrap differences; don't churn unrelated files.

## End-to-end live verification

Unit tests are mocked. Before declaring a release done, run a live
end-to-end pass against a real Insight in the target Sumo tenant —
preferably with a low-impact verdict like `"False Positive"` and a
clearly-labeled test comment. See PR #7 for the exemplar
(`scripts/e2e_insight_30105.py` was the one-off runner, gitignored).

## Common gotchas Claude should remember

- The default branch is **`master`**, not `main`. The README's example
  `uvx --from "...main.tar.gz"` URL is wrong (legacy typo) — use
  `master.tar.gz` everywhere.
- The `pyproject.toml` version has historically not been bumped on
  release; this is the cache-poisoning trap. Always bump it.
- The sandbox-sync step is not optional on Windows Claude Desktop.
- Sumo CSE API: **`comment` and `resolution` are distinct concepts.**
  `POST /insights/{id}/comments` takes `{"body": "..."}` (free text,
  many per insight). `PUT /insights/{id}/status` takes
  `{"status":"closed","resolution":"<enum>"}` (single structured close
  reason). There is no separate closure-note endpoint.
- Tool args from the LLM are NOT anonymous web input — they come from
  the trusted analyst's Claude session. Existing security model assumes
  this; don't add over-aggressive input validation.
- Credentials are dual-path: env vars `SUMO_ACCESS_ID` / `SUMO_ACCESS_KEY`
  win over the system keyring. Headless Linux / Docker / CI deployments
  should use the env-var path (no D-Bus / libsecret required). When
  adding a new secret, keep this precedence — env var first, then
  keyring, then fail with a message naming both paths.
