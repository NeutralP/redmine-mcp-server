# OAuth2 Setup Guide

The MCP server in OAuth mode acts as a **DCR-capable OAuth proxy** in front of Redmine. MCP clients (Claude Desktop, Codex CLI, VS Code, Claude Code, Kiro) connect with no manual `client_id`/`client_secret` — they Dynamic-Client-Register against this server, which bridges the flow to Redmine's static Doorkeeper application.

**Requirements:** Redmine 6.1+ and admin access to register one OAuth application.

## How it works

```
MCP client ──► MCP server (OAuth proxy) ──► Redmine Doorkeeper
   │ DCR /register, /authorize        │ /oauth/authorize
   │ /token, /auth/callback           │ /oauth/token
   │ FastMCP-issued JWT               │ Redmine access token
   │ (held client-side)               │ (held server-side)
```

- The MCP client only ever sees a short-lived FastMCP JWT.
- The real Redmine access token lives in the MCP server's upstream token store and is attached to outbound Redmine API calls.
- Every `/register` call gets its own ephemeral `client_id`/`client_secret`. The single static Redmine OAuth application is shared across all clients but its secret never leaves the server.

## Step 1 — Register one OAuth app in Redmine

**Administration → Applications → New Application**

| Field | Value |
|---|---|
| Name | `MCP Server` |
| Redirect URI | `<REDMINE_MCP_BASE_URL>/auth/callback` (one URI, fixed) |
| Confidential | Yes |

Save the resulting **Client ID** and **Client Secret**.

## Step 2 — Configure the MCP server

```bash
REDMINE_AUTH_MODE=oauth
REDMINE_URL=https://redmine.example.com
REDMINE_MCP_BASE_URL=https://mcp.example.com   # public URL of this server
REDMINE_OAUTH_CLIENT_ID=<from Step 1>
REDMINE_OAUTH_CLIENT_SECRET=<from Step 1>
# Optional:
# REDMINE_OAUTH_SCOPES=
```

Set these in `.env` (local) or `.env.docker` (Docker). Legacy credentials are not needed in OAuth mode.

## Step 3 — Start and verify

```bash
# Local
uv run python -m redmine_mcp_server.main

# Docker
docker-compose up --build -d
```

Quick check — the discovery document must advertise `registration_endpoint`:

```bash
curl -s http://localhost:8000/.well-known/oauth-authorization-server | jq .registration_endpoint
# → "http://localhost:8000/register"
```

## Step 4 — Connect any MCP client

Clients handle the full flow automatically:

```bash
codex mcp login redmine          # → opens browser, succeeds
```

| Client | OAuth2 | Notes |
|---|---|---|
| **Claude Desktop** | Yes | Settings → Connectors. **Now works** (DCR via `/register`) |
| **Claude Code** | Yes | Auto browser flow on 401 |
| **Codex CLI** | Yes | `codex mcp login <name>` |
| **VS Code** (1.102+) | Yes | Full OAuth 2.1 + PKCE + DCR |
| **Kiro** | Yes | Configurable `oauth.redirectUri` |

No client needs manual `client_id`/`client_secret`. The redirect URI in Redmine is fixed at `<REDMINE_MCP_BASE_URL>/auth/callback`; clients use their own dynamic localhost callbacks, which the proxy bridges.

## Migrating from legacy mode

1. Register the OAuth app (Step 1) and set the four env vars (Step 2).
2. Restart — no downtime needed.
3. Once confirmed, remove `REDMINE_API_KEY` / `REDMINE_USERNAME` / `REDMINE_PASSWORD`.
4. Rollback: set `REDMINE_AUTH_MODE=legacy`.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Dynamic client registration not supported` | Server isn't in OAuth mode, or running an old build | Check `REDMINE_AUTH_MODE=oauth`; `curl /.well-known/oauth-authorization-server` should show `registration_endpoint` |
| `OAuth mode requires the following env vars` at startup | `REDMINE_OAUTH_CLIENT_ID/SECRET` missing | Set both env vars |
| Browser opens, Redmine login OK, callback errors | Redirect URI in Redmine doesn't match `<REDMINE_MCP_BASE_URL>/auth/callback` | Update Redmine app's Redirect URI |
| Token works in Redmine but MCP returns 401 | `REDMINE_URL` is wrong from inside the container | In Docker, use the internal hostname (e.g. `http://redmine:3000`) |
| "Applications" menu missing in Redmine | Redmine too old | Requires Redmine 6.1+ |

## Security notes

- The MCP server holds the Redmine access token; it is not exposed to MCP clients.
- The default upstream-token store is in-memory. For multi-replica deployments, configure FastMCP with a persistent `client_storage` backend.
- Run behind HTTPS in production. FastMCP logs a warning on startup when the cookie used for the consent flow is set without `Secure`.
