"""OAuth integration for the Redmine MCP server.

Wraps FastMCP's ``OAuthProxy`` so MCP clients can authenticate via Redmine's
Doorkeeper using Dynamic Client Registration. Exposes the verifier, the proxy
factory, and a helper to read the upstream token from the active request.
"""

from __future__ import annotations

import logging
import os
import time

import httpx
from fastmcp.server.auth.auth import TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.dependencies import get_access_token
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


def _redmine_url() -> str:
    return os.environ.get("REDMINE_URL", "").rstrip("/")


def _redmine_internal_url() -> str:
    # Server-to-server URL for /token, /revoke, /oauth/token/info. Falls back
    # to REDMINE_URL; override when the container reaches Redmine on a
    # different hostname than the browser does.
    return os.environ.get("REDMINE_INTERNAL_URL", "").rstrip("/") or _redmine_url()


def _mcp_base_url() -> str:
    return os.environ.get("REDMINE_MCP_BASE_URL", "http://localhost:8000").rstrip("/")


def _require_env(**values: str | None) -> None:
    missing = [name for name, val in values.items() if not val]
    if missing:
        raise RuntimeError(
            "OAuth mode requires the following env vars to be set: "
            + ", ".join(missing)
        )


class RedmineTokenVerifier(TokenVerifier):
    """Validate a Redmine access token via Doorkeeper's ``/oauth/token/info``.

    token/info gives us authentication and the granted scopes in one call;
    /users/current.json doesn't expose scopes, which BearerAuthMiddleware
    needs to enforce per-request scope requirements.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        redmine_url = _redmine_internal_url()
        if not redmine_url:
            logger.error("REDMINE_URL is not configured — cannot verify token")
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{redmine_url}/oauth/token/info",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
        except httpx.RequestError as exc:
            logger.warning("Redmine unreachable during token verification: %s", exc)
            return None

        if response.status_code != 200:
            return None

        info = response.json()

        raw_scope = info.get("scope") or info.get("scopes") or []
        scopes = raw_scope.split() if isinstance(raw_scope, str) else list(raw_scope)

        owner_id = info.get("resource_owner_id")
        client_id = f"redmine:{owner_id}" if owner_id is not None else "redmine"

        expires_at = int(time.time()) + int(info.get("expires_in") or 3600)

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
        )


def build_oauth_proxy() -> OAuthProxy:
    """Construct the FastMCP ``OAuthProxy`` from environment configuration.

    Required: REDMINE_URL, REDMINE_MCP_BASE_URL, REDMINE_OAUTH_CLIENT_ID,
    REDMINE_OAUTH_CLIENT_SECRET. Optional: REDMINE_OAUTH_SCOPES.
    """
    redmine_url = _redmine_url()
    internal_url = _redmine_internal_url()
    base_url = _mcp_base_url()
    client_id = os.environ.get("REDMINE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("REDMINE_OAUTH_CLIENT_SECRET")

    _require_env(
        REDMINE_URL=redmine_url,
        REDMINE_MCP_BASE_URL=base_url,
        REDMINE_OAUTH_CLIENT_ID=client_id,
        REDMINE_OAUTH_CLIENT_SECRET=client_secret,
    )

    # Without an explicit scope, Doorkeeper grants only its default read
    # scopes and every write tool 403s. Pass the same list to both the
    # advertised metadata and the verifier (used as the upstream default).
    scopes_env = os.environ.get("REDMINE_OAUTH_SCOPES", "").strip()
    scopes = scopes_env.split() if scopes_env else None

    return OAuthProxy(
        # /authorize is browser-facing; /token and /revoke are server-to-server.
        upstream_authorization_endpoint=f"{redmine_url}/oauth/authorize",
        upstream_token_endpoint=f"{internal_url}/oauth/token",
        upstream_revocation_endpoint=f"{internal_url}/oauth/revoke",
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=RedmineTokenVerifier(
            base_url=base_url, required_scopes=scopes
        ),
        base_url=base_url,
        valid_scopes=scopes,
        # Doorkeeper does not implement RFC 8707 resource indicators.
        forward_resource=False,
    )


def get_current_token() -> str | None:
    """Return the upstream Redmine token for the current request, or None.

    Returns None outside an authenticated request — legacy-mode callers must
    fall back to API-key / username-password credentials.
    """
    access_token = get_access_token()
    return access_token.token if access_token else None
