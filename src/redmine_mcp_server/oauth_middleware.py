"""OAuth integration for the Redmine MCP server.

In OAuth mode the server is fronted by FastMCP's ``OAuthProxy`` which:
  * implements RFC 7591 Dynamic Client Registration as a "DCR shim" that
    hands every MCP client the same statically pre-registered Redmine
    Doorkeeper credentials,
  * proxies ``/authorize`` and ``/token`` to Redmine using a single fixed
    redirect URI (``<base_url>/auth/callback``),
  * issues short-lived FastMCP-signed JWTs to MCP clients while keeping the
    real Redmine access tokens server-side.

This module exposes:
  * :class:`RedmineTokenVerifier` — validates an upstream Redmine token by
    calling ``/users/current.json``;
  * :func:`build_oauth_proxy` — constructs the configured ``OAuthProxy``;
  * :func:`get_current_token` — retrieves the validated upstream token from
    the active request context (used by the Redmine client factory).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import httpx
from fastmcp.server.auth.auth import TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.dependencies import get_access_token
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


def _redmine_url() -> str:
    return os.environ.get("REDMINE_URL", "").rstrip("/")


def _mcp_base_url() -> str:
    return os.environ.get("REDMINE_MCP_BASE_URL", "http://localhost:8000").rstrip("/")


class RedmineTokenVerifier(TokenVerifier):
    """Validate a Redmine access token via ``/users/current.json``.

    Doorkeeper tokens are opaque, so we validate by hitting Redmine itself.
    The verifier is invoked by ``OAuthProxy`` after it swaps an inbound
    FastMCP JWT for the upstream token; on success the returned
    :class:`AccessToken` carries the original Redmine token in ``.token``,
    which downstream tool calls retrieve via :func:`get_current_token`.
    """

    def __init__(self, base_url: str | None = None):
        super().__init__(base_url=base_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        redmine_url = _redmine_url()
        if not redmine_url:
            logger.error("REDMINE_URL is not configured — cannot verify token")
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{redmine_url}/users/current.json",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
        except httpx.RequestError as exc:
            logger.warning("Redmine unreachable during token verification: %s", exc)
            return None

        if response.status_code != 200:
            return None

        client_id = "redmine"
        try:
            user = response.json().get("user") or {}
            if user.get("id") is not None:
                client_id = f"redmine:{user['id']}"
        except ValueError:
            pass

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=[],
            expires_at=int(time.time()) + 3600,
        )


def build_oauth_proxy() -> OAuthProxy:
    """Construct the FastMCP ``OAuthProxy`` from environment configuration.

    Required env vars:
        REDMINE_URL, REDMINE_MCP_BASE_URL,
        REDMINE_OAUTH_CLIENT_ID, REDMINE_OAUTH_CLIENT_SECRET

    Optional:
        REDMINE_OAUTH_SCOPES — space-separated, advertised in metadata.
    """
    redmine_url = _redmine_url()
    base_url = _mcp_base_url()
    client_id = os.environ.get("REDMINE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("REDMINE_OAUTH_CLIENT_SECRET")

    missing = [
        name
        for name, val in (
            ("REDMINE_URL", redmine_url),
            ("REDMINE_MCP_BASE_URL", base_url),
            ("REDMINE_OAUTH_CLIENT_ID", client_id),
            ("REDMINE_OAUTH_CLIENT_SECRET", client_secret),
        )
        if not val
    ]
    if missing:
        raise RuntimeError(
            "OAuth mode requires the following env vars to be set: "
            + ", ".join(missing)
        )

    scopes_env = os.environ.get("REDMINE_OAUTH_SCOPES", "").strip()
    valid_scopes = scopes_env.split() if scopes_env else None

    return OAuthProxy(
        upstream_authorization_endpoint=f"{redmine_url}/oauth/authorize",
        upstream_token_endpoint=f"{redmine_url}/oauth/token",
        upstream_revocation_endpoint=f"{redmine_url}/oauth/revoke",
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=RedmineTokenVerifier(base_url=base_url),
        base_url=base_url,
        valid_scopes=valid_scopes,
        # Redmine's Doorkeeper does not implement RFC 8707 resource indicators.
        forward_resource=False,
    )


def get_current_token() -> Optional[str]:
    """Return the upstream Redmine token for the current request, if any.

    Reads from FastMCP's authenticated request context (populated by
    ``OAuthProxy`` after it swaps the inbound JWT for the upstream token).
    Returns ``None`` outside of an authenticated request — callers in legacy
    mode must fall back to API-key / username-password credentials.
    """
    try:
        access_token = get_access_token()
    except Exception:  # defensive — outside any request context
        return None
    if access_token is None:
        return None
    return access_token.token
