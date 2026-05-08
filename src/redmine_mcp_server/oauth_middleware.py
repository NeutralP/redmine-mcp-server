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
    """Browser-facing Redmine URL (used for /authorize redirect)."""
    return os.environ.get("REDMINE_URL", "").rstrip("/")


def _redmine_internal_url() -> str:
    """Server-to-server Redmine URL (used for /token, /revoke, /users/current.json).

    Falls back to REDMINE_URL when unset. Override this when the MCP server
    reaches Redmine via a different hostname than the browser does — e.g. when
    both run in Docker on the same host:
        REDMINE_URL=http://localhost:8080            # what the browser sees
        REDMINE_INTERNAL_URL=http://host.docker.internal:8080
    """
    return (
        os.environ.get("REDMINE_INTERNAL_URL", "").rstrip("/") or _redmine_url()
    )


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

    def __init__(
        self,
        base_url: str | None = None,
        required_scopes: list[str] | None = None,
    ):
        super().__init__(base_url=base_url, required_scopes=required_scopes)

    async def verify_token(self, token: str) -> AccessToken | None:
        redmine_url = _redmine_internal_url()
        if not redmine_url:
            logger.error("REDMINE_URL is not configured — cannot verify token")
            return None

        # Use Doorkeeper's /oauth/token/info instead of /users/current.json:
        # one round-trip gives us both authentication (it 401s for bad tokens)
        # AND the granted scopes, which BearerAuthMiddleware needs to enforce
        # required_scopes per request. Without real scopes here every protected
        # call returns 403 insufficient_scope.
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

        try:
            info = response.json()
        except ValueError:
            return None

        # Doorkeeper returns scope as either a space-separated string or list.
        raw_scope = info.get("scope") or info.get("scopes") or []
        if isinstance(raw_scope, str):
            scopes = raw_scope.split()
        else:
            scopes = list(raw_scope)

        owner_id = info.get("resource_owner_id")
        client_id = f"redmine:{owner_id}" if owner_id is not None else "redmine"

        # Doorkeeper returns expires_in (seconds remaining); fall back to 1h.
        expires_in = info.get("expires_in")
        expires_at = int(time.time()) + (
            int(expires_in) if isinstance(expires_in, (int, float)) else 3600
        )

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
        )


def build_oauth_proxy() -> OAuthProxy:
    """Construct the FastMCP ``OAuthProxy`` from environment configuration.

    Required env vars:
        REDMINE_URL, REDMINE_MCP_BASE_URL,
        REDMINE_OAUTH_CLIENT_ID, REDMINE_OAUTH_CLIENT_SECRET

    Optional:
        REDMINE_OAUTH_SCOPES — space-separated, advertised in metadata.
    """
    redmine_url = _redmine_url()  # browser-facing
    internal_url = _redmine_internal_url()  # server-to-server
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

    # Scopes serve two roles: they are advertised in /.well-known metadata
    # (`valid_scopes`) AND injected as the upstream `scope=` param when an MCP
    # client doesn't request one of its own (via the verifier's
    # `required_scopes`, which OAuthProxy uses as the default in
    # `_build_upstream_authorize_url`). Without this, Doorkeeper falls back to
    # Redmine's default_scopes — only the three public read permissions —
    # and every write tool returns 403.
    scopes_env = os.environ.get("REDMINE_OAUTH_SCOPES", "").strip()
    scopes = scopes_env.split() if scopes_env else None

    return OAuthProxy(
        # /authorize is hit by the user's browser → must be browser-reachable.
        upstream_authorization_endpoint=f"{redmine_url}/oauth/authorize",
        # /token and /revoke are server-to-server → use the internal URL.
        upstream_token_endpoint=f"{internal_url}/oauth/token",
        upstream_revocation_endpoint=f"{internal_url}/oauth/revoke",
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=RedmineTokenVerifier(
            base_url=base_url, required_scopes=scopes
        ),
        base_url=base_url,
        valid_scopes=scopes,
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
