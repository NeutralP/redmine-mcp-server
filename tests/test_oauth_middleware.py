"""Tests for the OAuth integration.

Covers:
  * RedmineTokenVerifier — validates tokens via Redmine /users/current.json
  * build_oauth_proxy() — env-var validation and proxy construction
  * get_current_token() — reads upstream token from FastMCP request context
  * _get_redmine_client() — falls through to legacy auth when no OAuth context
  * The mounted FastMCP app — exposes /register, /.well-known/* with the
    registration_endpoint advertised (the fix for "Dynamic client registration
    not supported").
"""

from __future__ import annotations

import os

# Set required env vars before any project module is imported.
os.environ.setdefault("REDMINE_URL", "https://test-redmine.example.com")
os.environ.setdefault("REDMINE_MCP_BASE_URL", "http://localhost:8000")
os.environ.setdefault("REDMINE_OAUTH_CLIENT_ID", "test-client")
os.environ.setdefault("REDMINE_OAUTH_CLIENT_SECRET", "test-secret")

import pytest  # noqa: E402
from unittest.mock import patch, AsyncMock, MagicMock  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


# ---------------------------------------------------------------------------
# RedmineTokenVerifier
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRedmineTokenVerifier:
    @pytest.mark.asyncio
    async def test_valid_token_returns_access_token(self):
        from redmine_mcp_server.oauth_middleware import RedmineTokenVerifier

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"user": {"id": 42}}

        with patch(
            "redmine_mcp_server.oauth_middleware.httpx.AsyncClient"
        ) as mock_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = client

            result = await RedmineTokenVerifier().verify_token("good-token")

        assert result is not None
        assert result.token == "good-token"
        assert result.client_id == "redmine:42"

    @pytest.mark.asyncio
    async def test_invalid_token_returns_none(self):
        from redmine_mcp_server.oauth_middleware import RedmineTokenVerifier

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch(
            "redmine_mcp_server.oauth_middleware.httpx.AsyncClient"
        ) as mock_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = client

            result = await RedmineTokenVerifier().verify_token("bad-token")

        assert result is None

    @pytest.mark.asyncio
    async def test_redmine_unreachable_returns_none(self):
        import httpx

        from redmine_mcp_server.oauth_middleware import RedmineTokenVerifier

        with patch(
            "redmine_mcp_server.oauth_middleware.httpx.AsyncClient"
        ) as mock_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(side_effect=httpx.RequestError("boom"))
            mock_cls.return_value = client

            result = await RedmineTokenVerifier().verify_token("any-token")

        assert result is None

    @pytest.mark.asyncio
    async def test_forwards_token_as_bearer(self):
        from redmine_mcp_server.oauth_middleware import RedmineTokenVerifier

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"user": {"id": 1}}

        with patch(
            "redmine_mcp_server.oauth_middleware.httpx.AsyncClient"
        ) as mock_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = client

            await RedmineTokenVerifier().verify_token("forward-me")

        sent = client.get.call_args.kwargs["headers"]["Authorization"]
        assert sent == "Bearer forward-me"


# ---------------------------------------------------------------------------
# build_oauth_proxy
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBuildOAuthProxy:
    def test_builds_with_required_env(self):
        from redmine_mcp_server.oauth_middleware import build_oauth_proxy

        proxy = build_oauth_proxy()
        assert proxy is not None
        # OAuthProxy stores upstream endpoints with these attribute names.
        assert proxy._upstream_token_endpoint.endswith("/oauth/token")
        assert proxy._upstream_authorization_endpoint.endswith("/oauth/authorize")

    def test_missing_client_id_raises(self):
        from redmine_mcp_server.oauth_middleware import build_oauth_proxy

        with patch.dict(os.environ, {"REDMINE_OAUTH_CLIENT_ID": ""}, clear=False):
            with pytest.raises(RuntimeError, match="REDMINE_OAUTH_CLIENT_ID"):
                build_oauth_proxy()

    def test_missing_client_secret_raises(self):
        from redmine_mcp_server.oauth_middleware import build_oauth_proxy

        with patch.dict(
            os.environ, {"REDMINE_OAUTH_CLIENT_SECRET": ""}, clear=False
        ):
            with pytest.raises(RuntimeError, match="REDMINE_OAUTH_CLIENT_SECRET"):
                build_oauth_proxy()


# ---------------------------------------------------------------------------
# get_current_token()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetCurrentToken:
    def test_returns_none_outside_request_context(self):
        from redmine_mcp_server.oauth_middleware import get_current_token

        # Outside a FastMCP request, get_access_token() raises or returns None;
        # the helper must absorb that and return None.
        assert get_current_token() is None

    def test_returns_token_from_access_token(self):
        from redmine_mcp_server import oauth_middleware
        from mcp.server.auth.provider import AccessToken

        fake = AccessToken(
            token="ctx-token-xyz", client_id="redmine:1", scopes=[]
        )
        with patch.object(
            oauth_middleware, "get_access_token", return_value=fake
        ):
            assert oauth_middleware.get_current_token() == "ctx-token-xyz"


# ---------------------------------------------------------------------------
# _get_redmine_client() — auth selection
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetRedmineClient:
    @pytest.fixture(autouse=True)
    def _reset_legacy_cache(self):
        import redmine_mcp_server.redmine_handler as rh

        rh._legacy_client = None
        yield
        rh._legacy_client = None

    def test_uses_oauth_token_when_present(self):
        from redmine_mcp_server import oauth_middleware
        from redmine_mcp_server.redmine_handler import _get_redmine_client

        with (
            patch.object(
                oauth_middleware, "get_current_token", return_value="oauth-token-abc"
            ),
            patch("redmine_mcp_server.redmine_handler.Redmine") as mock_redmine,
        ):
            _get_redmine_client()
            headers = mock_redmine.call_args.kwargs["requests"]["headers"]
            assert headers["Authorization"] == "Bearer oauth-token-abc"

    def test_falls_back_to_api_key_without_oauth_token(self):
        from redmine_mcp_server import oauth_middleware
        from redmine_mcp_server.redmine_handler import _get_redmine_client
        import redmine_mcp_server.redmine_handler as rh

        with (
            patch.object(oauth_middleware, "get_current_token", return_value=None),
            patch.object(rh, "REDMINE_API_KEY", "test-api-key"),
            patch("redmine_mcp_server.redmine_handler.Redmine") as mock_redmine,
        ):
            _get_redmine_client()
            assert mock_redmine.call_args.kwargs.get("key") == "test-api-key"

    def test_oauth_token_priority_over_api_key(self):
        from redmine_mcp_server import oauth_middleware
        from redmine_mcp_server.redmine_handler import _get_redmine_client
        import redmine_mcp_server.redmine_handler as rh

        with (
            patch.object(
                oauth_middleware, "get_current_token", return_value="oauth-wins"
            ),
            patch.object(rh, "REDMINE_API_KEY", "should-not-be-used"),
            patch("redmine_mcp_server.redmine_handler.Redmine") as mock_redmine,
        ):
            _get_redmine_client()
            kw = mock_redmine.call_args.kwargs
            assert "key" not in kw
            assert kw["requests"]["headers"]["Authorization"] == "Bearer oauth-wins"


# ---------------------------------------------------------------------------
# Mounted app: discovery + DCR
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMountedOAuthApp:
    """End-to-end: when the server is built in oauth mode, the mounted app
    exposes the discovery and registration endpoints DCR clients require."""

    @pytest.fixture
    def app(self):
        # Import requires env vars to be set (already done at module top).
        with patch.dict(os.environ, {"REDMINE_AUTH_MODE": "oauth"}, clear=False):
            # Force fresh module import so FastMCP is built with auth=
            import importlib
            import redmine_mcp_server.redmine_handler as rh
            import redmine_mcp_server.main as main

            importlib.reload(rh)
            importlib.reload(main)
            yield main.app

    @pytest.mark.asyncio
    async def test_authorization_server_advertises_registration_endpoint(self, app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/.well-known/oauth-authorization-server")

        assert response.status_code == 200
        data = response.json()
        # The fix: registration_endpoint must be advertised so DCR-only clients
        # (Codex CLI, Claude Desktop) don't bail with "DCR not supported".
        assert "registration_endpoint" in data
        assert data["registration_endpoint"].endswith("/register")
        assert "S256" in data["code_challenge_methods_supported"]

    @pytest.mark.asyncio
    async def test_register_endpoint_accepts_dynamic_client(self, app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://127.0.0.1:1455/callback"],
                    "client_name": "codex-cli",
                },
            )

        assert response.status_code == 201
        body = response.json()
        assert body["client_id"]
        assert body["client_secret"]
        assert body["redirect_uris"] == ["http://127.0.0.1:1455/callback"]

    @pytest.mark.asyncio
    async def test_protected_resource_metadata_present(self, app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # FastMCP scopes the protected-resource document to the MCP path.
            response = await client.get(
                "/.well-known/oauth-protected-resource/mcp"
            )

        assert response.status_code == 200
        data = response.json()
        assert "authorization_servers" in data
