"""
Main entry point for the MCP Redmine server.

This module uses FastMCP's native HTTP transport for MCP protocol communication.
The server runs with built-in HTTP endpoints and handles MCP requests natively.

In OAuth mode, FastMCP's ``OAuthProxy`` (configured in ``redmine_handler``)
automatically serves:
    - /mcp                                       — MCP streamable HTTP transport
    - /.well-known/oauth-authorization-server    — RFC 8414 discovery
    - /.well-known/oauth-protected-resource      — RFC 8707 discovery
    - /register                                  — RFC 7591 DCR shim
    - /authorize, /token, /revoke, /auth/callback
"""

import logging
import os
import uvicorn
from importlib.metadata import version, PackageNotFoundError

# Configure basic logging before importing modules that log during init
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from .redmine_handler import mcp  # noqa: E402

logger = logging.getLogger(__name__)

REDMINE_URL = os.environ.get("REDMINE_URL", "").rstrip("/")
REDMINE_MCP_BASE_URL = os.environ.get(
    "REDMINE_MCP_BASE_URL", "http://localhost:8000"
).rstrip("/")
REDMINE_AUTH_MODE = os.environ.get("REDMINE_AUTH_MODE", "legacy").lower()


def get_version() -> str:
    """Get package version from metadata."""
    try:
        return version("redmine-mcp-server")
    except PackageNotFoundError:
        return "dev"


app = mcp.http_app(stateless_http=True)

logger.info("Redmine MCP Server v%s", get_version())
logger.info("Auth mode: %s", REDMINE_AUTH_MODE)


def main():
    """Main entry point for the console script."""
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, log_config=None)


if __name__ == "__main__":
    main()
