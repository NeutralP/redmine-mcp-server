"""
Configuration file for pytest.

This file configures pytest markers and test settings for the Redmine MCP server tests.
"""

import os

# Provide harmless OAuth credentials so importing redmine_handler succeeds even
# when a parent .env sets REDMINE_AUTH_MODE=oauth. Tests that exercise the
# OAuth proxy directly override these as needed; tests that don't touch OAuth
# remain unaffected. Use setdefault so real env values are respected.
os.environ.setdefault("REDMINE_OAUTH_CLIENT_ID", "test-client-id")
os.environ.setdefault("REDMINE_OAUTH_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("REDMINE_MCP_BASE_URL", "http://localhost:8000")

import pytest  # noqa: E402


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark tests as integration tests (require Redmine)",
    )
    config.addinivalue_line(
        "markers",
        "unit: mark tests as unit tests (use mocks, no external dependencies)",
    )


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    import sys

    src_path = os.path.join(os.path.dirname(__file__), "..", "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    os.environ["TESTING"] = "true"
    yield
    os.environ.pop("TESTING", None)


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Fixture to mock environment variables for testing."""
    monkeypatch.setenv("REDMINE_URL", "https://test-redmine.example.com")
    monkeypatch.setenv("REDMINE_USERNAME", "test_user")
    monkeypatch.setenv("REDMINE_PASSWORD", "test_password")
    monkeypatch.setenv("SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("SERVER_PORT", "8000")


@pytest.fixture
def mock_api_key_env(monkeypatch):
    """Fixture to mock API key authentication environment."""
    monkeypatch.setenv("REDMINE_URL", "https://test-redmine.example.com")
    monkeypatch.setenv("REDMINE_API_KEY", "test_api_key_12345")
    monkeypatch.setenv("SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("SERVER_PORT", "8000")
    # Remove username/password if they exist
    monkeypatch.delenv("REDMINE_USERNAME", raising=False)
    monkeypatch.delenv("REDMINE_PASSWORD", raising=False)
