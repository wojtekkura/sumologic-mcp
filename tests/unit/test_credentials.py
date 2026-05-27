"""Tests for credential loading — keyring + env-var fallback."""

import os
from unittest.mock import MagicMock, patch

import keyring.errors
import pytest

from sumologic_mcp.credentials import (
    ENV_ACCESS_ID,
    ENV_ACCESS_KEY,
    KEY_ACCESS_ID,
    KEY_ACCESS_KEY,
    SERVICE_NAME,
    Credentials,
    load_credentials,
)


def _mock_keyring(access_id: str | None = "test-id", access_key: str | None = "test-key"):
    """Return a mock keyring module with configurable get_password."""
    mock = MagicMock()

    def fake_get_password(service: str, key: str) -> str | None:
        if service == SERVICE_NAME and key == KEY_ACCESS_ID:
            return access_id
        if service == SERVICE_NAME and key == KEY_ACCESS_KEY:
            return access_key
        return None

    mock.get_password.side_effect = fake_get_password
    return mock


_BASE_ENV = {
    "SUMO_API_REGION": "us1",
    "ANALYST_USERNAME": "analyst@test.test",
    "SOAR_OWNER_ID": "42",
}


class TestLoadCredentials:
    def test_success(self) -> None:
        mock = _mock_keyring()
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
        ):
            creds = load_credentials()
            assert isinstance(creds, Credentials)
            assert creds.access_id == "test-id"
            assert creds.access_key == "test-key"
            assert creds.region == "us1"
            assert creds.analyst_username == "analyst@test.test"
            assert creds.soar_owner_id == 42

    def test_missing_access_id(self) -> None:
        mock = _mock_keyring(access_id=None)
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
            pytest.raises(RuntimeError, match=f"access_id.*{ENV_ACCESS_ID}"),
        ):
            load_credentials()

    def test_missing_access_key(self) -> None:
        mock = _mock_keyring(access_key=None)
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
            pytest.raises(RuntimeError, match=f"access_key.*{ENV_ACCESS_KEY}"),
        ):
            load_credentials()

    def test_missing_region(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV}
        del env["SUMO_API_REGION"]
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
            pytest.raises(RuntimeError, match="SUMO_API_REGION"),
        ):
            load_credentials()

    def test_invalid_region(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV, "SUMO_API_REGION": "mars"}
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
            pytest.raises(RuntimeError, match="Invalid SUMO_API_REGION"),
        ):
            load_credentials()

    def test_missing_analyst_username(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV}
        del env["ANALYST_USERNAME"]
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
            pytest.raises(RuntimeError, match="ANALYST_USERNAME"),
        ):
            load_credentials()

    def test_missing_soar_owner_id(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV}
        del env["SOAR_OWNER_ID"]
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
            pytest.raises(RuntimeError, match="SOAR_OWNER_ID"),
        ):
            load_credentials()

    def test_non_numeric_soar_owner_id(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV, "SOAR_OWNER_ID": "not-a-number"}
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
            pytest.raises(RuntimeError, match="must be an integer"),
        ):
            load_credentials()

    def test_all_valid_regions(self) -> None:
        from sumologic_mcp.credentials import VALID_REGIONS

        mock = _mock_keyring()
        for region in VALID_REGIONS:
            env = {**_BASE_ENV, "SUMO_API_REGION": region}
            with (
                patch("sumologic_mcp.credentials.keyring", mock),
                patch.dict(os.environ, env, clear=True),
            ):
                creds = load_credentials()
                assert creds.region == region


class TestEnvVarFallback:
    """Linux/headless/Docker path: secrets via env vars instead of keyring."""

    def test_env_vars_supply_secrets_when_keyring_empty(self) -> None:
        # No keyring entries; env vars hold the secrets. This is the
        # canonical Linux / Docker / CI shape.
        mock = _mock_keyring(access_id=None, access_key=None)
        env = {
            **_BASE_ENV,
            ENV_ACCESS_ID: "env-id-value",
            ENV_ACCESS_KEY: "env-key-value",
        }
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.access_id == "env-id-value"
            assert creds.access_key == "env-key-value"

    def test_env_vars_win_over_keyring(self) -> None:
        # Both present: env vars take precedence. Documented behavior so
        # CI / one-off runs can override a stale keyring entry without
        # having to wipe it first.
        mock = _mock_keyring(access_id="from-keyring", access_key="from-keyring")
        env = {
            **_BASE_ENV,
            ENV_ACCESS_ID: "from-env",
            ENV_ACCESS_KEY: "from-env",
        }
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.access_id == "from-env"
            assert creds.access_key == "from-env"
            # Keyring was short-circuited entirely — never consulted.
            mock.get_password.assert_not_called()

    def test_env_vars_work_when_keyring_backend_raises(self) -> None:
        # Headless Linux: keyring.get_password raises NoKeyringError /
        # KeyringLocked / etc. Env vars must still satisfy the loader.
        mock = MagicMock()
        mock.get_password.side_effect = keyring.errors.NoKeyringError("no backend")
        env = {
            **_BASE_ENV,
            ENV_ACCESS_ID: "headless-id",
            ENV_ACCESS_KEY: "headless-key",
        }
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.access_id == "headless-id"
            assert creds.access_key == "headless-key"
            mock.get_password.assert_not_called()  # env wins, never tried keyring

    def test_keyring_backend_error_treated_as_missing_when_env_also_unset(self) -> None:
        # Headless Linux with no env vars set: error message must mention
        # the env-var escape hatch so the user knows how to fix it.
        mock = MagicMock()
        mock.get_password.side_effect = keyring.errors.NoKeyringError("no backend")
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
            pytest.raises(RuntimeError, match=ENV_ACCESS_ID),
        ):
            load_credentials()

    def test_empty_env_var_falls_through_to_keyring(self) -> None:
        # Whitespace-only / empty env vars should NOT shadow the keyring —
        # otherwise an accidentally-blank shell export silently breaks
        # everything.
        mock = _mock_keyring(access_id="keyring-id", access_key="keyring-key")
        env = {**_BASE_ENV, ENV_ACCESS_ID: "", ENV_ACCESS_KEY: "   "}
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.access_id == "keyring-id"
            assert creds.access_key == "keyring-key"


class TestCollectorUrl:
    """SUMO_COLLECTOR_URL is optional — only required when ingest_logs
    is invoked. Loader must populate Credentials.collector_url from env."""

    def test_collector_url_loaded_when_env_set(self) -> None:
        mock = _mock_keyring()
        env = {
            **_BASE_ENV,
            "SUMO_COLLECTOR_URL": "https://collectors.de.sumologic.com/receiver/v1/http/TOKEN",
        }
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.collector_url == (
                "https://collectors.de.sumologic.com/receiver/v1/http/TOKEN"
            )

    def test_collector_url_none_when_env_unset(self) -> None:
        # Existing deployments without SUMO_COLLECTOR_URL must still load —
        # the field is optional, ingest_logs raises only at call time.
        mock = _mock_keyring()
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
        ):
            creds = load_credentials()
            assert creds.collector_url is None

    def test_blank_collector_url_treated_as_unset(self) -> None:
        mock = _mock_keyring()
        env = {**_BASE_ENV, "SUMO_COLLECTOR_URL": "   "}
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, env, clear=True),
        ):
            creds = load_credentials()
            assert creds.collector_url is None
