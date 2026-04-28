"""Tests for credential loading and WCM integration."""

import os
from unittest.mock import MagicMock, patch

import pytest

from sumologic_mcp.credentials import (
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
            pytest.raises(RuntimeError, match="access_id"),
        ):
            load_credentials()

    def test_missing_access_key(self) -> None:
        mock = _mock_keyring(access_key=None)
        with (
            patch("sumologic_mcp.credentials.keyring", mock),
            patch.dict(os.environ, _BASE_ENV, clear=True),
            pytest.raises(RuntimeError, match="access_key"),
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
