"""Tests for SIEM and SOAR clients."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from sumologic_mcp.clients.base import REGION_URLS, get_base_url, make_session
from sumologic_mcp.clients.siem import SIEMClient
from sumologic_mcp.clients.soar import SOARClient
from sumologic_mcp.credentials import Credentials


def _make_creds() -> Credentials:
    return Credentials(
        access_id="test-id",
        access_key="test-key",
        region="us1",
        analyst_username="analyst@test.test",
        soar_owner_id=42,
    )


class TestGetBaseUrl:
    def test_valid_siem(self) -> None:
        url = get_base_url("us1", "siem")
        assert url == "https://api.sumologic.com/api/sec/v1/"

    def test_valid_soar(self) -> None:
        url = get_base_url("eu", "soar")
        assert url == "https://api.eu.sumologic.com/api/csoar/v3/"

    def test_all_regions(self) -> None:
        for region in REGION_URLS:
            url = get_base_url(region, "siem")
            assert url.startswith("https://")
            assert url.endswith("/api/sec/v1/")

    def test_invalid_region(self) -> None:
        with pytest.raises(RuntimeError, match="Unknown region"):
            get_base_url("mars", "siem")

    def test_invalid_api(self) -> None:
        with pytest.raises(ValueError, match="Unknown api"):
            get_base_url("us1", "invalid")

    def test_case_insensitive_region(self) -> None:
        url = get_base_url("US1", "siem")
        assert url == "https://api.sumologic.com/api/sec/v1/"


class TestMakeSession:
    def test_returns_session_with_auth(self) -> None:
        session = make_session("my-id", "my-key")
        assert isinstance(session, requests.Session)
        assert session.auth == ("my-id", "my-key")
        assert session.headers["Content-Type"] == "application/json"
        assert session.headers["Accept"] == "application/json"


class TestSIEMClient:
    def _make_client(self) -> SIEMClient:
        return SIEMClient(_make_creds())

    def test_get_insight(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"data": {"id": "INSIGHT-123", "name": "Test Insight"}}
        with patch.object(client.session, "get", return_value=mock_resp):
            result = client.get_insight("INSIGHT-123")
            assert result["id"] == "INSIGHT-123"

    def test_get_insight_http_error(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 404
        mock_resp.text = "Not found"
        with (
            patch.object(client.session, "get", return_value=mock_resp),
            pytest.raises(requests.HTTPError),
        ):
            client.get_insight("INSIGHT-999")

    def test_assign_insight(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"status": "ok"}
        with patch.object(client.session, "put", return_value=mock_resp) as mock_put:
            client.assign_insight("INSIGHT-123", "analyst@test.test")
            call_args = mock_put.call_args
            assert "assignee" in call_args.kwargs.get("json", call_args[1].get("json", {}))

    def test_extract_flare_events_empty(self) -> None:
        client = self._make_client()
        result = client.extract_flare_events({"signals": []})
        assert result == []

    def test_extract_flare_events_with_data(self) -> None:
        client = self._make_client()
        insight = {
            "signals": [
                {
                    "allRecords": [
                        {
                            "fields": {
                                "feed_results.0.items.0.uid": "uid-001",
                                "feed_results.0.items.0.source": "darkweb",
                                "feed_results.0.items.1.uid": "uid-002",
                            }
                        }
                    ]
                }
            ]
        }
        result = client.extract_flare_events(insight)
        assert len(result) == 2
        uids = [e["uid"] for e in result]
        assert "uid-001" in uids
        assert "uid-002" in uids


class TestSOARClient:
    def _make_client(self) -> SOARClient:
        return SOARClient(_make_creds())

    def test_get_folder_id_found(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [
            {"id": 1, "name": "Incidents"},
            {"id": 2, "name": "Archive"},
        ]
        with patch.object(client.session, "get", return_value=mock_resp):
            assert client.get_folder_id("Incidents") == 1

    def test_get_folder_id_not_found(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [{"id": 1, "name": "Incidents"}]
        with patch.object(client.session, "get", return_value=mock_resp):
            assert client.get_folder_id("NonExistent") is None

    def test_list_templates_caches(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = [{"id": 10, "name": "General"}]
        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            result1 = client.list_templates()
            result2 = client.list_templates()
            assert result1 == result2
            mock_get.assert_called_once()

    def test_search_incidents(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"incidents": [{"id": 1}]}
        mock_resp.content = b'{"incidents": [{"id": 1}]}'
        with patch.object(client.session, "post", return_value=mock_resp):
            results = client.search_incidents()
            assert len(results) == 1
