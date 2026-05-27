"""Tests for SIEM and SOAR clients."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from sumologic_mcp.clients.base import REGION_URLS, get_base_url, make_session
from sumologic_mcp.clients.collector import CollectorClient
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

    def test_add_comment_hits_documented_endpoint_with_body_payload(self) -> None:
        # Spec: POST /sec/v1/insights/{id}/comments with {"body": "<text>"}.
        # Verifies the closure-note/comment endpoint contract — Sumo expects
        # the field name `body`, not `text` or `comment`.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = b'{"id":99,"body":"hello"}'
        mock_resp.json.return_value = {"id": 99, "body": "hello"}
        with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
            result = client.add_comment("INSIGHT-30105", "hello")
            assert result["id"] == 99
            url = mock_post.call_args.args[0]
            assert url.endswith("/insights/INSIGHT-30105/comments")
            payload = mock_post.call_args.kwargs["json"]
            assert payload == {"body": "hello"}

    def test_set_insight_status_closed_includes_resolution(self) -> None:
        # Spec: PUT /sec/v1/insights/{id}/status with
        # {"status":"closed","resolution":"<reason>"} when closing.
        # The resolution field is the structured close-reason ("False
        # Positive", "Resolved", etc.) — distinct from a free-text comment.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = b"{}"
        mock_resp.json.return_value = {}
        with patch.object(client.session, "put", return_value=mock_resp) as mock_put:
            client.set_insight_status("INSIGHT-30105", "closed", resolution="False Positive")
            url = mock_put.call_args.args[0]
            assert url.endswith("/insights/INSIGHT-30105/status")
            payload = mock_put.call_args.kwargs["json"]
            assert payload == {"status": "closed", "resolution": "False Positive"}

    def test_set_insight_status_drops_resolution_when_not_closed(self) -> None:
        # Sumo only honors `resolution` when status == "closed". Sending
        # it on an inprogress/new transition would be silently ignored
        # by the server — drop it client-side to keep the payload clean.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = b"{}"
        mock_resp.json.return_value = {}
        with patch.object(client.session, "put", return_value=mock_resp) as mock_put:
            client.set_insight_status("INSIGHT-30105", "inprogress", resolution="Resolved")
            payload = mock_put.call_args.kwargs["json"]
            assert payload == {"status": "inprogress"}
            assert "resolution" not in payload

    def test_set_insight_status_no_resolution_when_omitted(self) -> None:
        # Back-compat: existing callers (claim_incident) pass status only.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.content = b"{}"
        mock_resp.json.return_value = {}
        with patch.object(client.session, "put", return_value=mock_resp) as mock_put:
            client.set_insight_status("INSIGHT-30105", "closed")
            payload = mock_put.call_args.kwargs["json"]
            assert payload == {"status": "closed"}

    def test_assign_insight(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"status": "ok"}
        with patch.object(client.session, "put", return_value=mock_resp) as mock_put:
            client.assign_insight("INSIGHT-123", "analyst@test.test")
            call_args = mock_put.call_args
            assert "assignee" in call_args.kwargs.get("json", call_args[1].get("json", {}))

    def test_list_insights_hits_documented_path_and_required_params(self) -> None:
        # Spec: GET /sec/v1/insights/all with required `recordSummaryFields`
        # and `expand=signals`. No `limit`, no `offset`, no `sort` parameters.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "data": {"objects": [{"id": "1"}], "nextPageToken": None}
        }
        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            client.list_insights("status:new")
            mock_get.assert_called_once()
            url = mock_get.call_args.args[0]
            assert url.endswith("/insights/all")
            params = mock_get.call_args.kwargs["params"]
            assert params == {
                "q": "status:new",
                "recordSummaryFields": "device_ip,user_username",
                "expand": "signals",
            }
            # Forbidden params from the old offset/limit shape must not appear.
            for forbidden in ("limit", "offset", "sort", "sortDir"):
                assert forbidden not in params

    def test_list_insights_paginates_via_next_page_token(self) -> None:
        client = self._make_client()
        first = MagicMock()
        first.ok = True
        first.json.return_value = {
            "data": {
                "objects": [{"id": "a"}, {"id": "b"}],
                "nextPageToken": "page-2-token",
            }
        }
        second = MagicMock()
        second.ok = True
        second.json.return_value = {
            "data": {"objects": [{"id": "c"}], "nextPageToken": None}
        }
        with patch.object(client.session, "get", side_effect=[first, second]) as mock_get:
            result = client.list_insights("status:new")
            assert [r["id"] for r in result] == ["a", "b", "c"]
            assert mock_get.call_count == 2
            # First page MUST NOT carry a token.
            assert "nextPageToken" not in mock_get.call_args_list[0].kwargs["params"]
            # Second page MUST carry the token from page 1's response.
            second_params = mock_get.call_args_list[1].kwargs["params"]
            assert second_params["nextPageToken"] == "page-2-token"
            # Required params persist across pages.
            assert second_params["recordSummaryFields"] == "device_ip,user_username"
            assert second_params["expand"] == "signals"

    def test_list_insights_handles_top_level_next_page_token(self) -> None:
        # Some deployments place `nextPageToken` at the top level of the
        # response rather than inside the `data` envelope. Both must work.
        client = self._make_client()
        first = MagicMock()
        first.ok = True
        first.json.return_value = {
            "data": {"objects": [{"id": "x"}]},
            "nextPageToken": "tok",
        }
        second = MagicMock()
        second.ok = True
        second.json.return_value = {"data": {"objects": [{"id": "y"}]}}
        with patch.object(client.session, "get", side_effect=[first, second]) as mock_get:
            result = client.list_insights("status:new")
            assert len(result) == 2
            assert mock_get.call_args_list[1].kwargs["params"]["nextPageToken"] == "tok"

    def test_list_insights_terminates_when_no_token(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"data": {"objects": [{"id": "1"}]}}
        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            result = client.list_insights("status:new")
            assert len(result) == 1
            mock_get.assert_called_once()

    def test_list_insights_empty(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"data": {"objects": []}}
        with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
            result = client.list_insights("status:new")
            assert result == []
            mock_get.assert_called_once()

    def test_list_insights_pagination_iteration_bound(self) -> None:
        # Defensive: a server that keeps returning fresh tokens forever
        # must not be allowed to drive an infinite loop.
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "data": {"objects": [{"id": "1"}], "nextPageToken": "never-ends"}
        }
        with (
            patch.object(client.session, "get", return_value=mock_resp),
            pytest.raises(RuntimeError, match="exceeded 100 pagination iterations"),
        ):
            client.list_insights("status:new")

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


class TestCollectorClient:
    """Sumo HTTP Source ingest endpoint. URL contains an embedded token —
    auth is the URL itself; no basic auth header is sent."""

    URL = "https://collectors.de.sumologic.com/receiver/v1/http/FAKE_TOKEN"

    def _ok_resp(self) -> MagicMock:
        r = MagicMock()
        r.ok = True
        r.status_code = 200
        r.text = ""
        return r

    def test_single_dict_serializes_as_json_object(self) -> None:
        client = CollectorClient()
        with patch.object(client.session, "post", return_value=self._ok_resp()) as mock_post:
            result = client.post(self.URL, {"event": "login", "user": "alice"})
            assert result == {
                "status_code": 200,
                "records_sent": 1,
                "bytes_sent": len(b'{"event":"login","user":"alice"}'),
            }
            sent_body = mock_post.call_args.kwargs["data"]
            # Single JSON object, no trailing newline.
            assert sent_body == b'{"event":"login","user":"alice"}'
            assert mock_post.call_args.kwargs["headers"]["Content-Type"] == "application/json"

    def test_list_serializes_as_ndjson(self) -> None:
        # Spec: a list of records → one JSON object per line, newline-
        # delimited. This is what Sumo's HTTP Source expects for bulk.
        client = CollectorClient()
        with patch.object(client.session, "post", return_value=self._ok_resp()) as mock_post:
            result = client.post(self.URL, [{"a": 1}, {"a": 2}, {"a": 3}])
            assert result["records_sent"] == 3
            sent_body = mock_post.call_args.kwargs["data"].decode("utf-8")
            lines = sent_body.split("\n")
            assert lines == ['{"a":1}', '{"a":2}', '{"a":3}']

    def test_url_is_not_echoed_in_http_error(self) -> None:
        # Defense: the URL contains a secret token. Error messages must
        # never include it.
        client = CollectorClient()
        bad = MagicMock()
        bad.ok = False
        bad.status_code = 401
        bad.text = "unauthorized"
        with patch.object(client.session, "post", return_value=bad):
            with pytest.raises(requests.HTTPError) as exc:
                client.post(self.URL, {"x": 1})
            assert "FAKE_TOKEN" not in str(exc.value)
            assert "401" in str(exc.value)

    def test_optional_metadata_headers(self) -> None:
        client = CollectorClient()
        with patch.object(client.session, "post", return_value=self._ok_resp()) as mock_post:
            client.post(
                self.URL,
                {"x": 1},
                source_category="security/test",
                source_name="sumologic-mcp",
                source_host="analyst-laptop",
            )
            h = mock_post.call_args.kwargs["headers"]
            assert h["X-Sumo-Category"] == "security/test"
            assert h["X-Sumo-Name"] == "sumologic-mcp"
            assert h["X-Sumo-Host"] == "analyst-laptop"

    def test_rejects_empty_list(self) -> None:
        client = CollectorClient()
        with pytest.raises(ValueError, match="empty list"):
            client.post(self.URL, [])

    def test_rejects_non_dict_in_list(self) -> None:
        client = CollectorClient()
        with pytest.raises(ValueError, match="must be a JSON object"):
            client.post(self.URL, [{"ok": 1}, "not a dict"])  # type: ignore[list-item]

    def test_rejects_wrong_payload_type(self) -> None:
        client = CollectorClient()
        with pytest.raises(TypeError, match="dict or list"):
            client.post(self.URL, "raw string")  # type: ignore[arg-type]

    def test_no_basic_auth_sent(self) -> None:
        # The collector URL IS the auth. Make sure we didn't accidentally
        # bolt basic auth onto the session (which would leak the
        # analyst's SIEM creds to a different endpoint).
        client = CollectorClient()
        assert client.session.auth is None
