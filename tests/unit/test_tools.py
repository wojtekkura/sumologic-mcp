"""Tests for claim_incident and attach_note tools."""

import re
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from sumologic_mcp.credentials import Credentials
from sumologic_mcp.tools.add_insight_comment import add_insight_comment
from sumologic_mcp.tools.attach_note import attach_note
from sumologic_mcp.tools.claim_incident import (
    _dominant_source,
    _extract_identities,
    _extract_iocs,
    _infer_source,
    _is_public_ipv4,
    _pick_template,
    claim_incident,
)
from sumologic_mcp.tools.list_new_insights import _build_query, list_new_insights
from sumologic_mcp.tools.resolve_insight import resolve_insight


def _make_creds() -> Credentials:
    return Credentials(
        access_id="test-id",
        access_key="test-key",
        region="us1",
        analyst_username="analyst@test.test",
        soar_owner_id=42,
    )


class TestInferSource:
    def test_sentinelone_by_name(self) -> None:
        assert _infer_source({"name": "SentinelOne - Threat Detected"}) == "sentinelone"

    def test_flare_by_name(self) -> None:
        assert _infer_source({"name": "Flare - Dark Web Alert"}) == "flare"

    def test_okta_by_name(self) -> None:
        assert _infer_source({"name": "Okta - Login Failure"}) == "okta"

    def test_sentinelone_by_field(self) -> None:
        signal = {
            "name": "Generic Signal",
            "allRecords": [{"fields": {"threatInfo.threatId": "123"}}],
        }
        assert _infer_source(signal) == "sentinelone"

    def test_flare_by_field(self) -> None:
        signal = {
            "name": "Generic",
            "allRecords": [{"fields": {"feed_results.0.items.0.uid": "x"}}],
        }
        assert _infer_source(signal) == "flare"

    def test_unknown_source(self) -> None:
        assert _infer_source({"name": "Something Else", "allRecords": []}) == "unknown"


class TestDominantSource:
    def test_single_source(self) -> None:
        assert _dominant_source({"sentinelone": 3}) == "sentinelone"

    def test_tie_uses_precedence(self) -> None:
        assert _dominant_source({"okta": 2, "sentinelone": 2}) == "sentinelone"

    def test_empty(self) -> None:
        assert _dominant_source({}) == "unknown"

    def test_highest_count_wins(self) -> None:
        assert _dominant_source({"okta": 5, "sentinelone": 2}) == "okta"


class TestPickTemplate:
    def test_matches_source_name(self) -> None:
        templates = [
            {"id": 1, "name": "General Template"},
            {"id": 2, "name": "SentinelOne Incident"},
        ]
        result = _pick_template(templates, "sentinelone")
        assert result["id"] == 2

    def test_falls_back_to_general(self) -> None:
        templates = [
            {"id": 1, "name": "General Template"},
            {"id": 2, "name": "Other"},
        ]
        result = _pick_template(templates, "unknown")
        assert result["id"] == 1

    def test_falls_back_to_default(self) -> None:
        templates = [
            {"id": 1, "name": "Default Template"},
            {"id": 2, "name": "Other"},
        ]
        result = _pick_template(templates, "unknown")
        assert result["id"] == 1

    def test_falls_back_to_first(self) -> None:
        templates = [{"id": 99, "name": "Custom Only"}]
        result = _pick_template(templates, "unknown")
        assert result["id"] == 99


class TestIsPublicIpv4:
    def test_public(self) -> None:
        assert _is_public_ipv4("8.8.8.8") is True

    def test_private(self) -> None:
        assert _is_public_ipv4("192.168.1.1") is False

    def test_loopback(self) -> None:
        assert _is_public_ipv4("127.0.0.1") is False

    def test_invalid(self) -> None:
        assert _is_public_ipv4("not-an-ip") is False


class TestExtractIocs:
    def test_extracts_sha256(self) -> None:
        sha = "a" * 64
        signals = [{"allRecords": [{"fields": {"hash": sha}}]}]
        iocs = _extract_iocs(signals)
        assert sha in iocs["sha256"]

    def test_extracts_public_ip(self) -> None:
        signals = [{"allRecords": [{"fields": {"src_ip": "8.8.8.8"}}]}]
        iocs = _extract_iocs(signals)
        assert "8.8.8.8" in iocs["ipv4_public"]

    def test_skips_private_ip(self) -> None:
        signals = [{"allRecords": [{"fields": {"src_ip": "10.0.0.1"}}]}]
        iocs = _extract_iocs(signals)
        assert "10.0.0.1" not in iocs["ipv4_public"]

    def test_extracts_url(self) -> None:
        signals = [{"allRecords": [{"fields": {"link": "https://evil.test/payload"}}]}]
        iocs = _extract_iocs(signals)
        assert "https://evil.test/payload" in iocs["url"]


class TestExtractIdentities:
    def test_extracts_usernames(self) -> None:
        signals = [
            {
                "allRecords": [
                    {
                        "fields": {
                            "actor.alternateId": "user@test.test",
                            "target.0.alternateId": "admin@test.test",
                        }
                    }
                ]
            }
        ]
        identities = _extract_identities(signals)
        assert "user@test.test" in identities
        assert "admin@test.test" in identities

    def test_empty_signals(self) -> None:
        assert _extract_identities([]) == []


class TestClaimIncident:
    @patch("sumologic_mcp.tools.claim_incident.state")
    def test_claim_creates_soar_incident(self, mock_state: MagicMock) -> None:
        creds = _make_creds()
        mock_state.creds.return_value = creds
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_state.soar.return_value = mock_soar = MagicMock()

        mock_siem.get_insight.return_value = {
            "readableId": "INSIGHT-100",
            "name": "Test Insight",
            "severity": "HIGH",
            "entity": {"value": "1.2.3.4", "entityType": "ip"},
            "created": "2026-01-01T00:00:00Z",
            "signals": [],
        }
        mock_soar.list_templates.return_value = [{"id": 1, "name": "General Template"}]
        mock_soar.find_incident_by_insight.return_value = None
        mock_soar.create_incident.return_value = {"id": 999}

        result = claim_incident("INSIGHT-100")

        assert result["soar_id"] == 999
        assert result["soar_incident_existed"] is False
        assert result["analyst"] == "analyst@test.test"
        mock_siem.assign_insight.assert_called_once_with("INSIGHT-100", "analyst@test.test")
        mock_siem.set_insight_status.assert_called_once_with("INSIGHT-100", "inprogress")

    @patch("sumologic_mcp.tools.claim_incident.state")
    def test_claim_reuses_existing_soar_incident(self, mock_state: MagicMock) -> None:
        creds = _make_creds()
        mock_state.creds.return_value = creds
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_state.soar.return_value = mock_soar = MagicMock()

        mock_siem.get_insight.return_value = {
            "readableId": "INSIGHT-200",
            "name": "Existing",
            "severity": "LOW",
            "entity": {"value": "host.test", "entityType": "hostname"},
            "created": "2026-01-01T00:00:00Z",
            "signals": [],
        }
        mock_soar.list_templates.return_value = [{"id": 1, "name": "General"}]
        mock_soar.find_incident_by_insight.return_value = {"id": 555}

        result = claim_incident("INSIGHT-200")

        assert result["soar_id"] == 555
        assert result["soar_incident_existed"] is True
        mock_soar.create_incident.assert_not_called()


class TestAttachNote:
    @patch("sumologic_mcp.tools.attach_note.state")
    def test_attach_note_success(self, mock_state: MagicMock) -> None:
        creds = _make_creds()
        mock_state.creds.return_value = creds
        mock_state.soar.return_value = mock_soar = MagicMock()
        mock_soar.add_note.return_value = {"id": 42}

        result = attach_note(incident_id=100, text="# Finding\nSome markdown")

        assert result["note_id"] == 42
        assert result["author"] == "analyst@test.test"

    @patch("sumologic_mcp.tools.attach_note.state")
    def test_attach_note_custom_author(self, mock_state: MagicMock) -> None:
        creds = _make_creds()
        mock_state.creds.return_value = creds
        mock_state.soar.return_value = mock_soar = MagicMock()
        mock_soar.add_note.return_value = {"id": 43}

        result = attach_note(incident_id=100, text="note", author="custom@test.test")

        assert result["author"] == "custom@test.test"


class TestAddInsightComment:
    @patch("sumologic_mcp.tools.add_insight_comment.state")
    def test_posts_comment_and_returns_id(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.add_comment.return_value = {"id": 777, "body": "hi"}

        result = add_insight_comment("INSIGHT-30105", "hi")

        # The tool MUST call the underlying client; this is the
        # "comment was added" assertion.
        mock_siem.add_comment.assert_called_once_with("INSIGHT-30105", "hi")
        assert result == {"comment_id": 777, "insight_id": "INSIGHT-30105"}

    @patch("sumologic_mcp.tools.add_insight_comment.state")
    def test_handles_missing_id_in_response(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.add_comment.return_value = {}

        result = add_insight_comment("INSIGHT-30105", "hi")

        assert result["comment_id"] is None
        assert result["insight_id"] == "INSIGHT-30105"


class TestResolveInsight:
    @patch("sumologic_mcp.tools.resolve_insight.state")
    def test_resolves_with_closure_note_fires_both_endpoints_in_order(
        self, mock_state: MagicMock
    ) -> None:
        # End-to-end contract: when a closure_note is supplied,
        # resolve_insight MUST both add the comment AND set the status
        # to closed with the resolution — in that order.
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.add_comment.return_value = {"id": 101, "body": "closing"}
        mock_siem.set_insight_status.return_value = {}

        result = resolve_insight(
            "INSIGHT-30105",
            resolution="False Positive",
            closure_note="benign — internal test",
        )

        # Comment landed.
        mock_siem.add_comment.assert_called_once_with(
            "INSIGHT-30105", "benign — internal test"
        )
        # Closure resolution landed on the status endpoint.
        mock_siem.set_insight_status.assert_called_once_with(
            "INSIGHT-30105", "closed", resolution="False Positive"
        )
        # Comment first, then status — order matters for audit trail.
        call_names = [c[0] for c in mock_siem.method_calls]
        assert call_names.index("add_comment") < call_names.index("set_insight_status")

        assert result == {
            "insight_id": "INSIGHT-30105",
            "resolution": "False Positive",
            "comment_id": 101,
            "status": "closed",
        }

    @patch("sumologic_mcp.tools.resolve_insight.state")
    def test_resolves_without_closure_note_skips_comment(
        self, mock_state: MagicMock
    ) -> None:
        # No closure_note → no comment API call, but status MUST still close.
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.set_insight_status.return_value = {}

        result = resolve_insight("INSIGHT-30096", resolution="Resolved")

        mock_siem.add_comment.assert_not_called()
        mock_siem.set_insight_status.assert_called_once_with(
            "INSIGHT-30096", "closed", resolution="Resolved"
        )
        assert result["comment_id"] is None
        assert result["resolution"] == "Resolved"
        assert result["status"] == "closed"

    @patch("sumologic_mcp.tools.resolve_insight.state")
    def test_resolution_defaults_to_resolved(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.set_insight_status.return_value = {}

        result = resolve_insight("INSIGHT-30105")

        mock_siem.set_insight_status.assert_called_once_with(
            "INSIGHT-30105", "closed", resolution="Resolved"
        )
        assert result["resolution"] == "Resolved"

    @patch("sumologic_mcp.tools.resolve_insight.state")
    def test_passes_through_custom_subresolution(self, mock_state: MagicMock) -> None:
        # Custom sub-resolutions configured at the tenant level must
        # pass through verbatim — no client-side allowlist.
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.set_insight_status.return_value = {}

        resolve_insight("INSIGHT-30105", resolution="Resolved - Tuned Rule")

        mock_siem.set_insight_status.assert_called_once_with(
            "INSIGHT-30105", "closed", resolution="Resolved - Tuned Rule"
        )


class TestBuildQuery:
    def test_contains_required_clauses(self) -> None:
        q, cutoff = _build_query(24)
        # Sumo's DSL syntax: status:"new" with quotes per the docs.
        assert 'status:"new"' in q
        assert f"created:>{cutoff}" in q

    def test_no_undocumented_assignee_filter(self) -> None:
        # Sumo's custom DSL (docs at /docs/sec/) does not define a
        # "field is absent" operator. The unassigned filter must happen
        # client-side, not in `q`.
        q, _ = _build_query(24)
        assert "_exists_" not in q
        assert "assignee" not in q

    def test_cutoff_format(self) -> None:
        _, cutoff = _build_query(24)
        # ISO-8601 UTC, no microseconds, Z suffix
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", cutoff)

    def test_cutoff_respects_window(self) -> None:
        _, cutoff = _build_query(168)
        parsed = datetime.strptime(cutoff, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
        expected = datetime.now(UTC) - timedelta(hours=168)
        delta = abs((expected - parsed).total_seconds())
        assert delta < 5


class TestListNewInsights:
    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_happy_path(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = [
            {
                "readableId": "INSIGHT-1",
                "name": "Suspicious Login",
                "severity": "HIGH",
                "created": "2026-05-06T10:00:00Z",
                "signals": [
                    {
                        "id": "sig-1",
                        "name": "Okta Login Failure",
                        "severity": "HIGH",
                        "timestamp": "2026-05-06T09:59:00Z",
                        "extra": "should not appear",
                    },
                    {
                        "id": "sig-2",
                        "name": "Geo Anomaly",
                        "severity": "MEDIUM",
                        "timestamp": "2026-05-06T09:58:00Z",
                    },
                ],
            }
        ]

        result = list_new_insights()

        assert result["count"] == 1
        assert result["since_hours"] == 24
        ins = result["insights"][0]
        assert ins["insight_id"] == "INSIGHT-1"
        assert ins["name"] == "Suspicious Login"
        assert ins["severity"] == "HIGH"
        assert ins["created"] == "2026-05-06T10:00:00Z"
        assert ins["signal_count"] == 2
        assert ins["signals"][0] == {
            "id": "sig-1",
            "name": "Okta Login Failure",
            "severity": "HIGH",
            "timestamp": "2026-05-06T09:59:00Z",
        }
        assert "extra" not in ins["signals"][0]

    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_empty(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = []

        result = list_new_insights()

        assert result["count"] == 0
        assert result["insights"] == []
        assert 'status:"new"' in result["query"]

    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_filters_assigned_insights_client_side(
        self, mock_state: MagicMock
    ) -> None:
        # Sumo's DSL has no "field is absent" operator, so unassigned
        # filtering happens here. Anything with a truthy `assignee` must
        # be dropped from the projection.
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = [
            {"readableId": "UNASSIGNED-1", "name": "kept", "signals": []},
            {
                "readableId": "ASSIGNED-1",
                "name": "dropped — already assigned",
                "assignee": {"username": "someone@test.test"},
                "signals": [],
            },
            {
                "readableId": "ASSIGNED-2",
                "name": "dropped — string assignee",
                "assignee": "someone@test.test",
                "signals": [],
            },
            {"readableId": "UNASSIGNED-2", "name": "kept too", "signals": []},
        ]

        result = list_new_insights()

        ids = [ins["insight_id"] for ins in result["insights"]]
        assert ids == ["UNASSIGNED-1", "UNASSIGNED-2"]
        assert result["count"] == 2

    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_since_hours_override_propagates_to_query(
        self, mock_state: MagicMock
    ) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = []

        list_new_insights(since_hours=168)

        sent_q = mock_siem.list_insights.call_args.args[0]
        m = re.search(r"created:>(\S+)", sent_q)
        assert m is not None
        cutoff = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
        expected = datetime.now(UTC) - timedelta(hours=168)
        assert abs((expected - cutoff).total_seconds()) < 5

    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_missing_signals_key(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = [
            {"readableId": "INSIGHT-2", "name": "No Signals"}
        ]

        result = list_new_insights()

        assert result["insights"][0]["signal_count"] == 0
        assert result["insights"][0]["signals"] == []

    @patch("sumologic_mcp.tools.list_new_insights.state")
    def test_insight_id_falls_back_to_id(self, mock_state: MagicMock) -> None:
        mock_state.siem.return_value = mock_siem = MagicMock()
        mock_siem.list_insights.return_value = [
            {"id": "raw-uuid-abc", "name": "No Readable Id"}
        ]

        result = list_new_insights()

        assert result["insights"][0]["insight_id"] == "raw-uuid-abc"
