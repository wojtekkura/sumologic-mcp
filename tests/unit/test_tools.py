"""Tests for claim_incident and attach_note tools."""

from unittest.mock import MagicMock, patch

from sumologic_mcp.credentials import Credentials
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
