from sumologic_mcp.clients import state
from sumologic_mcp.clients.siem import SIEMClient

VALID_RESOLUTIONS = {"Resolved", "False Positive", "No Action", "Duplicate"}


def resolve_insight(
    insight_id: str,
    resolution: str = "Resolved",
    closure_note: str | None = None,
) -> dict:
    """Close a Sumo Logic SIEM Insight with a structured resolution and
    an optional free-text closure note.

    Two API calls are made:
      1. If `closure_note` is provided, POST it to
         `/sec/v1/insights/{insight_id}/comments` (the closure note is
         a regular comment — Sumo has no dedicated closure-note endpoint).
      2. PUT `/sec/v1/insights/{insight_id}/status` with
         `{"status": "closed", "resolution": <resolution>}`.

    Comments and resolutions are independent concepts in the Sumo SEC
    API — `resolution` is a single structured enum string surfaced as
    the "Resolution" field on the closed Insight; comments are the
    free-form thread shown on the Insight detail page.

    Args:
        insight_id: SIEM insight ID (e.g. "INSIGHT-30105").
        resolution: One of "Resolved", "False Positive", "No Action",
            "Duplicate", or a configured custom sub-resolution. Custom
            values are passed through without validation.
        closure_note: Optional free-text comment posted before the
            status change.

    Returns:
        {
            "insight_id": str,
            "resolution": str,
            "comment_id": int | str | None,  # None if no closure_note
            "status": "closed",
        }
    """
    siem = state.siem()

    comment_id: int | str | None = None
    if closure_note:
        comment_result = siem.add_comment(insight_id, closure_note)
        comment_id = comment_result.get("id")

    siem.set_insight_status(insight_id, SIEMClient.STATUS_CLOSED, resolution=resolution)

    return {
        "insight_id": insight_id,
        "resolution": resolution,
        "comment_id": comment_id,
        "status": SIEMClient.STATUS_CLOSED,
    }
