from sumologic_mcp.clients import state


def add_insight_comment(insight_id: str, body: str) -> dict:
    """Add a free-text comment to a Sumo Logic SIEM Insight.

    Posts to `/sec/v1/insights/{insight_id}/comments`. Comments are the
    free-form thread on the Insight detail page — distinct from the
    structured `resolution` (closure reason) set when an Insight is
    closed via `resolve_insight`.

    Args:
        insight_id: SIEM insight ID (e.g. "INSIGHT-30105").
        body: Comment text.

    Returns:
        {"comment_id": str | int | None, "insight_id": str}
    """
    result = state.siem().add_comment(insight_id, body)
    return {"comment_id": result.get("id"), "insight_id": insight_id}
