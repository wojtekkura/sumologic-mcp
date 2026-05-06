from datetime import UTC, datetime, timedelta

from sumologic_mcp.clients import state
from sumologic_mcp.clients.siem import SIEMClient


def _build_query(since_hours: int) -> tuple[str, str]:
    """Compose Sumo's DSL query for new insights created within the window.

    The `assignee` filter is intentionally NOT in the query — Sumo's custom
    DSL (documented at /docs/sec/) defines explicit operators (`:"value"`,
    `:in(...)`, `:contains(...)`, `:>num`, `:date..date`) but no documented
    "field is absent" operator. We therefore filter unassigned insights
    client-side in `list_new_insights`.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=int(since_hours))
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    q = f'status:"{SIEMClient.STATUS_NEW}" created:>{cutoff_iso}'
    return q, cutoff_iso


def list_new_insights(since_hours: int = 24) -> dict:
    """List Sumo Logic SIEM Insights that are new and unassigned.

    Auto-paginates the Cloud SIEM `/insights/all` endpoint via Sumo's
    `nextPageToken` flow and returns a compact, agent-friendly projection
    of each result, including the signals attached to it. Intended as a
    discovery tool for Claude agents that need to find fresh triage work
    without already knowing an insight ID.

    Args:
        since_hours: Look back window in hours over the insight `created`
            timestamp. Defaults to 24.

    Returns:
        Dict with keys:
            - since_hours: int — the window used.
            - cutoff_utc: str — ISO-8601 UTC cutoff sent in the query.
            - query: str — the Sumo DSL filter sent (debug aid).
            - count: int — number of insights returned (after the
              client-side unassigned filter).
            - insights: list[dict] — one entry per insight, each with
              insight_id, name, severity, created, signal_count, and signals
              (a list of {id, name, severity, timestamp}).
    """
    q, cutoff_iso = _build_query(since_hours)
    raw = state.siem().list_insights(q)

    insights: list[dict] = []
    for ins in raw:
        # Sumo's DSL has no documented "field is absent" operator, so we
        # filter unassigned insights here. Treat any falsy assignee
        # (None, missing key, empty dict) as unassigned.
        if ins.get("assignee"):
            continue
        signals_raw = ins.get("signals") or []
        signals = [
            {
                "id": s.get("id"),
                "name": s.get("name"),
                "severity": s.get("severity"),
                "timestamp": s.get("timestamp"),
            }
            for s in signals_raw
        ]
        insights.append(
            {
                "insight_id": ins.get("readableId") or ins.get("id"),
                "name": ins.get("name"),
                "severity": ins.get("severity"),
                "created": ins.get("created"),
                "signal_count": len(signals),
                "signals": signals,
            }
        )

    return {
        "since_hours": int(since_hours),
        "cutoff_utc": cutoff_iso,
        "query": q,
        "count": len(insights),
        "insights": insights,
    }
