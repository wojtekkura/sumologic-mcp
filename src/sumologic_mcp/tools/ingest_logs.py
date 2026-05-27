from sumologic_mcp.clients import state


def ingest_logs(
    payload: dict | list[dict],
    collector_url: str | None = None,
    source_category: str | None = None,
    source_name: str | None = None,
    source_host: str | None = None,
) -> dict:
    """Push one or many JSON log records to a Sumo Logic HTTP Source collector.

    Use this to send arbitrary structured events into a Sumo tenant — for
    example, analyst-authored audit notes from an investigation, summaries
    of automated triage, or correlation outputs that should land in the
    same indexed store the analyst already searches.

    The destination is an HTTP Source URL of the form
    `https://collectors.<region>.sumologic.com/receiver/v1/http/<token>`.
    The path token is a secret — prefer pre-configuring it via the
    `SUMO_COLLECTOR_URL` env var rather than passing it on every call.

    Single object → posted as `application/json`. List of objects →
    posted as newline-delimited JSON (NDJSON), one record per line.

    Args:
        payload: A single JSON object (one record) OR a list of JSON
            objects (many records, sent as NDJSON in one request).
        collector_url: Override the SUMO_COLLECTOR_URL env var. Optional;
            normally leave unset and configure via env.
        source_category: Optional Sumo `_sourceCategory` override for
            this batch (sent as `X-Sumo-Category` header).
        source_name: Optional Sumo `_sourceName` override (sent as
            `X-Sumo-Name` header).
        source_host: Optional Sumo `_sourceHost` override (sent as
            `X-Sumo-Host` header).

    Returns:
        {
            "status_code": int,         # HTTP status from the collector (200 = ok)
            "records_sent": int,        # 1 for a dict, len(list) for a list
            "bytes_sent": int,          # serialized body size on the wire
        }
    """
    url = collector_url or state.creds().collector_url
    if not url:
        raise RuntimeError(
            "No collector URL. Pass `collector_url` or set the SUMO_COLLECTOR_URL "
            "env var in your MCP host config."
        )
    return state.collector().post(
        url,
        payload,
        source_category=source_category,
        source_name=source_name,
        source_host=source_host,
    )
