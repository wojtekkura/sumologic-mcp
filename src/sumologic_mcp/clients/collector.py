"""Thin client for Sumo Logic HTTP Source (HTTP Collector) endpoints.

These endpoints are *not* the SIEM/SOAR REST API — they're per-collector
ingest URLs containing an embedded token (everything after
`/receiver/v1/http/` is the secret). Auth is the URL itself; no basic
auth header is sent. Format follows Sumo's documented HTTP Source spec:
- single JSON object → POST as `application/json`
- list of JSON objects → POST as newline-delimited JSON (NDJSON), one
  object per line, still `application/json` content type
"""

import json

import requests


class CollectorClient:
    def __init__(self) -> None:
        # Dedicated session — no basic auth, no inherited credentials.
        # The Authorization is the URL itself.
        self.session = requests.Session()

    @staticmethod
    def _serialize(payload: dict | list[dict]) -> tuple[str, int]:
        """Return (body, record_count). Single dict → JSON; list → NDJSON."""
        if isinstance(payload, dict):
            return json.dumps(payload, separators=(",", ":")), 1
        if isinstance(payload, list):
            if not payload:
                raise ValueError("payload is an empty list")
            if not all(isinstance(item, dict) for item in payload):
                raise ValueError("every item in payload list must be a JSON object")
            body = "\n".join(json.dumps(item, separators=(",", ":")) for item in payload)
            return body, len(payload)
        raise TypeError(
            f"payload must be a dict or list of dicts, got {type(payload).__name__}"
        )

    def post(
        self,
        url: str,
        payload: dict | list[dict],
        source_category: str | None = None,
        source_name: str | None = None,
        source_host: str | None = None,
    ) -> dict:
        """Push one or many JSON records to a Sumo Logic HTTP Source.

        Returns {"status_code": int, "records_sent": int, "bytes_sent": int}.
        Raises requests.HTTPError on non-2xx.
        """
        body, count = self._serialize(payload)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if source_category:
            headers["X-Sumo-Category"] = source_category
        if source_name:
            headers["X-Sumo-Name"] = source_name
        if source_host:
            headers["X-Sumo-Host"] = source_host

        resp = self.session.post(url, data=body.encode("utf-8"), headers=headers)
        if not resp.ok:
            # Truncate response text to keep error messages short. Do NOT
            # echo the URL in the error message — it contains the token.
            raise requests.HTTPError(
                f"POST to collector failed: {resp.status_code} {resp.text[:300]}",
                response=resp,
            )
        return {
            "status_code": resp.status_code,
            "records_sent": count,
            "bytes_sent": len(body.encode("utf-8")),
        }
