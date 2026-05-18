import re
from urllib.parse import urljoin

import requests

from sumologic_mcp.clients.base import get_base_url, make_session
from sumologic_mcp.credentials import Credentials


class SIEMClient:
    STATUS_NEW = "new"
    STATUS_IN_PROGRESS = "inprogress"
    STATUS_CLOSED = "closed"

    def __init__(self, creds: Credentials):
        self.session = make_session(creds.access_id, creds.access_key)
        self.base_url = get_base_url(creds.region, "siem")

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = urljoin(self.base_url, path)
        resp = self.session.get(url, params=params)
        if not resp.ok:
            raise requests.HTTPError(
                f"GET {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json()

    def _put(self, path: str, payload: dict) -> dict:
        url = urljoin(self.base_url, path)
        resp = self.session.put(url, json=payload)
        if not resp.ok:
            raise requests.HTTPError(
                f"PUT {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json() if resp.content else {}

    def _post(self, path: str, payload: dict) -> dict:
        url = urljoin(self.base_url, path)
        resp = self.session.post(url, json=payload)
        if not resp.ok:
            raise requests.HTTPError(
                f"POST {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json() if resp.content else {}

    def get_insight(self, insight_id: str) -> dict:
        data = self._get(f"insights/{insight_id}")
        return data.get("data", data)

    # `recordSummaryFields` is marked **required** on Sumo Cloud SIEM's
    # `GET /sec/v1/insights/all`. We don't actually use the per-record
    # summaries (the tool projects from `signals`, not `records`), so a
    # short generic field list is sufficient to satisfy the constraint.
    INSIGHTS_RECORD_SUMMARY_FIELDS = "device_ip,user_username"

    # `expand` controls which subfields are returned. We always need
    # `signals` because list_new_insights projects them; without this,
    # the response omits the signals array.
    INSIGHTS_EXPAND = "signals"

    def list_insights(self, q: str) -> list[dict]:
        """Walk paginated `/insights/all` results matching Sumo's DSL `q`.

        Sumo Logic Cloud SIEM's documented listing endpoint
        (`GET /sec/v1/insights/all`) uses opaque `nextPageToken` pagination,
        not offset/limit. There is no client-controllable page size; Sumo
        decides per-page count and returns a `nextPageToken` until the
        results are exhausted.

        Per Sumo's docs, the `nextPageToken` expires one minute after issue,
        so this loop is intentionally tight — no `time.sleep`, no caller
        callbacks between pages.

        Required parameter `recordSummaryFields` is sent with a small
        generic default; the `expand=signals` knob ensures the response
        carries the signals array that callers project from.

        Bounded at 100 iterations to guard against a misbehaving server
        that keeps issuing tokens forever.
        """
        base_params: dict[str, str] = {
            "recordSummaryFields": self.INSIGHTS_RECORD_SUMMARY_FIELDS,
            "expand": self.INSIGHTS_EXPAND,
        }
        if q:
            base_params["q"] = q

        results: list[dict] = []
        next_token: str | None = None
        for _ in range(100):
            params = dict(base_params)
            if next_token:
                params["nextPageToken"] = next_token
            resp = self._get("insights/all", params)
            data = resp.get("data") or {}
            objects = data.get("objects") or []
            results.extend(objects)
            # Tokens may live in either the `data` envelope or the top
            # level depending on the deployment; check both.
            next_token = data.get("nextPageToken") or resp.get("nextPageToken")
            if not next_token:
                return results
        raise RuntimeError(
            f"list_insights exceeded 100 pagination iterations (q={q!r})"
        )

    def assign_insight(self, insight_id: str, username: str) -> dict:
        return self._put(
            f"insights/{insight_id}/assignee",
            {"assignee": {"type": "USER", "value": username}},
        )

    def set_insight_status(
        self, insight_id: str, status: str, resolution: str | None = None
    ) -> dict:
        payload: dict = {"status": status}
        # `resolution` is the structured close-reason ("False Positive",
        # "Duplicate", "Resolved", "No Action", or a configured custom
        # sub-resolution). Sumo only honors it when status == "closed".
        if status == self.STATUS_CLOSED and resolution:
            payload["resolution"] = resolution
        return self._put(f"insights/{insight_id}/status", payload)

    def add_comment(self, insight_id: str, body: str) -> dict:
        result = self._post(f"insights/{insight_id}/comments", {"body": body})
        return result.get("data", result)

    def link_soar_incident(
        self, insight_id: str, soar_incident_id: int, name: str, assignee: str = ""
    ) -> dict:
        result = self._post(
            f"insights/{insight_id}/related-incidents/",
            {
                "relatedIncidentFields": {
                    "id": soar_incident_id,
                    "name": name,
                    "link": f"/csoar/ui/#incident|{soar_incident_id}|details",
                    "type": "incident",
                    "status": "Open",
                    "assignee": assignee,
                }
            },
        )
        return result.get("data", result)

    def extract_flare_events(self, insight: dict) -> list[dict]:
        events: dict[str, dict] = {}
        for signal in insight.get("signals", []):
            for record in signal.get("allRecords", []):
                fields = record.get("fields", {})
                for key, value in fields.items():
                    m = re.match(r"feed_results\.\d+\.items\.(\d+)\.(.+)", key)
                    if not m or not value or str(value) in ("null", ""):
                        continue
                    item_idx, field = m.group(1), m.group(2)
                    if item_idx not in events:
                        events[item_idx] = {}
                    events[item_idx][field] = value
        seen_uids: set[str] = set()
        result: list[dict] = []
        for item in sorted(events.values(), key=lambda x: x.get("uid", "")):
            uid = item.get("uid")
            if uid and uid not in seen_uids:
                seen_uids.add(uid)
                result.append(item)
        return result
