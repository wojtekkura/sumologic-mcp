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

    def assign_insight(self, insight_id: str, username: str) -> dict:
        return self._put(
            f"insights/{insight_id}/assignee",
            {"assignee": {"type": "USER", "value": username}},
        )

    def set_insight_status(self, insight_id: str, status: str) -> dict:
        return self._put(f"insights/{insight_id}/status", {"status": status})

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
