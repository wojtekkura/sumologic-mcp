from datetime import UTC, datetime
from urllib.parse import urljoin

import markdown as md
import requests

from sumologic_mcp.clients.base import get_base_url, make_session
from sumologic_mcp.credentials import Credentials


class SOARClient:
    def __init__(self, creds: Credentials):
        self.session = make_session(creds.access_id, creds.access_key)
        self.base_url = get_base_url(creds.region, "soar")
        self._templates_cache: list[dict] | None = None

    def _get(self, path: str, params: dict | None = None):
        url = urljoin(self.base_url, path)
        resp = self.session.get(url, params=params)
        if not resp.ok:
            raise requests.HTTPError(
                f"GET {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        url = urljoin(self.base_url, path)
        resp = self.session.post(url, json=payload)
        if not resp.ok:
            raise requests.HTTPError(
                f"POST {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json() if resp.content else {}

    def _patch(self, path: str, payload: dict) -> dict:
        url = urljoin(self.base_url, path)
        resp = self.session.patch(url, json=payload)
        if not resp.ok:
            raise requests.HTTPError(
                f"PATCH {url} -> {resp.status_code}: {resp.text[:500]}", response=resp
            )
        return resp.json() if resp.content else {}

    def get_folder_id(self, name: str) -> int | None:
        folders = self._get("folders/")
        if isinstance(folders, list):
            for f in folders:
                if f.get("name") == name:
                    return f["id"]
        return None

    def set_incident_folder(self, incident_id: int, folder_id: int) -> dict:
        return self._patch(f"incidents/{incident_id}/folder/", {"folder_id": folder_id})

    def list_templates(self) -> list[dict]:
        if self._templates_cache is not None:
            return self._templates_cache
        data = self._get("incident_templates/")
        templates = data if isinstance(data, list) else data.get("data", data.get("types", []))
        self._templates_cache = templates
        return templates

    def search_incidents(
        self,
        filter_str: str | None = None,
        page_size: int = 50,
        page_number: int = 1,
        columns: list | None = None,
    ) -> list:
        cols = columns or ["incidentid", "status", "openingtime", "owner", "description", "type"]
        payload: dict = {
            "all": True,
            "page_size": page_size,
            "page_number": page_number,
            "columns": cols,
        }
        if filter_str:
            payload["filter"] = filter_str
        data = self._post("incidents/search/", payload)
        return data if isinstance(data, list) else data.get("incidents", data.get("results", []))

    def find_incident_by_insight(self, insight_id: str) -> dict | None:
        results = self.search_incidents(filter_str=f"Incident ID: {insight_id}")
        return results[0] if results else None

    def create_incident(
        self,
        name: str,
        template_id: int,
        description: str = "",
        owner_id: int | None = None,
        folder: str = "Incidents",
    ) -> dict:
        fields = {
            "description": description,
            "incidentid": name,
            "opt_2": name,
            "type": ["Incident Management"],
        }
        payload: dict = {
            "name": name,
            "incident_type": {"id": template_id},
            "owner": owner_id,
            "fields": fields,
        }
        result = self._post("incidents/", payload)
        if folder:
            folder_id = self.get_folder_id(folder)
            if folder_id:
                self.set_incident_folder(result["id"], folder_id)
        return result

    def add_note(
        self,
        incident_id: int,
        text: str,
        title: str = "inVestiGator Investigation",
        author: str = "",
    ) -> dict:
        html = md.markdown(text, extensions=["tables", "fenced_code"])
        payload: dict = {
            "title": title,
            "additional_info": html,
            "created_on": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        if author:
            payload["created_by"] = author
        return self._post(f"incidents/{incident_id}/notes/", payload)
