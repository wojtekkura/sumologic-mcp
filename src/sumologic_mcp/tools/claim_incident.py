import ipaddress
import re
from collections import Counter
from typing import Any

from sumologic_mcp.clients import state

# ─── Source inference ────────────────────────────────────────────────────────

_SOURCE_NAME_PREFIXES = [
    (re.compile(r"^SentinelOne\b", re.I), "sentinelone"),
    (re.compile(r"^Flare\b", re.I), "flare"),
    (re.compile(r"^Okta\b", re.I), "okta"),
]

_SOURCE_FIELD_HINTS = [
    (re.compile(r"^threatInfo\."), "sentinelone"),
    (re.compile(r"^agentDetectionInfo\."), "sentinelone"),
    (re.compile(r"^agentRealtimeInfo\."), "sentinelone"),
    (re.compile(r"^feed_results\."), "flare"),
]


def _flatten_fields(signal: dict) -> dict:
    out: dict = {}
    for rec in signal.get("allRecords", []):
        out.update(rec.get("fields", {}) or {})
    return out


def _infer_source(signal: dict) -> str:
    name = signal.get("name") or ""
    for rx, src in _SOURCE_NAME_PREFIXES:
        if rx.search(name):
            return src
    for key in _flatten_fields(signal):
        for rx, src in _SOURCE_FIELD_HINTS:
            if rx.match(key):
                return src
    return "unknown"


# ─── Per-source key-field tables ─────────────────────────────────────────────

_SENTINELONE_KEYS = [
    ("threatId", ["threatInfo.threatId"]),
    ("threatName", ["threatInfo.threatName"]),
    ("classification", ["threatInfo.classification"]),
    ("confidenceLevel", ["threatInfo.confidenceLevel"]),
    ("filePath", ["threatInfo.filePath"]),
    ("sha256", ["threatInfo.sha256"]),
    ("sha1", ["threatInfo.sha1"]),
    ("md5", ["threatInfo.md5"]),
    ("publisher", ["threatInfo.publisherName"]),
    ("certificate", ["threatInfo.certificateId"]),
    ("mitigationStatus", ["threatInfo.mitigationStatus"]),
    ("incidentStatus", ["threatInfo.incidentStatus"]),
    ("analystVerdict", ["threatInfo.analystVerdict"]),
    ("identifiedAt", ["threatInfo.identifiedAt"]),
    ("storylineId", ["threatInfo.storyline"]),
    ("endpointName", ["agentRealtimeInfo.agentComputerName"]),
    ("agentUuid", ["agentDetectionInfo.agentUuid", "agentRealtimeInfo.agentUuid"]),
    ("agentOsName", ["agentRealtimeInfo.agentOsName"]),
    ("processUser", ["threatInfo.processUser"]),
    ("lastLoggedInUser", ["agentDetectionInfo.agentLastLoggedInUserName"]),
    ("externalIp", ["agentDetectionInfo.externalIp"]),
    ("siteName", ["agentDetectionInfo.siteName", "agentRealtimeInfo.siteName"]),
]

_OKTA_KEYS = [
    ("eventType", ["eventType", "EventData.eventType"]),
    ("outcome", ["outcome.result", "EventData.outcome"]),
    ("actorUser", ["actor.alternateId", "EventData.actorAlternateId"]),
    ("targetUser", ["target.0.alternateId", "EventData.TargetUserName"]),
    ("srcIp", ["client.ipAddress", "EventData.clientIp"]),
    ("userAgent", ["client.userAgent.rawUserAgent"]),
    ("occurredAt", ["occurredAt", "EventData.eventTime"]),
]

_SOURCE_KEY_TABLES = {
    "sentinelone": _SENTINELONE_KEYS,
    "okta": _OKTA_KEYS,
}


def _first_present(fields: dict, keys: list) -> Any:
    for k in keys:
        v = fields.get(k)
        if v not in (None, "", "null"):
            return v
    return None


def _extract_key_fields(signal: dict, source: str) -> dict:
    table = _SOURCE_KEY_TABLES.get(source)
    if not table:
        return {}
    fields = _flatten_fields(signal)
    out: dict = {}
    for name, candidates in table:
        v = _first_present(fields, candidates)
        if v is not None:
            out[name] = v
    return out


# ─── IoC / identity extraction ───────────────────────────────────────────────

_SHA256_RX = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RX = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RX = re.compile(r"\b[a-fA-F0-9]{32}\b")
_IPV4_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RX = re.compile(r"https?://[^\s,;\"<>]+", re.I)


def _is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _extract_iocs(signals: list) -> dict:
    sha256s: set[str] = set()
    sha1s: set[str] = set()
    md5s: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()
    for sig in signals:
        for rec in sig.get("allRecords", []):
            for _k, v in (rec.get("fields", {}) or {}).items():
                if v in (None, "", "null"):
                    continue
                sv = str(v)
                for u in _URL_RX.findall(sv):
                    urls.add(u.rstrip(".,);"))
                for h in _SHA256_RX.findall(sv):
                    sha256s.add(h.lower())
                for h in _SHA1_RX.findall(sv):
                    sha1s.add(h.lower())
                for h in _MD5_RX.findall(sv):
                    md5s.add(h.lower())
                for ipstr in _IPV4_RX.findall(sv):
                    if _is_public_ipv4(ipstr):
                        ips.add(ipstr)
    return {
        "sha256": sorted(sha256s),
        "sha1": sorted(sha1s),
        "md5": sorted(md5s),
        "ipv4_public": sorted(ips),
        "url": sorted(urls),
    }


def _extract_identities(signals: list) -> list:
    out: set[str] = set()
    for sig in signals:
        for rec in sig.get("allRecords", []):
            f = rec.get("fields", {}) or {}
            for k in (
                "EventData.TargetUserName",
                "EventData.SubjectUserName",
                "actor.alternateId",
                "target.0.alternateId",
            ):
                v = f.get(k)
                if v and str(v) not in ("null", ""):
                    out.add(str(v))
    return sorted(out)


# ─── Template auto-selection ─────────────────────────────────────────────────

_SOURCE_PRECEDENCE = ["sentinelone", "flare", "okta", "unknown"]


def _dominant_source(source_counts: dict[str, int]) -> str:
    if not source_counts:
        return "unknown"
    max_count = max(source_counts.values())
    contenders = [s for s, c in source_counts.items() if c == max_count]
    for src in _SOURCE_PRECEDENCE:
        if src in contenders:
            return src
    return contenders[0]


def _pick_template(templates: list[dict], source: str) -> dict:
    if not templates:
        raise RuntimeError("Cloud SOAR returned no incident templates")

    def match(needle: str) -> dict | None:
        for t in templates:
            if needle in (t.get("name") or "").lower():
                return t
        return None

    return (
        (match(source) if source != "unknown" else None)
        or match("general")
        or match("default")
        or templates[0]
    )


# ─── The tool ────────────────────────────────────────────────────────────────


def claim_incident(
    insight_id: str,
    analyst: str | None = None,
) -> dict:
    """Claim a Sumo Logic SIEM Insight: fetch, assign analyst, set inprogress,
    find or create the linked Cloud SOAR incident, and return a structured triage view.

    The SOAR template is auto-derived from the dominant signal source via fuzzy
    substring match on `incident_templates/`, with a general -> default -> first
    fallback chain.

    File-less: the structured triage dict is returned inline to the caller; no
    artifacts are written to disk by this tool.

    Args:
        insight_id: SIEM insight ID (e.g. "INSIGHT-28592").
        analyst: Override SIEM assignee + note author. Defaults to env ANALYST_USERNAME.

    Returns:
        Structured dict with insight metadata, per-signal summaries, inferred
        sources, Flare UIDs, identities, IoC candidates, soar_id, and template
        selection trace.
    """
    siem = state.siem()
    soar = state.soar()
    creds = state.creds()

    final_analyst = analyst or creds.analyst_username
    owner_id = creds.soar_owner_id

    insight = siem.get_insight(insight_id)
    signals = insight.get("signals", []) or []

    per_signal: list[dict] = []
    source_counts: Counter[str] = Counter()
    for idx, sig in enumerate(signals, start=1):
        src = _infer_source(sig)
        source_counts[src] += 1
        per_signal.append(
            {
                "index": idx,
                "name": sig.get("name"),
                "severity": sig.get("severity"),
                "timestamp": sig.get("timestamp"),
                "records": len(sig.get("allRecords") or []),
                "source": src,
                "key_fields": _extract_key_fields(sig, src),
            }
        )

    flare_uids = (
        [e.get("uid") for e in siem.extract_flare_events(insight) if e.get("uid")]
        if signals
        else []
    )
    identities = _extract_identities(signals)
    iocs = _extract_iocs(signals)

    dominant = _dominant_source(dict(source_counts))
    templates = soar.list_templates()
    template = _pick_template(templates, dominant)
    template_id = int(template["id"])
    template_meta = {
        "id": template_id,
        "name": template.get("name", ""),
        "matched_on": f"{dominant} ({source_counts.get(dominant, 0)} signals)",
    }

    siem.assign_insight(insight_id, final_analyst)
    siem.set_insight_status(insight_id, "inprogress")

    existing = soar.find_incident_by_insight(insight_id)
    soar_existed = bool(existing)
    if existing:
        soar_id: int = int(existing["id"])
    else:
        created = soar.create_incident(insight_id, template_id, owner_id=owner_id)
        soar_id = int(created["id"])

    siem.link_soar_incident(insight_id, soar_id, insight_id, assignee=final_analyst)

    entity = insight.get("entity") or {}
    if isinstance(entity, dict):
        entity_out = {"value": entity.get("value"), "type": entity.get("entityType")}
    else:
        entity_out = {"value": str(entity), "type": None}

    return {
        "soar_id": soar_id,
        "soar_incident_existed": soar_existed,
        "analyst": final_analyst,
        "owner_id": owner_id,
        "template": template_meta,
        "insight": {
            "id": insight.get("readableId") or insight.get("id"),
            "name": insight.get("name"),
            "severity": insight.get("severity"),
            "entity": entity_out,
            "created": insight.get("created"),
            "signal_count": len(signals),
        },
        "inferred_sources": dict(source_counts),
        "signals": per_signal,
        "flare_uids": flare_uids,
        "identities": identities,
        "ioc_candidates": iocs,
    }
