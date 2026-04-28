import requests

REGION_URLS = {
    "us1": "https://api.sumologic.com",
    "us2": "https://api.us2.sumologic.com",
    "eu": "https://api.eu.sumologic.com",
    "de": "https://api.de.sumologic.com",
    "au": "https://api.au.sumologic.com",
    "jp": "https://api.jp.sumologic.com",
    "ca": "https://api.ca.sumologic.com",
    "in": "https://api.in.sumologic.com",
}

SIEM_PATH = "/api/sec/v1/"
SOAR_PATH = "/api/csoar/v3/"


def get_base_url(region: str, api: str) -> str:
    region = region.lower()
    if region not in REGION_URLS:
        raise RuntimeError(f"Unknown region '{region}'. Valid: {', '.join(REGION_URLS)}")
    paths = {"siem": SIEM_PATH, "soar": SOAR_PATH}
    if api not in paths:
        raise ValueError(f"Unknown api '{api}'. Valid: {', '.join(paths)}")
    return REGION_URLS[region] + paths[api]


def make_session(access_id: str, access_key: str) -> requests.Session:
    session = requests.Session()
    session.auth = (access_id, access_key)
    session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    return session
