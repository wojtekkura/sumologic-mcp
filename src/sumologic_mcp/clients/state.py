from sumologic_mcp.clients.collector import CollectorClient
from sumologic_mcp.clients.siem import SIEMClient
from sumologic_mcp.clients.soar import SOARClient
from sumologic_mcp.credentials import Credentials, load_credentials

_creds: Credentials | None = None
_siem: SIEMClient | None = None
_soar: SOARClient | None = None
_collector: CollectorClient | None = None


def init() -> None:
    global _creds, _siem, _soar, _collector
    _creds = load_credentials()
    _siem = SIEMClient(_creds)
    _soar = SOARClient(_creds)
    _collector = CollectorClient()


def creds() -> Credentials:
    if _creds is None:
        raise RuntimeError("clients.state.init() not called before tool invocation")
    return _creds


def siem() -> SIEMClient:
    if _siem is None:
        raise RuntimeError("clients.state.init() not called before tool invocation")
    return _siem


def soar() -> SOARClient:
    if _soar is None:
        raise RuntimeError("clients.state.init() not called before tool invocation")
    return _soar


def collector() -> CollectorClient:
    if _collector is None:
        raise RuntimeError("clients.state.init() not called before tool invocation")
    return _collector
