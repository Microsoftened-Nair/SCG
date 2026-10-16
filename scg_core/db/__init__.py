"""SCG Database Package."""

from typing import Any

__all__ = [
    # Mappers
    "db_record_to_report",
    "report_to_db_record",
    # Models
    "Base",
    "Principal",
    "Repository",
    "ScanRun",
    "Component",
    "ScanComponent",
    "Vulnerability",
    "ComponentVulnerability",
    "RemediationPR",
    # Session
    "async_engine_factory",
    "get_db_session",
    "AsyncSessionLocal",
    "get_sessionmaker",
]

_MODELS = {
    "Base",
    "Principal",
    "Repository",
    "ScanRun",
    "Component",
    "ScanComponent",
    "Vulnerability",
    "ComponentVulnerability",
    "RemediationPR",
}

_SESSION = {
    "async_engine_factory",
    "get_db_session",
    "AsyncSessionLocal",
    "get_sessionmaker",
}


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name in _MODELS:
            models = importlib.import_module("scg_core.db.models")
            return getattr(models, name)
        if name in _SESSION:
            session = importlib.import_module("scg_core.db.session")
            return getattr(session, name)

        mappers = importlib.import_module("scg_core.db.mappers")
        return getattr(mappers, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
