"""SCG Schemas Package."""

from typing import Any

__all__ = [
    "DependencyNode",
    "Ecosystem",
    "PackageHealthData",
    "ReachabilityStatus",
    "RepositoryScanReport",
    "SemVerString",
    "SeverityLevel",
    "TrustScoreBreakdown",
    "VulnerabilityRecord",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        base = importlib.import_module("scg_core.schemas.base")
        return getattr(base, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
