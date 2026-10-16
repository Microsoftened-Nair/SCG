"""SCG Schemas Package."""

from typing import Any

__all__ = [
    "AwareUTC",
    "CvssSource",
    "DependencyNode",
    "Ecosystem",
    "EnrichmentStageResult",
    "PackageHealthData",
    "ReachabilityStatus",
    "RegistryMetadataResponse",
    "RepositoryScanReport",
    "ScorecardCheckDetail",
    "ScorecardReport",
    "SemVerString",
    "SeverityLevel",
    "SignalSource",
    "TrustScoreBreakdown",
    "VersionParseStatus",
    "VulnerabilityRecord",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name in (
            "ScorecardCheckDetail",
            "ScorecardReport",
            "RegistryMetadataResponse",
            "EnrichmentStageResult",
        ):
            enrichment = importlib.import_module("scg_core.schemas.enrichment")
            return getattr(enrichment, name)
        base = importlib.import_module("scg_core.schemas.base")
        return getattr(base, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
