"""SCG Schemas Package."""

from typing import Any

__all__ = [
    "AwareUTC",
    "CvssSource",
    "DependencyNode",
    "Ecosystem",
    "EnrichmentStageResult",
    "FileScanStatus",
    "ImportStatement",
    "InvocationCall",
    "PackageHealthData",
    "ParseConfidence",
    "ReachabilityEvaluationResult",
    "ReachabilityStatus",
    "RegistryMetadataResponse",
    "RepositoryScanReport",
    "ScorecardCheckDetail",
    "ScorecardReport",
    "SemVerString",
    "SeverityLevel",
    "SignalSource",
    "SourceFileScanResult",
    "SourceTier",
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

        if name in (
            "SourceTier",
            "FileScanStatus",
            "ParseConfidence",
            "ImportStatement",
            "InvocationCall",
            "SourceFileScanResult",
            "ReachabilityEvaluationResult",
        ):
            reachability = importlib.import_module("scg_core.schemas.reachability")
            return getattr(reachability, name)

        base = importlib.import_module("scg_core.schemas.base")
        return getattr(base, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
