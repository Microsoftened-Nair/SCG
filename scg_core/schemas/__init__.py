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
    # Phase 5 Track D Scoring Schemas
    "FacetName",
    "EvidenceKind",
    "SuppressionScope",
    "Evidence",
    "Deduction",
    "PolicyWeights",
    "Suppression",
    "SCGPolicyConfig",
    "FacetResult",
    "DependencyScoreResult",
    "ProjectTrustReport",
    "TWO_PLACES",
    "FOUR_PLACES",
    "quantize",
    "SEVERITY_WEIGHTS",
    # Phase 6 Track E Remediation Schemas
    "UpgradeSafetyClassification",
    "ManifestUpdateMode",
    "RemediationStrategy",
    "RemediationOutcome",
    "ScoreComputationMode",
    "VersionChange",
    "RemediationVerification",
    "RemediationCandidate",
    "SandboxExecutionResult",
    "PullRequestResult",
    # Phase 7 API Schemas
    "ScanStatus",
    "ErrorCode",
    "VALID_TRANSITIONS",
    "validate_transition",
    "ErrorResponse",
    "ScanInitiationRequest",
    "ScanInitiationResponse",
    "ScanStatusResponse",
    "GraphNodeSummary",
    "GraphEdge",
    "BoundedGraphResponse",
    "RemediationTriggerRequest",
]

_API_SCHEMAS = {
    "ScanStatus",
    "ErrorCode",
    "VALID_TRANSITIONS",
    "validate_transition",
    "ErrorResponse",
    "ScanInitiationRequest",
    "ScanInitiationResponse",
    "ScanStatusResponse",
    "GraphNodeSummary",
    "GraphEdge",
    "BoundedGraphResponse",
    "RemediationTriggerRequest",
}


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name in _API_SCHEMAS:
            api = importlib.import_module("scg_core.schemas.api")
            return getattr(api, name)

        if name in (
            "FacetName",
            "EvidenceKind",
            "SuppressionScope",
            "Evidence",
            "Deduction",
            "PolicyWeights",
            "Suppression",
            "SCGPolicyConfig",
            "FacetResult",
            "DependencyScoreResult",
            "ProjectTrustReport",
            "TWO_PLACES",
            "FOUR_PLACES",
            "quantize",
            "SEVERITY_WEIGHTS",
        ):
            scoring = importlib.import_module("scg_core.schemas.scoring")
            return getattr(scoring, name)

        if name in (
            "UpgradeSafetyClassification",
            "ManifestUpdateMode",
            "RemediationStrategy",
            "RemediationOutcome",
            "ScoreComputationMode",
            "VersionChange",
            "RemediationVerification",
            "RemediationCandidate",
            "SandboxExecutionResult",
            "PullRequestResult",
        ):
            remediation = importlib.import_module("scg_core.schemas.remediation")
            return getattr(remediation, name)

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
