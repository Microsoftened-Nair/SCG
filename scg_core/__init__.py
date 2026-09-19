"""Supply Chain Guardian (SCG) Core Package."""

from typing import Any

__all__ = [
    "ASTParseError",
    "EnrichmentAPIError",
    "GraphCycleError",
    "ManifestParseError",
    "RateLimitExceededError",
    "RemediationExecutionError",
    "SBOMGenerationError",
    "SCGError",
    "ScoringPolicyError",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        exceptions = importlib.import_module("scg_core.exceptions")
        return getattr(exceptions, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
