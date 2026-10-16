"""Supply Chain Guardian (SCG) Scoring and Policy Governance package."""

from typing import Any

__all__ = [
    "PolicyLoader",
    "PolicyParseError",
    "TrustScoringEngine",
    "VETTED_BUILD_TOOLS",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name in {"TrustScoringEngine", "VETTED_BUILD_TOOLS"}:
            engine = importlib.import_module("scg_core.scoring.engine")
            return getattr(engine, name)

        loader = importlib.import_module("scg_core.scoring.policy_loader")
        return getattr(loader, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
