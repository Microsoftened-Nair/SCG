"""SCG Reachability analysis and exposure factor resolution engine."""

from typing import Any

__all__ = [
    "ASTScanner",
    "ReachabilityResolver",
    "normalize_pypi_name",
    "PYPI_IMPORT_TO_DIST",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name in {"ASTScanner", "normalize_pypi_name", "PYPI_IMPORT_TO_DIST"}:
            scanner = importlib.import_module("scg_core.reachability.ast_scanner")
            return getattr(scanner, name)
        if name == "ReachabilityResolver":
            resolver = importlib.import_module("scg_core.reachability.resolver")
            return getattr(resolver, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
