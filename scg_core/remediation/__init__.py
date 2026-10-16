"""Supply Chain Guardian Track E: Autonomous Remediation package."""

from typing import Any

__all__ = ["SemVerSolver"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        module = importlib.import_module("scg_core.remediation.semver_solver")
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
