"""Supply Chain Guardian Track E: Autonomous Remediation package."""

from typing import Any

__all__ = ["SemVerSolver", "SandboxRunner"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        if name == "SemVerSolver":
            module = importlib.import_module("scg_core.remediation.semver_solver")
            return getattr(module, name)
        if name == "SandboxRunner":
            module = importlib.import_module("scg_core.remediation.sandbox_runner")
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
