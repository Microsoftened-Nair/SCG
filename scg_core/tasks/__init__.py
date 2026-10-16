"""SCG Background Tasks Package."""

from typing import Any

__all__ = [
    "celery_app",
    "task_clone_and_sbom",
    "task_build_graph",
    "task_enrich_components",
    "task_static_reachability",
    "task_score_and_persist",
    "orchestrate_full_scan",
    "trigger_remediation_task",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        pipeline = importlib.import_module("scg_core.tasks.pipeline")
        return getattr(pipeline, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
