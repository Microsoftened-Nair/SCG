"""SCG Database Package."""

from typing import Any

__all__ = [
    "db_record_to_report",
    "report_to_db_record",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        import importlib

        mappers = importlib.import_module("scg_core.db.mappers")
        return getattr(mappers, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
