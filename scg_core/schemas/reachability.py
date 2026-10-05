"""Data models and schemas for Static AST Reachability Analysis."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field
from scg_core.schemas.base import Ecosystem, ReachabilityStatus


class SourceTier(str, Enum):
    """Classification of source code files by operational role."""

    APPLICATION = "APPLICATION"
    TEST = "TEST"
    TOOLING = "TOOLING"


class FileScanStatus(str, Enum):
    """Processing status for a source file during AST traversal."""

    SCANNED = "SCANNED"
    SKIPPED_TOO_LARGE = "SKIPPED_TOO_LARGE"
    PARSE_FAILED = "PARSE_FAILED"
    SKIPPED_BINARY = "SKIPPED_BINARY"


class ParseConfidence(str, Enum):
    """Confidence level of AST parsing extraction."""

    HIGH = "HIGH"  # Grammar AST parsed
    LOW = "LOW"  # Fallback regex/heuristic
    FAILED = "FAILED"


class ImportStatement(BaseModel):
    """Extracted import or require statement representation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_file: str
    line_number: int
    raw_module: str
    canonical_package: str
    imported_symbols: List[str] = Field(default_factory=list)
    alias: Optional[str] = None
    is_dynamic: bool = False
    is_reexport: bool = False


class InvocationCall(BaseModel):
    """Function or method call expression extracted from AST."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_file: str
    line_number: int
    caller_symbol: str
    full_expression: str
    resolved_package: Optional[str] = None
    resolved_symbol: Optional[str] = None


class SourceFileScanResult(BaseModel):
    """Per-file extraction output from the AST scanner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_path: str
    tier: SourceTier
    ecosystem: Ecosystem
    status: FileScanStatus
    parse_confidence: ParseConfidence
    imports: List[ImportStatement] = Field(default_factory=list)
    invocations: List[InvocationCall] = Field(default_factory=list)
    parse_errors: List[str] = Field(default_factory=list)


class ReachabilityEvaluationResult(BaseModel):
    """Final reachability and exposure factor evaluation result for a dependency node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    ecosystem: Ecosystem
    resolved_version: str
    graph_depth: Optional[int] = None
    reachability: ReachabilityStatus
    exposure_factor: float = Field(..., ge=0.0, le=1.0)
    effective_exposure_factor: float = Field(..., ge=0.0, le=1.0)
    symbol_confirmed_reachable: bool = False
    evidence_files: List[str] = Field(default_factory=list)
    evidence_call_sites: List[str] = Field(default_factory=list)
