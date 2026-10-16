"""API Request and Response Data Contracts for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-04, P7-05).
Defines Pydantic v2 schemas, lifecycle status enums, error codes, and the
ScanStatus finite-state machine (FSM).
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ScanStatus(str, Enum):
    """Scan execution lifecycle states."""

    QUEUED = "QUEUED"
    CLONING = "CLONING"
    BUILDING_SBOM = "BUILDING_SBOM"
    ENRICHING = "ENRICHING"
    ANALYZING_REACHABILITY = "ANALYZING_REACHABILITY"
    SCORING = "SCORING"
    COMPLETED = "COMPLETED"
    COMPLETED_PARTIAL = "COMPLETED_PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ErrorCode(str, Enum):
    """Structured categorical error codes for API error responses."""

    REPO_NOT_FOUND = "REPO_NOT_FOUND"
    REPO_TOO_LARGE = "REPO_TOO_LARGE"
    REPO_URL_REJECTED = "REPO_URL_REJECTED"
    NO_SUPPORTED_MANIFEST = "NO_SUPPORTED_MANIFEST"
    UNLOCKED_MANIFEST = "UNLOCKED_MANIFEST"
    UPSTREAM_RATE_LIMITED = "UPSTREAM_RATE_LIMITED"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    PARTIAL_ANALYSIS = "PARTIAL_ANALYSIS"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    UNAUTHORIZED = "UNAUTHORIZED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# Finite-State Machine valid status transitions (P7-05)
VALID_TRANSITIONS: Dict[ScanStatus, Set[ScanStatus]] = {
    ScanStatus.QUEUED: {
        ScanStatus.CLONING,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.CLONING: {
        ScanStatus.BUILDING_SBOM,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.BUILDING_SBOM: {
        ScanStatus.ENRICHING,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.ENRICHING: {
        ScanStatus.ANALYZING_REACHABILITY,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.ANALYZING_REACHABILITY: {
        ScanStatus.SCORING,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.SCORING: {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_PARTIAL,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.COMPLETED_PARTIAL: set(),
    ScanStatus.FAILED: set(),
    ScanStatus.CANCELLED: set(),
}


def validate_transition(current: ScanStatus, target: ScanStatus) -> None:
    """Validate that transitioning from current to target ScanStatus is permitted by the FSM.

    Args:
        current: Current ScanStatus enum value.
        target: Target ScanStatus enum value.

    Raises:
        ValueError: If the state transition is illegal.
    """
    allowed_targets = VALID_TRANSITIONS.get(current, set())
    if target not in allowed_targets:
        raise ValueError(
            f"Invalid state transition: cannot transition scan status from {current.value} to {target.value}"
        )


class ErrorResponse(BaseModel):
    """Standardized error payload conformant to RFC 7807 principles."""

    model_config = ConfigDict(extra="forbid")

    code: ErrorCode
    message: str
    detail: Optional[str] = None
    retryable: bool
    scan_id: Optional[uuid.UUID] = None
    trace_id: Optional[str] = None


class ScanInitiationRequest(BaseModel):
    """Payload to initiate a new repository scan."""

    model_config = ConfigDict(extra="forbid")

    repository_url: HttpUrl
    branch: Optional[str] = Field(default=None, max_length=128)


class ScanInitiationResponse(BaseModel):
    """Response returned upon accepting a new scan request."""

    model_config = ConfigDict(extra="forbid")

    scan_id: uuid.UUID
    status: ScanStatus
    poll_url: str


class ScanStatusResponse(BaseModel):
    """Detailed scan status and point-in-time scoring summary."""

    model_config = ConfigDict(extra="forbid")

    scan_id: uuid.UUID
    status: ScanStatus
    overall_trust_score: Optional[float] = None
    mean_confidence: Optional[float] = None
    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    analysis_completeness: str = "FULL"
    error: Optional[ErrorResponse] = None


class GraphNodeSummary(BaseModel):
    """Bounded graph node representation for dependency visualization."""

    model_config = ConfigDict(extra="forbid")

    purl: str
    package_name: str
    version: str
    depth: Optional[int] = None
    composite_score: float
    risk_tier: str
    vuln_count: int
    reachability: str


class GraphEdge(BaseModel):
    """Directed dependency relationship edge between two purls."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str


class BoundedGraphResponse(BaseModel):
    """Bounded dependency graph response (P7-09)."""

    model_config = ConfigDict(extra="forbid")

    scan_id: uuid.UUID
    total_nodes: int
    truncated: bool
    nodes: List[GraphNodeSummary]
    edges: List[GraphEdge]


class RemediationTriggerRequest(BaseModel):
    """Request payload to initiate safe autonomous remediation."""

    model_config = ConfigDict(extra="forbid")

    package_name: str
    target_version: str
    base_branch: str = "main"


if __name__ == "__main__":
    print("Executing verification harness for scg_core/schemas/api.py (REQ-P7-06)...")

    # 1. Assert valid state transitions pass
    try:
        validate_transition(ScanStatus.QUEUED, ScanStatus.CLONING)
        validate_transition(ScanStatus.CLONING, ScanStatus.BUILDING_SBOM)
        validate_transition(ScanStatus.BUILDING_SBOM, ScanStatus.ENRICHING)
        validate_transition(ScanStatus.ENRICHING, ScanStatus.ANALYZING_REACHABILITY)
        validate_transition(ScanStatus.ANALYZING_REACHABILITY, ScanStatus.SCORING)
        validate_transition(ScanStatus.SCORING, ScanStatus.COMPLETED)
        validate_transition(ScanStatus.SCORING, ScanStatus.COMPLETED_PARTIAL)
        validate_transition(ScanStatus.QUEUED, ScanStatus.FAILED)
        validate_transition(ScanStatus.QUEUED, ScanStatus.CANCELLED)
        print("✓ Valid state transitions (including QUEUED -> CLONING) passed successfully.")
    except Exception as exc:
        raise AssertionError(f"Valid transition raised unexpected exception: {exc}") from exc

    # 2. Assert illegal transitions raise ValueError
    try:
        validate_transition(ScanStatus.QUEUED, ScanStatus.COMPLETED)
        raise AssertionError("Illegal transition QUEUED -> COMPLETED failed to raise ValueError")
    except ValueError as exc:
        assert "Invalid state transition" in str(exc)
        print("✓ Illegal transition (QUEUED -> COMPLETED) correctly raised ValueError.")

    try:
        validate_transition(ScanStatus.COMPLETED, ScanStatus.CLONING)
        raise AssertionError("Illegal transition COMPLETED -> CLONING failed to raise ValueError")
    except ValueError as exc:
        assert "Invalid state transition" in str(exc)
        print("✓ Illegal transition from terminal state correctly raised ValueError.")

    print("PHASE 7 API SCHEMAS & FSM VALIDATION: SUCCESS")
