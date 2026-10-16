"""Shared schemas and enums for Supply Chain Guardian Track E (Safe Autonomous Remediation).

Governs safe autonomous remediation of direct and transitive dependencies,
including upgrade safety classifications, remediation strategies, verification models,
and pull request results.
"""

from __future__ import annotations

from decimal import Decimal
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from scg_core.schemas.base import Ecosystem


class UpgradeSafetyClassification(str, Enum):
    """Classification of the safety level of a dependency version upgrade."""

    PATCH_FIX_SAFE = "PATCH_FIX_SAFE"
    MINOR_FEATURE_SAFE = "MINOR_FEATURE_SAFE"
    MAJOR_BREAKING = "MAJOR_BREAKING"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    UNRESOLVABLE_CONFLICT = "UNRESOLVABLE_CONFLICT"


class ManifestUpdateMode(str, Enum):
    """Mode for updating dependency manifests and lockfiles."""

    LOCKFILE_ONLY = "LOCKFILE_ONLY"
    RAISE_FLOOR = "RAISE_FLOOR"
    WIDEN_RANGE = "WIDEN_RANGE"


class RemediationStrategy(str, Enum):
    """Remediation strategy applied to resolve a vulnerable dependency."""

    DIRECT_BUMP = "DIRECT_BUMP"
    PARENT_BUMP = "PARENT_BUMP"
    SCOPED_OVERRIDE = "SCOPED_OVERRIDE"
    GLOBAL_OVERRIDE = "GLOBAL_OVERRIDE"
    PIN_TRANSITIVE = "PIN_TRANSITIVE"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class RemediationOutcome(str, Enum):
    """Outcome of attempting to remediate a dependency vulnerability."""

    LOCKFILE_UPDATED = "LOCKFILE_UPDATED"
    MANIFEST_ONLY_FALLBACK = "MANIFEST_ONLY_FALLBACK"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    SANDBOX_ERROR = "SANDBOX_ERROR"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    SUPPRESSED_BY_PRIOR_REJECTION = "SUPPRESSED_BY_PRIOR_REJECTION"


class ScoreComputationMode(str, Enum):
    """Mode used to compute trust score changes post-remediation."""

    RECOMPUTED = "RECOMPUTED"
    ESTIMATED = "ESTIMATED"


class VersionChange(BaseModel):
    """Record of a package version modification occurring during remediation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    from_version: str
    to_version: str
    is_intended_target: bool


class RemediationVerification(BaseModel):
    """Verification results validating that a remediation safely resolves advisories."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_version_resolved: bool
    advisory_still_matches: bool
    lockfile_parses: bool
    unexpected_version_changes: List[VersionChange] = Field(default_factory=list)
    verdict: Literal["VERIFIED", "PARTIAL", "FAILED"]


class RemediationCandidate(BaseModel):
    """Proposed candidate for remediating a dependency vulnerability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    ecosystem: Ecosystem
    current_version: str
    target_version: str
    classification: UpgradeSafetyClassification
    strategy: RemediationStrategy
    manifest_mode: ManifestUpdateMode
    cves_resolved: List[str]
    is_direct: bool
    manifest_path: str
    lockfile_path: Optional[str] = None
    parent_package: Optional[str] = None


class SandboxExecutionResult(BaseModel):
    """Result of executing a remediation action within an isolated sandbox."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: RemediationOutcome
    exit_code: Optional[int] = None
    modified_files: List[str] = Field(default_factory=list)
    stderr_excerpt: Optional[str] = Field(None, max_length=8192)
    duration_seconds: float
    verification: Optional[RemediationVerification] = None


class PullRequestResult(BaseModel):
    """Outcome and metadata from generating a remediation pull request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pr_created: bool
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    branch_name: str
    skipped_reason: Optional[str] = None
    score_before: Decimal
    score_after: Decimal
    score_computation: ScoreComputationMode
