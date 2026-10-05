"""Ingestion and dependency graph construction data contracts for Supply Chain Guardian (SCG).

Conforms to SCG-SRS-PHASE-2-2026-REV-2.1 Section 3.1.
Provides frozen, immutable Pydantic v2 models for workspace state, manifest scope
classification, raw component records, and graph topology metadata.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from scg_core.schemas.base import Ecosystem


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AnalysisCompleteness(str, Enum):
    """Qualitative completeness classification for a completed ingestion pass.

    Variants:
        FULL: All manifests present, lockfiles resolved, no anomalies detected.
        UNLOCKED_MANIFEST: Manifest present but corresponding lockfile absent; version
            ranges are specifiers, not pinned resolutions.
        PARTIAL_TIMEOUT: Clone or parsing exceeded the wall-clock budget; result is
            incomplete and should not drive automated remediations.
        UNRESOLVED_REFS: One or more bom-ref entries in the CycloneDX document could
            not be mapped to a concrete purl; graph topology may be incomplete.
        UNSUPPORTED_WORKSPACE_LAYOUT: Repository uses a monorepo/workspace layout that
            cannot be cleanly mapped to a single hoisted manifest graph.
    """

    FULL = "FULL"
    UNLOCKED_MANIFEST = "UNLOCKED_MANIFEST"
    PARTIAL_TIMEOUT = "PARTIAL_TIMEOUT"
    UNRESOLVED_REFS = "UNRESOLVED_REFS"
    UNSUPPORTED_WORKSPACE_LAYOUT = "UNSUPPORTED_WORKSPACE_LAYOUT"


# ---------------------------------------------------------------------------
# Core Ingestion Models
# ---------------------------------------------------------------------------


class ManifestDescriptor(BaseModel):
    """Describes a single discovered manifest file and its parsed dependency scopes.

    All dependency maps use the canonical package name as the key and the declared
    version specifier (range or pinned) as the value.  No environment resolution or
    network I/O is performed during construction; values are extracted statically from
    the manifest and/or lockfile.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ecosystem: Ecosystem = Field(
        ...,
        description="Target software ecosystem for this manifest.",
    )
    manifest_path: Path = Field(
        ...,
        description="Absolute path to the primary manifest file within the workspace.",
    )
    lockfile_path: Optional[Path] = Field(
        default=None,
        description="Absolute path to the resolved lockfile, or None if absent.",
    )
    is_locked: bool = Field(
        ...,
        description=(
            "True if a corresponding lockfile exists and was parsed; False indicates "
            "unlocked specifier-only resolution."
        ),
    )
    prod_dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Production runtime dependencies: {name: declared_specifier}.",
    )
    dev_dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Development/tooling dependencies not shipped in production builds.",
    )
    optional_dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional feature-gated dependencies (npm optionalDependencies).",
    )
    peer_dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Peer dependencies declared by the package (npm peerDependencies).",
    )


class ClonedWorkspace(BaseModel):
    """Immutable snapshot of a successfully cloned ephemeral repository workspace.

    Produced by GitWorkspaceManager.create_ephemeral_workspace and passed to
    downstream ingestion stages.  The workspace directory is guaranteed to exist for
    the duration of the enclosing context manager; callers MUST NOT retain references
    beyond that scope.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    scan_id: str = Field(
        ...,
        description="Universally unique scan job identifier (UUIDv4 string).",
    )
    workspace_path: Path = Field(
        ...,
        description="Absolute path to the ephemeral temporary workspace directory.",
    )
    commit_sha: str = Field(
        ...,
        pattern=r"^[0-9a-f]{40}$",
        description="Full 40-character lowercase hexadecimal SHA-1 HEAD commit hash.",
    )
    manifests: List[ManifestDescriptor] = Field(
        ...,
        description="Ordered list of all manifests discovered within the workspace.",
    )
    analysis_completeness: AnalysisCompleteness = Field(
        default=AnalysisCompleteness.FULL,
        description="Highest-severity completeness status across all discovered manifests.",
    )


# ---------------------------------------------------------------------------
# Graph Component Records
# ---------------------------------------------------------------------------


class RawComponentRecord(BaseModel):
    """Raw, unnormalized component record extracted from a CycloneDX SBOM document.

    Represents a single dependency node prior to graph compilation.  Fields are
    populated from CycloneDX ``components`` entries and cross-referenced dependency
    relationship arrays.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    purl: str = Field(
        ...,
        description="Package URL (PURL) identifier, e.g. pkg:npm/express@4.18.2.",
    )
    name: str = Field(
        ...,
        description="Canonical package name as published on the registry.",
    )
    version: str = Field(
        ...,
        description="Resolved pinned version string.",
    )
    ecosystem: Ecosystem = Field(
        ...,
        description="Software ecosystem to which this component belongs.",
    )
    direct: bool = Field(
        ...,
        description="True if this component is a direct dependency of the project root.",
    )
    declared_specifier: Optional[str] = Field(
        default=None,
        description="Raw version range or specifier from the manifest (e.g. ^4.0.0).",
    )
    resolved_integrity: Optional[str] = Field(
        default=None,
        description="Cryptographic integrity hash (sha512/sha256) from the lockfile.",
    )
    dependencies: List[str] = Field(
        default_factory=list,
        description="Ordered list of child PURL identifiers this component depends on.",
    )


# ---------------------------------------------------------------------------
# Graph Metadata Models
# ---------------------------------------------------------------------------


class EcosystemGraphMetadata(BaseModel):
    """Topology statistics for a single-ecosystem sub-graph.

    Computed after BFS depth resolution and bounded cycle sampling.  All counts
    exclude the synthetic root node pkg:scg/target-root@local.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_nodes: int = Field(
        ...,
        ge=0,
        description="Total number of component nodes (excluding the synthetic root).",
    )
    total_edges: int = Field(
        ...,
        ge=0,
        description="Total number of directed dependency edges in the sub-graph.",
    )
    direct_dependencies_count: int = Field(
        ...,
        ge=0,
        description="Number of nodes at depth=1 (direct dependencies of the root).",
    )
    transitive_dependencies_count: int = Field(
        ...,
        ge=0,
        description="Number of nodes at depth>=2 reachable from the root.",
    )
    orphaned_nodes_count: int = Field(
        ...,
        ge=0,
        description="Number of nodes unreachable from the root (depth=None).",
    )
    max_depth: int = Field(
        ...,
        ge=0,
        description="Maximum BFS shortest-path depth from root across all reachable nodes.",
    )
    has_cycles: bool = Field(
        ...,
        description="True if at least one directed cycle was detected (bounded sample).",
    )
    unresolved_refs: List[str] = Field(
        default_factory=list,
        description="bom-ref strings that could not be resolved to a concrete PURL.",
    )


class GraphMetadata(BaseModel):
    """Aggregate topology statistics for the composed multi-ecosystem dependency graph.

    Produced by DependencyGraphBuilder after all sub-graphs are composed under the
    unified synthetic super-root.  per_ecosystem maps each ecosystem value string
    (e.g. "npm", "pypi") to its individual EcosystemGraphMetadata.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_nodes: int = Field(
        ...,
        ge=0,
        description="Total component nodes across all ecosystems (excluding synthetic root).",
    )
    total_edges: int = Field(
        ...,
        ge=0,
        description="Total directed edges across the composed graph.",
    )
    direct_dependencies_count: int = Field(
        ...,
        ge=0,
        description="Total direct dependencies (depth=1) across all ecosystems.",
    )
    transitive_dependencies_count: int = Field(
        ...,
        ge=0,
        description="Total transitive dependencies (depth>=2) across all ecosystems.",
    )
    orphaned_nodes_count: int = Field(
        ...,
        ge=0,
        description="Total unreachable/orphaned nodes (depth=None) in the composed graph.",
    )
    max_depth: int = Field(
        ...,
        ge=0,
        description="Global maximum BFS depth across all ecosystems.",
    )
    has_cycles: bool = Field(
        ...,
        description="True if at least one directed cycle exists in the composed graph.",
    )
    cycle_samples: List[List[str]] = Field(
        default_factory=list,
        description=(
            "Up to 10 sample cycles (each a list of PURL strings forming the cycle). "
            "Bounded via itertools.islice to prevent exponential materialization (P2-05)."
        ),
    )
    unresolved_refs: List[str] = Field(
        default_factory=list,
        description="Aggregate list of bom-ref strings unresolvable across all ecosystems.",
    )
    per_ecosystem: Dict[str, EcosystemGraphMetadata] = Field(
        default_factory=dict,
        description="Per-ecosystem topology breakdown keyed by ecosystem value string.",
    )


# ---------------------------------------------------------------------------
# Self-Test  (INGEST module schema verification)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pathlib import Path as _Path
    from pydantic import ValidationError

    print("Executing verification harness for scg_core/schemas/ingestion.py ...")

    # --- TC-SCHEMA-01: AnalysisCompleteness enum round-trip ---
    for variant in AnalysisCompleteness:
        restored = AnalysisCompleteness(variant.value)
        assert restored is variant, f"Enum round-trip failed for {variant}"
    print("OK [1/6] AnalysisCompleteness: all variants round-trip via value.")

    # --- TC-SCHEMA-02: ManifestDescriptor (frozen, extra=forbid) ---
    md = ManifestDescriptor(
        ecosystem=Ecosystem.NPM,
        manifest_path=_Path("/tmp/test/package.json"),
        lockfile_path=_Path("/tmp/test/package-lock.json"),
        is_locked=True,
        prod_dependencies={"express": "^4.18.0"},
        dev_dependencies={"jest": "^29.0.0"},
        optional_dependencies={},
        peer_dependencies={"react": ">=18.0.0"},
    )
    assert md.ecosystem == Ecosystem.NPM
    assert md.is_locked is True
    try:
        md.is_locked = False  # type: ignore[misc]  -- must raise ValidationError (frozen_instance)
        raise AssertionError("ManifestDescriptor should be frozen/immutable")
    except ValidationError as exc:
        assert "frozen" in str(exc).lower(), f"Unexpected error message: {exc}"
    print("OK [2/6] ManifestDescriptor: constructed, fields verified, immutability enforced.")

    # --- TC-SCHEMA-03: ClonedWorkspace commit_sha pattern validation ---
    try:
        ClonedWorkspace(
            scan_id="scan-001",
            workspace_path=_Path("/tmp/ws"),
            commit_sha="INVALID_SHA",
            manifests=[md],
        )
        raise AssertionError("Should reject non-hex commit_sha")
    except ValidationError:
        pass

    valid_ws = ClonedWorkspace(
        scan_id="scan-001",
        workspace_path=_Path("/tmp/ws"),
        commit_sha="a" * 40,
        manifests=[md],
    )
    assert valid_ws.commit_sha == "a" * 40
    assert valid_ws.analysis_completeness == AnalysisCompleteness.FULL
    print("OK [3/6] ClonedWorkspace: SHA validation (reject invalid, accept 40-hex), default completeness=FULL.")

    # --- TC-SCHEMA-04: RawComponentRecord (frozen, extra=forbid) ---
    rcr = RawComponentRecord(
        purl="pkg:npm/express@4.18.2",
        name="express",
        version="4.18.2",
        ecosystem=Ecosystem.NPM,
        direct=True,
        declared_specifier="^4.18.0",
        resolved_integrity="sha512-abc123",
        dependencies=["pkg:npm/body-parser@1.20.1"],
    )
    assert rcr.direct is True
    assert len(rcr.dependencies) == 1
    try:
        rcr.name = "tampered"  # type: ignore[misc]  -- must raise ValidationError (frozen_instance)
        raise AssertionError("RawComponentRecord should be frozen")
    except ValidationError as exc:
        assert "frozen" in str(exc).lower(), f"Unexpected error message: {exc}"
    print("OK [4/6] RawComponentRecord: fields verified, immutability enforced.")

    # --- TC-SCHEMA-05: EcosystemGraphMetadata construction ---
    ego_meta = EcosystemGraphMetadata(
        total_nodes=10,
        total_edges=12,
        direct_dependencies_count=3,
        transitive_dependencies_count=6,
        orphaned_nodes_count=1,
        max_depth=4,
        has_cycles=False,
        unresolved_refs=["ref-ghost-001"],
    )
    assert ego_meta.orphaned_nodes_count == 1
    assert ego_meta.has_cycles is False
    print("OK [5/6] EcosystemGraphMetadata: constructed and field values verified.")

    # --- TC-SCHEMA-06: GraphMetadata with per_ecosystem and JSON round-trip ---
    gm = GraphMetadata(
        total_nodes=10,
        total_edges=12,
        direct_dependencies_count=3,
        transitive_dependencies_count=6,
        orphaned_nodes_count=1,
        max_depth=4,
        has_cycles=True,
        cycle_samples=[["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0", "pkg:npm/a@1.0.0"]],
        unresolved_refs=[],
        per_ecosystem={"npm": ego_meta},
    )
    assert gm.has_cycles is True
    assert len(gm.cycle_samples) == 1
    assert "npm" in gm.per_ecosystem
    restored_gm = GraphMetadata.model_validate_json(gm.model_dump_json())
    assert restored_gm == gm
    print("OK [6/6] GraphMetadata: per_ecosystem, cycle_samples, and JSON round-trip verified.")

    print("\nSUCCESS: scg_core/schemas/ingestion.py verified")
