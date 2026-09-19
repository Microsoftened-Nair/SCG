"""Deterministic mock fixture generator for Supply Chain Guardian (SCG).

Produces schema-compliant test fixtures for downstream pipeline tracks:
1. tests/fixtures/mock_graph.json (NetworkX node-link dependency topology)
2. tests/fixtures/mock_enrichment.json (Vulnerabilities and package health data)
3. tests/fixtures/mock_reachability.json (Static AST reachability classifications)
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure repository root is in sys.path for direct script execution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from scg_core.schemas.base import (
    AwareUTC,
    CvssSource,
    Ecosystem,
    PackageHealthData,
    ReachabilityStatus,
    SeverityLevel,
    SignalSource,
    VulnerabilityRecord,
)

FIXTURES_DIR = Path(__file__).resolve().parent


class EnrichmentBundle(BaseModel):
    """Enrichment bundle containing vulnerability and health data for a package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    purl: str = Field(..., description="Canonical package URL.")
    vulnerabilities: List[VulnerabilityRecord] = Field(
        default_factory=list,
        description="List of security advisories affecting the package.",
    )
    health: PackageHealthData = Field(
        ...,
        description="Health, activity, and maintenance metrics.",
    )


class ReachabilityRecord(BaseModel):
    """Reachability evaluation resolution for a dependency."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    purl: str = Field(..., description="Canonical package URL.")
    reachability: ReachabilityStatus = Field(
        ...,
        description="AST reachability classification.",
    )
    exposure_factor: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Exposure weight factor between 0.0 and 1.0.",
    )
    symbol_confirmed_reachable: bool = Field(
        default=False,
        description="True if vulnerable symbol is confirmed called in AST traversal.",
    )
    call_sites: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Source code references and call sites.",
    )


def generate_mock_graph() -> Dict[str, Any]:
    """Generates the NetworkX node-link representation of the dependency graph.

    Returns:
        Dictionary conforming to NetworkX node-link format.
    """
    g = nx.DiGraph()

    # Node definitions
    nodes = [
        {
            "id": "pkg:scg/target-app@1.0.0",
            "name": "target-app",
            "version": "1.0.0",
            "ecosystem": "npm",
            "is_direct": False,
            "depth": 0,
            "scope": "PROD",
        },
        {
            "id": "pkg:npm/express@4.18.2",
            "name": "express",
            "version": "4.18.2",
            "ecosystem": "npm",
            "is_direct": True,
            "depth": 1,
            "scope": "PROD",
        },
        {
            "id": "pkg:npm/lodash@4.17.20",
            "name": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm",
            "is_direct": True,
            "depth": 1,
            "scope": "PROD",
        },
        {
            "id": "pkg:npm/body-parser@1.20.1",
            "name": "body-parser",
            "version": "1.20.1",
            "ecosystem": "npm",
            "is_direct": True,
            "depth": 1,
            "scope": "PROD",
        },
        {
            "id": "pkg:npm/debug@2.6.9",
            "name": "debug",
            "version": "2.6.9",
            "ecosystem": "npm",
            "is_direct": False,
            "depth": 2,
            "scope": "PROD",
        },
        {
            "id": "pkg:npm/jest@29.7.0",
            "name": "jest",
            "version": "29.7.0",
            "ecosystem": "npm",
            "is_direct": True,
            "depth": 1,
            "scope": "DEV",
        },
        {
            "id": "pkg:npm/pretty-format@29.7.0",
            "name": "pretty-format",
            "version": "29.7.0",
            "ecosystem": "npm",
            "is_direct": False,
            "depth": 2,
            "scope": "DEV",
        },
        {
            "id": "pkg:npm/isolated-leaf@1.0.0",
            "name": "isolated-leaf",
            "version": "1.0.0",
            "ecosystem": "npm",
            "is_direct": False,
            "depth": None,
            "scope": "PROD",
        },
    ]

    for node in nodes:
        g.add_node(node["id"], **node)

    # Edge definitions
    edges = [
        ("pkg:scg/target-app@1.0.0", "pkg:npm/express@4.18.2"),
        ("pkg:scg/target-app@1.0.0", "pkg:npm/lodash@4.17.20"),
        ("pkg:scg/target-app@1.0.0", "pkg:npm/body-parser@1.20.1"),
        ("pkg:npm/express@4.18.2", "pkg:npm/body-parser@1.20.1"),
        ("pkg:npm/body-parser@1.20.1", "pkg:npm/debug@2.6.9"),
        ("pkg:scg/target-app@1.0.0", "pkg:npm/jest@29.7.0"),
        ("pkg:npm/jest@29.7.0", "pkg:npm/pretty-format@29.7.0"),
    ]

    for src, dst in edges:
        g.add_edge(src, dst)

    return nx.node_link_data(g)


def generate_mock_enrichment() -> Dict[str, Dict[str, Any]]:
    """Generates the enrichment bundle mapping purls to vulnerability and health metrics.

    Returns:
        Dictionary mapping canonical purl strings to serialized EnrichmentBundle dicts.
    """
    bundles: Dict[str, EnrichmentBundle] = {}

    # 1. pkg:npm/lodash@4.17.20
    lodash_vuln = VulnerabilityRecord(
        id="GHSA-p6mc-m468-83gw",
        aliases=["CVE-2020-28500"],
        summary="Prototype Pollution in lodash",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_source=CvssSource.PUBLISHED_VECTOR,
        severity=SeverityLevel.HIGH,
        epss_score=0.45,
        epss_percentile=0.95,
        is_known_exploited=False,
        published=datetime(2020, 10, 27, 0, 0, 0, tzinfo=timezone.utc),
        withdrawn=None,
        fixed_versions=["4.17.21"],
        vulnerable_version_ranges=["< 4.17.21"],
        vulnerable_symbols=["template"],
    )
    lodash_health = PackageHealthData(
        published_date=datetime(2020, 8, 13, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2021, 2, 20, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=None,
        weekly_downloads=45000000,
        has_install_scripts=False,
        openssf_scorecard_score=6.2,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.ABSENT,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/lodash@4.17.20"] = EnrichmentBundle(
        purl="pkg:npm/lodash@4.17.20",
        vulnerabilities=[lodash_vuln],
        health=lodash_health,
    )

    # 2. pkg:npm/express@4.18.2
    express_health = PackageHealthData(
        published_date=datetime(2022, 10, 8, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=3,
        weekly_downloads=30000000,
        has_install_scripts=False,
        openssf_scorecard_score=8.1,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/express@4.18.2"] = EnrichmentBundle(
        purl="pkg:npm/express@4.18.2",
        vulnerabilities=[],
        health=express_health,
    )

    # 3. pkg:npm/body-parser@1.20.1
    body_parser_health = PackageHealthData(
        published_date=datetime(2022, 10, 5, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2022, 10, 5, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=2,
        weekly_downloads=25000000,
        has_install_scripts=False,
        openssf_scorecard_score=7.8,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/body-parser@1.20.1"] = EnrichmentBundle(
        purl="pkg:npm/body-parser@1.20.1",
        vulnerabilities=[],
        health=body_parser_health,
    )

    # 4. pkg:npm/debug@2.6.9
    debug_health = PackageHealthData(
        published_date=datetime(2017, 9, 22, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2017, 9, 22, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=2,
        weekly_downloads=100000000,
        has_install_scripts=False,
        openssf_scorecard_score=5.5,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/debug@2.6.9"] = EnrichmentBundle(
        purl="pkg:npm/debug@2.6.9",
        vulnerabilities=[],
        health=debug_health,
    )

    # 5. pkg:npm/jest@29.7.0
    jest_health = PackageHealthData(
        published_date=datetime(2023, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2023, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=8,
        weekly_downloads=22000000,
        has_install_scripts=False,
        openssf_scorecard_score=8.9,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/jest@29.7.0"] = EnrichmentBundle(
        purl="pkg:npm/jest@29.7.0",
        vulnerabilities=[],
        health=jest_health,
    )

    # 6. pkg:npm/pretty-format@29.7.0
    pretty_format_health = PackageHealthData(
        published_date=datetime(2023, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2023, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=8,
        weekly_downloads=20000000,
        has_install_scripts=False,
        openssf_scorecard_score=8.7,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.OPENSSF_SCORECARD,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/pretty-format@29.7.0"] = EnrichmentBundle(
        purl="pkg:npm/pretty-format@29.7.0",
        vulnerabilities=[],
        health=pretty_format_health,
    )

    # 7. pkg:npm/isolated-leaf@1.0.0
    isolated_leaf_health = PackageHealthData(
        published_date=datetime(2021, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2021, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
        maintainer_count=1,
        weekly_downloads=120,
        has_install_scripts=False,
        openssf_scorecard_score=None,
        is_deprecated=False,
        signal_sources={
            "weekly_downloads": SignalSource.REGISTRY_API,
            "maintainer_count": SignalSource.REGISTRY_API,
            "openssf_scorecard_score": SignalSource.UNAVAILABLE_404,
            "has_install_scripts": SignalSource.REGISTRY_API,
            "published_date": SignalSource.REGISTRY_API,
            "last_registry_activity": SignalSource.REGISTRY_API,
        },
    )
    bundles["pkg:npm/isolated-leaf@1.0.0"] = EnrichmentBundle(
        purl="pkg:npm/isolated-leaf@1.0.0",
        vulnerabilities=[],
        health=isolated_leaf_health,
    )

    return {purl: bundle.model_dump(mode="json") for purl, bundle in bundles.items()}


def generate_mock_reachability() -> Dict[str, Dict[str, Any]]:
    """Generates the reachability resolution mapping for all dependencies.

    Returns:
        Dictionary mapping canonical purl strings to serialized ReachabilityRecord dicts.
    """
    records: Dict[str, ReachabilityRecord] = {
        "pkg:npm/express@4.18.2": ReachabilityRecord(
            purl="pkg:npm/express@4.18.2",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            exposure_factor=1.0,
            symbol_confirmed_reachable=False,
            call_sites=[{"file": "src/app.js", "line": 5, "symbol": "express"}],
        ),
        "pkg:npm/lodash@4.17.20": ReachabilityRecord(
            purl="pkg:npm/lodash@4.17.20",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            exposure_factor=1.0,
            symbol_confirmed_reachable=True,
            call_sites=[{"file": "src/app.js", "line": 42, "symbol": "template"}],
        ),
        "pkg:npm/body-parser@1.20.1": ReachabilityRecord(
            purl="pkg:npm/body-parser@1.20.1",
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            exposure_factor=0.8,
            symbol_confirmed_reachable=False,
            call_sites=[{"file": "src/app.js", "line": 8, "symbol": "json"}],
        ),
        "pkg:npm/debug@2.6.9": ReachabilityRecord(
            purl="pkg:npm/debug@2.6.9",
            reachability=ReachabilityStatus.TRANSITIVE_REQUIRED,
            exposure_factor=0.5,
            symbol_confirmed_reachable=False,
            call_sites=[],
        ),
        "pkg:npm/jest@29.7.0": ReachabilityRecord(
            purl="pkg:npm/jest@29.7.0",
            reachability=ReachabilityStatus.DEV_DEPENDENCY,
            exposure_factor=0.1,
            symbol_confirmed_reachable=False,
            call_sites=[],
        ),
        "pkg:npm/pretty-format@29.7.0": ReachabilityRecord(
            purl="pkg:npm/pretty-format@29.7.0",
            reachability=ReachabilityStatus.DEV_DEPENDENCY,
            exposure_factor=0.1,
            symbol_confirmed_reachable=False,
            call_sites=[],
        ),
        "pkg:npm/isolated-leaf@1.0.0": ReachabilityRecord(
            purl="pkg:npm/isolated-leaf@1.0.0",
            reachability=ReachabilityStatus.UNREFERENCED_LATENT,
            exposure_factor=0.2,
            symbol_confirmed_reachable=False,
            call_sites=[],
        ),
    }

    return {purl: record.model_dump(mode="json") for purl, record in records.items()}


def write_fixtures(fixtures_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Writes the three mock fixture JSON files to the target directory.

    Args:
        fixtures_dir: Target directory path. Defaults to tests/fixtures/.

    Returns:
        Mapping of fixture names to their destination file paths.
    """
    target_dir = fixtures_dir if fixtures_dir is not None else FIXTURES_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, Path] = {
        "graph": target_dir / "mock_graph.json",
        "enrichment": target_dir / "mock_enrichment.json",
        "reachability": target_dir / "mock_reachability.json",
    }

    # Generate payloads
    graph_data = generate_mock_graph()
    enrichment_data = generate_mock_enrichment()
    reachability_data = generate_mock_reachability()

    # Write files with UTF-8 encoding and 2-space indentation
    paths["graph"].write_text(json.dumps(graph_data, indent=2), encoding="utf-8")
    paths["enrichment"].write_text(json.dumps(enrichment_data, indent=2), encoding="utf-8")
    paths["reachability"].write_text(json.dumps(reachability_data, indent=2), encoding="utf-8")

    return paths


if __name__ == "__main__":
    print("Generating universal mock fixtures for Supply Chain Guardian...")
    generated_paths = write_fixtures()

    # 1. Assert files exist
    for name, path in generated_paths.items():
        assert path.is_file(), f"Expected fixture file {path} was not created"
        assert path.stat().st_size > 0, f"Fixture file {path} is empty"
    print("✓ [1/4] All 3 fixture files generated and non-empty.")

    # 2. Validate mock_graph.json
    with generated_paths["graph"].open("r", encoding="utf-8") as f:
        graph_raw = json.load(f)
    g_restored = nx.node_link_graph(graph_raw)
    assert len(g_restored.nodes) == 8, f"Expected 8 nodes in graph, found {len(g_restored.nodes)}"
    assert len(g_restored.edges) == 7, f"Expected 7 edges in graph, found {len(g_restored.edges)}"

    # Validate raw node dictionaries
    for node_entry in graph_raw["nodes"]:
        assert "id" in node_entry, f"Node entry missing 'id': {node_entry}"
        assert "name" in node_entry, f"Node {node_entry['id']} missing 'name'"
        assert "version" in node_entry, f"Node {node_entry['id']} missing 'version'"
        assert "ecosystem" in node_entry, f"Node {node_entry['id']} missing 'ecosystem'"
        assert "is_direct" in node_entry, f"Node {node_entry['id']} missing 'is_direct'"
        assert "depth" in node_entry, f"Node {node_entry['id']} missing 'depth'"
        assert "scope" in node_entry, f"Node {node_entry['id']} missing 'scope'"

    # Validate reconstructed NetworkX graph attributes
    for node_id, data in g_restored.nodes(data=True):
        assert node_id, "Node ID must be non-empty"
        assert "name" in data, f"Node {node_id} missing 'name'"
        assert "version" in data, f"Node {node_id} missing 'version'"
        assert "ecosystem" in data, f"Node {node_id} missing 'ecosystem'"
        assert "is_direct" in data, f"Node {node_id} missing 'is_direct'"
        assert "depth" in data, f"Node {node_id} missing 'depth'"
        assert "scope" in data, f"Node {node_id} missing 'scope'"

    # Validate isolated-leaf has depth=None and degree=0
    assert g_restored.nodes["pkg:npm/isolated-leaf@1.0.0"]["depth"] is None
    assert g_restored.degree["pkg:npm/isolated-leaf@1.0.0"] == 0
    print("✓ [2/4] mock_graph.json verified with NetworkX node-link round-trip.")

    # 3. Validate mock_enrichment.json
    with generated_paths["enrichment"].open("r", encoding="utf-8") as f:
        enrichment_raw = json.load(f)

    assert len(enrichment_raw) == 7, f"Expected 7 enrichment entries, found {len(enrichment_raw)}"
    for purl, bundle_dict in enrichment_raw.items():
        # Validate Pydantic deserialization
        bundle = EnrichmentBundle.model_validate(bundle_dict)
        assert bundle.purl == purl
        # Verify timezone awareness on dates
        assert bundle.health.published_date.tzinfo is not None
        assert bundle.health.last_registry_activity.tzinfo is not None

    # Validate specific requirements for lodash
    lodash = EnrichmentBundle.model_validate(enrichment_raw["pkg:npm/lodash@4.17.20"])
    assert len(lodash.vulnerabilities) == 1
    assert lodash.vulnerabilities[0].id == "GHSA-p6mc-m468-83gw"
    assert lodash.vulnerabilities[0].cvss_score == 7.5
    assert lodash.vulnerabilities[0].cvss_source == CvssSource.PUBLISHED_VECTOR
    assert lodash.vulnerabilities[0].severity == SeverityLevel.HIGH
    assert lodash.vulnerabilities[0].fixed_versions == ["4.17.21"]
    assert lodash.vulnerabilities[0].vulnerable_symbols == ["template"]
    assert lodash.health.maintainer_count is None
    assert lodash.health.weekly_downloads == 45000000
    assert lodash.health.openssf_scorecard_score == 6.2

    # Validate express clean
    express = EnrichmentBundle.model_validate(enrichment_raw["pkg:npm/express@4.18.2"])
    assert len(express.vulnerabilities) == 0
    assert express.health.openssf_scorecard_score == 8.1

    # Validate isolated-leaf scorecard=None and UNAVAILABLE_404
    isolated = EnrichmentBundle.model_validate(enrichment_raw["pkg:npm/isolated-leaf@1.0.0"])
    assert isolated.health.openssf_scorecard_score is None
    assert isolated.health.signal_sources["openssf_scorecard_score"] == SignalSource.UNAVAILABLE_404
    print("✓ [3/4] mock_enrichment.json successfully deserialized into Pydantic models.")

    # 4. Validate mock_reachability.json
    with generated_paths["reachability"].open("r", encoding="utf-8") as f:
        reachability_raw = json.load(f)

    assert len(reachability_raw) == 7, f"Expected 7 reachability entries, found {len(reachability_raw)}"
    for purl, record_dict in reachability_raw.items():
        record = ReachabilityRecord.model_validate(record_dict)
        assert record.purl == purl

    # Check specific reachability requirements
    assert reachability_raw["pkg:npm/express@4.18.2"]["reachability"] == ReachabilityStatus.DIRECT_IMPORTED
    assert reachability_raw["pkg:npm/express@4.18.2"]["exposure_factor"] == 1.0

    assert reachability_raw["pkg:npm/lodash@4.17.20"]["reachability"] == ReachabilityStatus.DIRECT_IMPORTED
    assert reachability_raw["pkg:npm/lodash@4.17.20"]["exposure_factor"] == 1.0
    assert reachability_raw["pkg:npm/lodash@4.17.20"]["symbol_confirmed_reachable"] is True

    assert reachability_raw["pkg:npm/debug@2.6.9"]["reachability"] == ReachabilityStatus.TRANSITIVE_REQUIRED
    assert reachability_raw["pkg:npm/debug@2.6.9"]["exposure_factor"] == 0.5

    assert reachability_raw["pkg:npm/jest@29.7.0"]["reachability"] == ReachabilityStatus.DEV_DEPENDENCY
    assert reachability_raw["pkg:npm/jest@29.7.0"]["exposure_factor"] == 0.1

    assert reachability_raw["pkg:npm/isolated-leaf@1.0.0"]["reachability"] == ReachabilityStatus.UNREFERENCED_LATENT
    assert reachability_raw["pkg:npm/isolated-leaf@1.0.0"]["exposure_factor"] == 0.2
    print("✓ [4/4] mock_reachability.json verified with ReachabilityRecord schema.")

    print("\nSCG-FOUNDATION-MOCKS-01 VALIDATION: SUCCESS")
