"""Single-Pass BFS Dependency Graph Reachability Correlator & Exposure Resolver."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from scg_core.schemas.base import (
    Ecosystem,
    ReachabilityStatus,
    SeverityLevel,
    VulnerabilityRecord,
)
from scg_core.schemas.reachability import (
    FileScanStatus,
    ImportStatement,
    ParseConfidence,
    ReachabilityEvaluationResult,
    SourceFileScanResult,
    SourceTier,
)

logger = logging.getLogger(__name__)


class ReachabilityResolver:
    """Computes reachability status and exposure factors via single-pass BFS in O(V + E) time."""

    EXPOSURE_WEIGHTS: Dict[ReachabilityStatus, float] = {
        ReachabilityStatus.DIRECT_IMPORTED: 1.0,
        ReachabilityStatus.UNKNOWN_REACHABILITY: 0.6,
        ReachabilityStatus.TRANSITIVE_REQUIRED: 0.5,
        ReachabilityStatus.UNREFERENCED_LATENT: 0.2,
        ReachabilityStatus.DEV_DEPENDENCY: 0.1,
    }

    def evaluate_graph_reachability(
        self,
        graph: nx.DiGraph,
        scan_results: List[SourceFileScanResult],
        coverage: float,
        dev_packages: Set[str],
        vulnerabilities_map: Dict[str, List[VulnerabilityRecord]],
    ) -> Tuple[Dict[str, ReachabilityEvaluationResult], List[str]]:
        """Evaluate dependency reachability and compute deterministic exposure factors.

        Args:
            graph: Dependency directed graph (networkx.DiGraph).
            scan_results: Per-file AST scan results from ASTScanner.
            coverage: Repository AST analysis coverage ratio.
            dev_packages: Set of package names designated as dev dependencies in manifests.
            vulnerabilities_map: Mapping of node PURLs to list of VulnerabilityRecords.

        Returns:
            Tuple of evaluation results dictionary and list of analysis warning messages.
        """
        warnings: List[str] = []
        evaluation_results: Dict[str, ReachabilityEvaluationResult] = {}
        root_node = "pkg:scg/target-root@local"

        # Guard: Low analysis coverage triggers conservative UNKNOWN_REACHABILITY everywhere (P4-08)
        if coverage < 0.90:
            warnings.append(
                f"Coverage {coverage:.1%} below 90% threshold. Forcing UNKNOWN_REACHABILITY."
            )
            for node, data in graph.nodes(data=True):
                if node == root_node:
                    continue
                evaluation_results[node] = self._build_result(
                    node,
                    data,
                    ReachabilityStatus.UNKNOWN_REACHABILITY,
                    0.6,
                    [],
                    [],
                    False,
                )
            return evaluation_results, warnings

        # 1. Index imports across tiers
        app_imported_pkgs: Dict[str, List[str]] = {}
        test_imported_pkgs: Dict[str, List[str]] = {}
        resolved_invocations: Set[Tuple[str, str]] = set()
        evidence_call_sites: Dict[str, List[str]] = {}

        for scan in scan_results:
            for imp in scan.imports:
                pkg = imp.canonical_package.lower()
                if scan.tier == SourceTier.APPLICATION:
                    app_imported_pkgs.setdefault(pkg, []).append(
                        f"{scan.file_path}:{imp.line_number}"
                    )
                elif scan.tier == SourceTier.TEST:
                    test_imported_pkgs.setdefault(pkg, []).append(
                        f"{scan.file_path}:{imp.line_number}"
                    )

            for inv in scan.invocations:
                if inv.resolved_package and inv.resolved_symbol:
                    key = (inv.resolved_package.lower(), inv.resolved_symbol)
                    resolved_invocations.add(key)
                    evidence_call_sites.setdefault(
                        inv.resolved_package.lower(), []
                    ).append(
                        f"{scan.file_path}:{inv.line_number} -> {inv.full_expression}"
                    )

        # 2. Identify direct roots
        imported_direct_nodes: Set[str] = set()
        dev_direct_nodes: Set[str] = set()

        for node, data in graph.nodes(data=True):
            if node == root_node or not data.get("is_direct", False):
                continue
            pkg = data.get("name", "").lower()
            if pkg in app_imported_pkgs:
                imported_direct_nodes.add(node)
            elif pkg in dev_packages or pkg in test_imported_pkgs:
                dev_direct_nodes.add(node)

        # 3. Single-pass BFS closure computation using virtual super-sources (P4-01)
        reachable_from_prod: Set[str] = set()
        if imported_direct_nodes:
            super_prod = "__scg_virtual_prod_source__"
            graph.add_node(super_prod)
            graph.add_edges_from((super_prod, n) for n in imported_direct_nodes)
            reachable_from_prod = set(nx.descendants(graph, super_prod))
            graph.remove_node(super_prod)
            reachable_from_prod |= imported_direct_nodes

        dev_closure: Set[str] = set()
        if dev_direct_nodes:
            super_dev = "__scg_virtual_dev_source__"
            graph.add_node(super_dev)
            graph.add_edges_from((super_dev, n) for n in dev_direct_nodes)
            dev_closure = set(nx.descendants(graph, super_dev))
            graph.remove_node(super_dev)
            dev_closure |= dev_direct_nodes

        # Production reachability unconditionally overrides dev status (P4-02)
        dev_closure_only = dev_closure - reachable_from_prod

        # 4. Classify nodes using explicit decision procedure (P4-02)
        for node, data in graph.nodes(data=True):
            if node == root_node:
                continue

            pkg = data.get("name", "").lower()
            depth = data.get("depth")
            is_direct = data.get("is_direct", False)
            evidence: List[str] = []
            call_evidence = evidence_call_sites.get(pkg, [])

            if depth is None:
                status = ReachabilityStatus.UNREFERENCED_LATENT
            elif is_direct and node in imported_direct_nodes:
                status = ReachabilityStatus.DIRECT_IMPORTED
                evidence = app_imported_pkgs.get(pkg, [])
            elif node in reachable_from_prod:
                status = ReachabilityStatus.TRANSITIVE_REQUIRED
            elif node in dev_closure_only:
                status = ReachabilityStatus.DEV_DEPENDENCY
                evidence = test_imported_pkgs.get(pkg, [])
            else:
                status = ReachabilityStatus.UNREFERENCED_LATENT

            # Symbol confirmation via binding table (P4-05)
            vulns = vulnerabilities_map.get(node, [])
            symbol_confirmed = False
            for vuln in vulns:
                for sym in vuln.vulnerable_symbols:
                    if (pkg, sym) in resolved_invocations:
                        symbol_confirmed = True
                        break
                if symbol_confirmed:
                    break

            base_exposure = self.EXPOSURE_WEIGHTS[status]

            # Critical Vulnerability Floor Invariant: Max(exposure, 0.6) (P4-10)
            is_critical = any(
                v.severity == SeverityLevel.CRITICAL or v.is_known_exploited
                for v in vulns
            )
            effective_exposure = (
                max(base_exposure, 0.6) if is_critical else base_exposure
            )

            evaluation_results[node] = self._build_result(
                node,
                data,
                status,
                base_exposure,
                evidence,
                call_evidence,
                symbol_confirmed,
                effective_exposure,
            )

        return evaluation_results, warnings

    def _build_result(
        self,
        node: str,
        data: Dict,
        status: ReachabilityStatus,
        exposure: float,
        evidence: List[str],
        call_evidence: List[str],
        symbol_confirmed: bool,
        effective_exposure: Optional[float] = None,
    ) -> ReachabilityEvaluationResult:
        """Construct a validated ReachabilityEvaluationResult instance."""
        eco_str = data.get("ecosystem", "npm").lower()
        eco = Ecosystem.NPM if eco_str == "npm" else Ecosystem.PYPI
        return ReachabilityEvaluationResult(
            package_name=data.get("name", ""),
            ecosystem=eco,
            resolved_version=data.get("version", ""),
            graph_depth=data.get("depth"),
            reachability=status,
            exposure_factor=exposure,
            effective_exposure_factor=effective_exposure
            if effective_exposure is not None
            else exposure,
            symbol_confirmed_reachable=symbol_confirmed,
            evidence_files=evidence,
            evidence_call_sites=call_evidence,
        )


def test_reachability_5_tier_single_pass_bfs() -> None:
    """REACH-TC-01: Single-Pass Multi-Source BFS Resolution."""
    resolver = ReachabilityResolver()
    graph = nx.DiGraph()
    root = "pkg:scg/target-root@local"
    graph.add_node(root, depth=0)

    # Topology:
    # Root -> express (Direct, App Imported) -> body-parser (Transitive)
    # Root -> jest (Direct, Dev) -> diff-sequences (Dev Transitive)
    # Root -> unreferenced-helper (Direct, Latent)
    # Disconnected orphan (depth=None)
    nodes = [
        ("pkg:npm/express@4.18.2", "express", 1, True),
        ("pkg:npm/body-parser@1.20.1", "body-parser", 2, False),
        ("pkg:npm/jest@29.0.0", "jest", 1, True),
        ("pkg:npm/diff-sequences@29.0.0", "diff-sequences", 2, False),
        ("pkg:npm/unreferenced-helper@1.0.0", "unreferenced-helper", 1, True),
        ("pkg:npm/orphan-lib@1.0.0", "orphan-lib", None, False),
    ]
    for purl, name, depth, direct in nodes:
        graph.add_node(
            purl,
            name=name,
            version="1.0.0",
            depth=depth,
            is_direct=direct,
            ecosystem="npm",
        )

    graph.add_edge(root, "pkg:npm/express@4.18.2")
    graph.add_edge("pkg:npm/express@4.18.2", "pkg:npm/body-parser@1.20.1")
    graph.add_edge(root, "pkg:npm/jest@29.0.0")
    graph.add_edge("pkg:npm/jest@29.0.0", "pkg:npm/diff-sequences@29.0.0")
    graph.add_edge(root, "pkg:npm/unreferenced-helper@1.0.0")

    # App imports only express
    scan_results = [
        SourceFileScanResult(
            file_path="src/index.ts",
            tier=SourceTier.APPLICATION,
            ecosystem=Ecosystem.NPM,
            status=FileScanStatus.SCANNED,
            parse_confidence=ParseConfidence.HIGH,
            imports=[
                ImportStatement(
                    source_file="src/index.ts",
                    line_number=1,
                    raw_module="express",
                    canonical_package="express",
                )
            ],
        )
    ]

    res, warnings = resolver.evaluate_graph_reachability(
        graph=graph,
        scan_results=scan_results,
        coverage=1.0,
        dev_packages={"jest"},
        vulnerabilities_map={},
    )

    assert (
        res["pkg:npm/express@4.18.2"].reachability
        == ReachabilityStatus.DIRECT_IMPORTED
    )
    assert res["pkg:npm/express@4.18.2"].exposure_factor == 1.0
    assert (
        res["pkg:npm/body-parser@1.20.1"].reachability
        == ReachabilityStatus.TRANSITIVE_REQUIRED
    )
    assert res["pkg:npm/body-parser@1.20.1"].exposure_factor == 0.5
    assert (
        res["pkg:npm/jest@29.0.0"].reachability
        == ReachabilityStatus.DEV_DEPENDENCY
    )
    assert res["pkg:npm/jest@29.0.0"].exposure_factor == 0.1
    assert (
        res["pkg:npm/diff-sequences@29.0.0"].reachability
        == ReachabilityStatus.DEV_DEPENDENCY
    )
    assert res["pkg:npm/diff-sequences@29.0.0"].exposure_factor == 0.1
    assert (
        res["pkg:npm/unreferenced-helper@1.0.0"].reachability
        == ReachabilityStatus.UNREFERENCED_LATENT
    )
    assert res["pkg:npm/unreferenced-helper@1.0.0"].exposure_factor == 0.2
    assert (
        res["pkg:npm/orphan-lib@1.0.0"].reachability
        == ReachabilityStatus.UNREFERENCED_LATENT
    )


def test_critical_exposure_floor_and_pypi_mapping() -> None:
    """REACH-TC-02: Critical Floor Invariant & PyPI Distribution Mapping."""
    resolver = ReachabilityResolver()
    graph = nx.DiGraph()
    root = "pkg:scg/target-root@local"
    graph.add_node(root, depth=0)

    # PyYAML imported via `import yaml`
    purl_yaml = "pkg:pypi/pyyaml@5.4.1"
    graph.add_node(
        purl_yaml,
        name="pyyaml",
        version="5.4.1",
        depth=1,
        is_direct=True,
        ecosystem="pypi",
    )
    graph.add_edge(root, purl_yaml)

    # Latent dependency carrying a Critical CVE
    purl_latent = "pkg:pypi/unreferenced-lib@1.0.0"
    graph.add_node(
        purl_latent,
        name="unreferenced-lib",
        version="1.0.0",
        depth=1,
        is_direct=True,
        ecosystem="pypi",
    )
    graph.add_edge(root, purl_latent)

    crit_vuln = VulnerabilityRecord(
        id="CVE-2024-9999",
        summary="Remote Code Execution",
        cvss_score=9.8,
        severity=SeverityLevel.CRITICAL,
    )

    scan_results = [
        SourceFileScanResult(
            file_path="main.py",
            tier=SourceTier.APPLICATION,
            ecosystem=Ecosystem.PYPI,
            status=FileScanStatus.SCANNED,
            parse_confidence=ParseConfidence.HIGH,
            imports=[
                ImportStatement(
                    source_file="main.py",
                    line_number=1,
                    raw_module="yaml",
                    canonical_package="pyyaml",
                )
            ],
        )
    ]

    res, _ = resolver.evaluate_graph_reachability(
        graph=graph,
        scan_results=scan_results,
        coverage=1.0,
        dev_packages=set(),
        vulnerabilities_map={purl_latent: [crit_vuln]},
    )

    # pyyaml is mapped from yaml and classified DIRECT_IMPORTED
    assert res[purl_yaml].reachability == ReachabilityStatus.DIRECT_IMPORTED
    assert res[purl_yaml].exposure_factor == 1.0

    # unreferenced-lib is UNREFERENCED_LATENT (base exposure 0.2), but floored to 0.6 due to CRITICAL severity
    assert (
        res[purl_latent].reachability == ReachabilityStatus.UNREFERENCED_LATENT
    )
    assert res[purl_latent].exposure_factor == 0.2
    assert res[purl_latent].effective_exposure_factor == 0.6


if __name__ == "__main__":
    test_reachability_5_tier_single_pass_bfs()
    test_critical_exposure_floor_and_pypi_mapping()
    print("SUCCESS")
