"""In-memory NetworkX directed dependency graph compiler for Supply Chain Guardian (SCG).

Conforms to SCG-SRS-PHASE-2-2026-REV-2.1 Section 3.4 (COMPONENT-1.3.1).

Topology invariants enforced:
    P2-04: Never assumes bom-ref == purl. Builds an explicit ref_to_purl lookup from
           the components catalog. Unknown refs are logged to unresolved_refs; no
           phantom nodes are created.
    P2-05: Cycle detection uses itertools.islice(nx.simple_cycles(graph), 10).
           Unbounded enumeration of simple cycles is strictly prohibited.
    P2-06: BFS depth calculated via nx.single_source_shortest_path_length (O(V+E)).
           Unreachable / orphaned nodes receive depth=None; the sentinel 999 is
           strictly forbidden.
    P2-07: Multi-ecosystem graphs composed under a unified synthetic super-root via
           compose_graphs(); depths are recalculated across the composed topology.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.ingestion import (
    EcosystemGraphMetadata,
    GraphMetadata,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GraphConstructionError(Exception):
    """Raised when dependency graph assembly fails due to a structural invariant violation."""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class DependencyGraphBuilder:
    """Builds in-memory directed dependency graphs from CycloneDX 1.5 documents.

    Single-ecosystem graphs are produced by :meth:`build_graph`.  Multi-ecosystem
    repositories can be combined into a single composed graph via
    :meth:`compose_graphs`, which stitches per-ecosystem sub-graphs under a unified
    synthetic super-root and recalculates BFS depths.

    Synthetic root node identifier:
        ``pkg:scg/target-root@local``
    """

    ROOT_NODE: str = "pkg:scg/target-root@local"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_graph(
        self,
        cyclonedx_bom: Dict[str, Any],
        ecosystem: Ecosystem,
    ) -> Tuple[nx.DiGraph, GraphMetadata]:
        """Compile a directed dependency graph from a CycloneDX 1.5 document.

        Steps:
            1. Initialise a ``nx.DiGraph`` with the synthetic root node at depth 0.
            2. Build an explicit ``bom-ref -> purl`` lookup from the components array
               (P2-04).  Non-purl bom-ref strings (e.g. UUIDs) are resolved via the
               ``purl`` field; bare names are normalised to
               ``pkg:<ecosystem>/<name>@<version>``.
            3. Construct directed edges from the dependencies array; skip unresolvable
               parent or child references and record them in ``unresolved_refs``.
            4. Remove any node that has no entry in the components catalog (phantom
               prevention).
            5. Populate node attributes: ``name``, ``version``, ``ecosystem``,
               ``is_direct``, ``scope``.
            6. Compute BFS shortest-path distance from ROOT_NODE (O(V+E)).  Assign
               ``depth=None`` to orphaned / unreachable nodes (P2-06).
            7. Sample up to 10 directed cycles via
               ``itertools.islice(nx.simple_cycles(...), 10)`` (P2-05).
            8. Return ``(graph, GraphMetadata)`` with accurate per-ecosystem stats.

        Args:
            cyclonedx_bom: Parsed CycloneDX 1.5 JSON document.
            ecosystem: Ecosystem context for node attribute population and purl fallback.

        Returns:
            A 2-tuple of the constructed ``nx.DiGraph`` and the corresponding
            ``GraphMetadata``.

        Raises:
            GraphConstructionError: Reserved for structural violations detected during
                graph assembly.
        """
        graph: nx.DiGraph = nx.DiGraph()

        # Step 1 -- synthetic root node
        graph.add_node(
            self.ROOT_NODE,
            name="target-root",
            version="local",
            ecosystem=ecosystem.value,
            depth=0,
        )

        # Locate root bom-ref from metadata (may be a UUID or purl)
        root_bom_ref: str = (
            cyclonedx_bom.get("metadata", {})
            .get("component", {})
            .get("bom-ref", self.ROOT_NODE)
        )

        components: List[Dict[str, Any]] = cyclonedx_bom.get("components", [])
        dependencies: List[Dict[str, Any]] = cyclonedx_bom.get("dependencies", [])

        # Step 2 -- build explicit bom-ref -> purl map (P2-04)
        ref_to_purl: Dict[str, str] = {}
        metadata_map: Dict[str, Dict[str, Any]] = {}

        for comp in components:
            ref: Optional[str] = comp.get("bom-ref")
            purl: Optional[str] = comp.get("purl")

            if not ref:
                continue

            # Normalise purl: use declared purl field; fall back to constructing one
            if not purl:
                name_raw = comp.get("name", "")
                ver_raw = comp.get("version", "")
                purl = (
                    ref
                    if ref.startswith("pkg:")
                    else f"pkg:{ecosystem.value}/{name_raw}@{ver_raw}"
                )

            ref_to_purl[ref] = purl
            metadata_map[purl] = {
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "ecosystem": ecosystem.value,
                "scope": comp.get("scope", "required"),
            }

        # Map the root bom-ref to the synthetic ROOT_NODE
        ref_to_purl[root_bom_ref] = self.ROOT_NODE

        unresolved_refs: List[str] = []

        def _resolve(ref_str: str) -> Optional[str]:
            """Translate a bom-ref to a purl; record unresolvable refs."""
            resolved = ref_to_purl.get(ref_str)
            if resolved is None:
                unresolved_refs.append(ref_str)
            return resolved

        # Step 3 -- construct directed edges
        direct_purls: Set[str] = set()

        for rel in dependencies:
            parent_purl = _resolve(rel.get("ref", ""))
            if not parent_purl:
                continue

            for child_ref in rel.get("dependsOn", []):
                child_purl = _resolve(child_ref)
                if not child_purl:
                    continue

                if parent_purl == self.ROOT_NODE:
                    graph.add_edge(self.ROOT_NODE, child_purl)
                    direct_purls.add(child_purl)
                else:
                    graph.add_edge(parent_purl, child_purl)

        # Step 4 -- remove phantom nodes not in the components catalog
        for node in list(graph.nodes()):
            if node == self.ROOT_NODE:
                continue
            if node not in metadata_map:
                graph.remove_node(node)

        # Step 5 -- populate node attributes for declared components
        for node in list(graph.nodes()):
            if node == self.ROOT_NODE:
                continue
            meta = metadata_map.get(node)
            if meta is None:
                # Node was removed in step 4; skip (already gone)
                continue
            graph.nodes[node]["name"] = meta["name"]
            graph.nodes[node]["version"] = meta["version"]
            graph.nodes[node]["ecosystem"] = ecosystem.value
            graph.nodes[node]["is_direct"] = node in direct_purls
            graph.nodes[node]["scope"] = meta.get("scope", "required")

        # Also add component nodes that have no dependency edges at all
        # (declared but completely disconnected -- orphaned by design)
        for purl, meta in metadata_map.items():
            if purl not in graph:
                graph.add_node(
                    purl,
                    name=meta["name"],
                    version=meta["version"],
                    ecosystem=ecosystem.value,
                    is_direct=purl in direct_purls,
                    scope=meta.get("scope", "required"),
                )

        # Step 6 -- BFS depth from ROOT_NODE (P2-06)
        depth_map: Dict[str, int] = nx.single_source_shortest_path_length(
            graph, self.ROOT_NODE
        )

        orphaned_count: int = 0
        max_depth: int = 0

        for node in graph.nodes():
            if node == self.ROOT_NODE:
                continue
            d = depth_map.get(node)  # None if unreachable
            graph.nodes[node]["depth"] = d  # depth=None for orphans; never 999 (P2-06)
            if d is None:
                orphaned_count += 1
            elif d > max_depth:
                max_depth = d

        # Step 7 -- bounded cycle sampling (P2-05)
        cycle_samples: List[List[str]] = list(
            itertools.islice(nx.simple_cycles(graph), 10)
        )
        has_cycles: bool = len(cycle_samples) > 0

        # Step 8 -- build metadata
        total_non_root_nodes: int = graph.number_of_nodes() - 1
        transitive_count: int = max(
            0, total_non_root_nodes - len(direct_purls) - orphaned_count
        )

        deduplicated_unresolved: List[str] = list(dict.fromkeys(unresolved_refs))

        eco_meta = EcosystemGraphMetadata(
            total_nodes=total_non_root_nodes,
            total_edges=graph.number_of_edges(),
            direct_dependencies_count=len(direct_purls),
            transitive_dependencies_count=transitive_count,
            orphaned_nodes_count=orphaned_count,
            max_depth=max_depth,
            has_cycles=has_cycles,
            unresolved_refs=deduplicated_unresolved,
        )

        metadata = GraphMetadata(
            total_nodes=eco_meta.total_nodes,
            total_edges=eco_meta.total_edges,
            direct_dependencies_count=eco_meta.direct_dependencies_count,
            transitive_dependencies_count=eco_meta.transitive_dependencies_count,
            orphaned_nodes_count=eco_meta.orphaned_nodes_count,
            max_depth=eco_meta.max_depth,
            has_cycles=has_cycles,
            cycle_samples=cycle_samples,
            unresolved_refs=deduplicated_unresolved,
            per_ecosystem={ecosystem.value: eco_meta},
        )

        return graph, metadata

    @classmethod
    def compose_graphs(
        cls,
        graphs: Dict[Ecosystem, nx.DiGraph],
    ) -> Tuple[nx.DiGraph, GraphMetadata]:
        """Compose multiple ecosystem sub-graphs under the unified synthetic super-root.

        Each ecosystem's direct dependencies retain ``depth=1`` relative to
        ``ROOT_NODE`` after composition.  BFS depths and cycle samples are recalculated
        across the entire composed topology (P2-07).

        Per-ecosystem statistics preserved from each individual sub-graph are merged
        into the ``per_ecosystem`` field of the returned ``GraphMetadata``.

        Args:
            graphs: Mapping of ecosystem to its ``nx.DiGraph`` (as returned by
                :meth:`build_graph`).

        Returns:
            A 2-tuple ``(composed_graph, GraphMetadata)`` for the unified graph.

        Raises:
            GraphConstructionError: If ``graphs`` is empty.
        """
        if not graphs:
            raise GraphConstructionError(
                "compose_graphs requires at least one ecosystem sub-graph."
            )

        composed: nx.DiGraph = nx.DiGraph()
        composed.add_node(
            cls.ROOT_NODE, name="target-root", version="local", depth=0
        )

        per_eco: Dict[str, EcosystemGraphMetadata] = {}

        for eco, sub_g in graphs.items():
            # Merge all non-root nodes
            for node, data in sub_g.nodes(data=True):
                if node == cls.ROOT_NODE:
                    continue
                composed.add_node(node, **data)

            # Merge all edges
            for u, v in sub_g.edges():
                composed.add_edge(u, v)

        # Recalculate BFS depths across the full composed graph (P2-06)
        depth_map: Dict[str, int] = nx.single_source_shortest_path_length(
            composed, cls.ROOT_NODE
        )

        total_direct: int = 0
        total_orphans: int = 0
        global_max_depth: int = 0

        for node in composed.nodes():
            if node == cls.ROOT_NODE:
                continue
            d = depth_map.get(node)
            composed.nodes[node]["depth"] = d  # None for orphans; never 999 (P2-06)
            if d is None:
                total_orphans += 1
            else:
                if d > global_max_depth:
                    global_max_depth = d
            if composed.nodes[node].get("is_direct", False):
                total_direct += 1

        total_nodes: int = composed.number_of_nodes() - 1
        total_edges: int = composed.number_of_edges()
        total_transitive: int = max(0, total_nodes - total_direct - total_orphans)

        # Bounded cycle sampling across the composed graph (P2-05)
        cycle_samples: List[List[str]] = list(
            itertools.islice(nx.simple_cycles(composed), 10)
        )

        # Build per_ecosystem from the individual sub-graph metadata (re-read
        # stats from the composed node set for accuracy post-merge)
        for eco, sub_g in graphs.items():
            eco_direct = sum(
                1
                for n in sub_g.nodes()
                if n != cls.ROOT_NODE and sub_g.nodes[n].get("is_direct", False)
            )
            eco_nodes = sub_g.number_of_nodes() - 1
            eco_edges = sub_g.number_of_edges()
            eco_orphans = sum(
                1
                for n in sub_g.nodes()
                if n != cls.ROOT_NODE and sub_g.nodes[n].get("depth") is None
            )
            eco_max_d = max(
                (
                    sub_g.nodes[n].get("depth") or 0
                    for n in sub_g.nodes()
                    if n != cls.ROOT_NODE and sub_g.nodes[n].get("depth") is not None
                ),
                default=0,
            )
            eco_transitive = max(0, eco_nodes - eco_direct - eco_orphans)
            eco_cycles = list(itertools.islice(nx.simple_cycles(sub_g), 10))

            per_eco[eco.value] = EcosystemGraphMetadata(
                total_nodes=eco_nodes,
                total_edges=eco_edges,
                direct_dependencies_count=eco_direct,
                transitive_dependencies_count=eco_transitive,
                orphaned_nodes_count=eco_orphans,
                max_depth=eco_max_d,
                has_cycles=len(eco_cycles) > 0,
                unresolved_refs=[],
            )

        master_meta = GraphMetadata(
            total_nodes=total_nodes,
            total_edges=total_edges,
            direct_dependencies_count=total_direct,
            transitive_dependencies_count=total_transitive,
            orphaned_nodes_count=total_orphans,
            max_depth=global_max_depth,
            has_cycles=len(cycle_samples) > 0,
            cycle_samples=cycle_samples,
            unresolved_refs=[],
            per_ecosystem=per_eco,
        )

        return composed, master_meta


# ---------------------------------------------------------------------------
# Self-Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Executing verification harness for scg_core/ingestion/graph_builder.py ...")

    builder = DependencyGraphBuilder()

    # ===========================================================================
    # INGEST-TC-03: UUID bom-ref decoupling & depth=None for orphaned nodes
    # Reference: Phase 2 SRS Section 4.3 (P2-04, P2-06)
    # ===========================================================================
    print("\n-- INGEST-TC-03: UUID bom-ref decoupling & orphaned node depth=None --")

    bom_tc03 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "bom-ref": "root-uuid-001",
                "name": "target-app",
                "version": "1.0.0",
            }
        },
        "components": [
            {
                "bom-ref": "uuid-express-002",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
            },
            {
                "bom-ref": "uuid-disconnected-003",
                "name": "orphan-pkg",
                "version": "1.0.0",
                "purl": "pkg:npm/orphan-pkg@1.0.0",
            },
        ],
        "dependencies": [
            {"ref": "root-uuid-001", "dependsOn": ["uuid-express-002"]},
            {"ref": "uuid-disconnected-003", "dependsOn": []},
        ],
    }

    graph, meta = builder.build_graph(bom_tc03, Ecosystem.NPM)

    # Node count (excludes synthetic root)
    assert meta.total_nodes == 2, f"Expected 2 nodes, got {meta.total_nodes}"
    assert meta.direct_dependencies_count == 1, (
        f"Expected 1 direct dep, got {meta.direct_dependencies_count}"
    )
    assert meta.orphaned_nodes_count == 1, (
        f"Expected 1 orphaned node, got {meta.orphaned_nodes_count}"
    )

    # Express: direct dependency at depth 1
    express = graph.nodes["pkg:npm/express@4.18.2"]
    assert express["depth"] == 1, f"express depth should be 1, got {express['depth']}"
    assert express["is_direct"] is True, "express should be tagged as direct"
    print("OK [TC-03-1/4] express@4.18.2: depth=1, is_direct=True.")

    # Orphan: unreachable from root -- depth must be None, never 999 (P2-06)
    orphan = graph.nodes["pkg:npm/orphan-pkg@1.0.0"]
    assert orphan["depth"] is None, (
        f"orphan depth must be None (not 999 or any sentinel), got {orphan['depth']}"
    )
    assert orphan.get("is_direct", False) is False, "orphan must not be tagged as direct"
    print("OK [TC-03-2/4] orphan-pkg@1.0.0: depth=None (never 999), is_direct=False.")

    # No cycles in this acyclic test graph
    assert meta.has_cycles is False, "No cycles expected in TC-03 graph"
    print("OK [TC-03-3/4] No cycles detected in acyclic graph.")

    # Metadata JSON round-trip
    restored = GraphMetadata.model_validate_json(meta.model_dump_json())
    assert restored == meta
    print("OK [TC-03-4/4] GraphMetadata JSON round-trip verified.")

    # ===========================================================================
    # INGEST-TC-04: Transitive depth and cycle detection
    # ===========================================================================
    print("\n-- INGEST-TC-04: Transitive depth and cycle detection --")

    bom_tc04 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root-ref", "name": "app", "version": "1.0"}},
        "components": [
            {"bom-ref": "ref-a", "name": "pkgA", "version": "1.0", "purl": "pkg:npm/pkgA@1.0"},
            {"bom-ref": "ref-b", "name": "pkgB", "version": "1.0", "purl": "pkg:npm/pkgB@1.0"},
            {"bom-ref": "ref-c", "name": "pkgC", "version": "1.0", "purl": "pkg:npm/pkgC@1.0"},
        ],
        "dependencies": [
            {"ref": "root-ref", "dependsOn": ["ref-a"]},
            {"ref": "ref-a", "dependsOn": ["ref-b"]},
            {"ref": "ref-b", "dependsOn": ["ref-c"]},
            {"ref": "ref-c", "dependsOn": ["ref-a"]},   # cycle: A -> B -> C -> A
        ],
    }

    graph4, meta4 = builder.build_graph(bom_tc04, Ecosystem.NPM)

    assert graph4.nodes["pkg:npm/pkgA@1.0"]["depth"] == 1
    assert graph4.nodes["pkg:npm/pkgB@1.0"]["depth"] == 2
    assert graph4.nodes["pkg:npm/pkgC@1.0"]["depth"] == 3
    print("OK [TC-04-1/3] Transitive depths: pkgA=1, pkgB=2, pkgC=3.")

    assert meta4.has_cycles is True, "Cycle A->B->C->A should be detected"
    assert len(meta4.cycle_samples) > 0, "At least one cycle sample expected"
    assert len(meta4.cycle_samples) <= 10, "Cycle samples must be bounded to <=10 (P2-05)"
    print(f"OK [TC-04-2/3] Cycle detected; {len(meta4.cycle_samples)} sample(s) bounded to <=10 (P2-05).")

    assert meta4.direct_dependencies_count == 1   # only pkgA is at depth 1
    assert meta4.transitive_dependencies_count == 2  # pkgB, pkgC
    print("OK [TC-04-3/3] direct=1, transitive=2.")

    # ===========================================================================
    # INGEST-TC-05: Multi-ecosystem graph composition (P2-07)
    # ===========================================================================
    print("\n-- INGEST-TC-05: Multi-ecosystem compose_graphs --")

    bom_npm = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "npm-root", "name": "app", "version": "1.0"}},
        "components": [
            {"bom-ref": "npm-ref-1", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        ],
        "dependencies": [
            {"ref": "npm-root", "dependsOn": ["npm-ref-1"]},
        ],
    }
    bom_pypi = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "pypi-root", "name": "app", "version": "1.0"}},
        "components": [
            {"bom-ref": "pypi-ref-1", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
        "dependencies": [
            {"ref": "pypi-root", "dependsOn": ["pypi-ref-1"]},
        ],
    }

    npm_graph, _ = builder.build_graph(bom_npm, Ecosystem.NPM)
    pypi_graph, _ = builder.build_graph(bom_pypi, Ecosystem.PYPI)

    composed_graph, composed_meta = DependencyGraphBuilder.compose_graphs(
        {Ecosystem.NPM: npm_graph, Ecosystem.PYPI: pypi_graph}
    )

    assert "pkg:npm/lodash@4.17.21" in composed_graph, "lodash missing from composed graph"
    assert "pkg:pypi/requests@2.31.0" in composed_graph, "requests missing from composed graph"
    assert composed_meta.total_nodes == 2, f"Expected 2 total nodes, got {composed_meta.total_nodes}"
    assert composed_meta.direct_dependencies_count == 2, (
        f"Expected 2 direct deps (one per ecosystem), got {composed_meta.direct_dependencies_count}"
    )
    assert "npm" in composed_meta.per_ecosystem
    assert "pypi" in composed_meta.per_ecosystem

    # Both direct deps should have depth=1 in the composed graph
    lodash_depth = composed_graph.nodes["pkg:npm/lodash@4.17.21"].get("depth")
    requests_depth = composed_graph.nodes["pkg:pypi/requests@2.31.0"].get("depth")
    assert lodash_depth == 1, f"lodash depth in composed graph should be 1, got {lodash_depth}"
    assert requests_depth == 1, f"requests depth in composed graph should be 1, got {requests_depth}"
    print("OK [TC-05-1/2] Composed graph has 2 nodes from 2 ecosystems, both at depth=1.")
    print(f"OK [TC-05-2/2] per_ecosystem: {list(composed_meta.per_ecosystem.keys())}.")

    print("\nSUCCESS: scg_core/ingestion/graph_builder.py verified")
