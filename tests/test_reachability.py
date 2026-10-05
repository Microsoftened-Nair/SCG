"""Comprehensive test suite for Track C Static AST Reachability Analysis Engine."""

from pathlib import Path
import tempfile
import pytest
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
    InvocationCall,
    ParseConfidence,
    ReachabilityEvaluationResult,
    SourceFileScanResult,
    SourceTier,
)
from scg_core.reachability.ast_scanner import (
    ASTScanner,
    PYPI_IMPORT_TO_DIST,
    normalize_pypi_name,
)
from scg_core.reachability.resolver import (
    ReachabilityResolver,
    test_critical_exposure_floor_and_pypi_mapping,
    test_reachability_5_tier_single_pass_bfs,
)


class TestReachabilitySchemas:
    """Verify schema constraints, frozen configs, and extra forbid rules."""

    def test_schema_immutability(self):
        stmt = ImportStatement(
            source_file="app.py",
            line_number=1,
            raw_module="os",
            canonical_package="os",
        )
        with pytest.raises(Exception):
            stmt.source_file = "other.py"  # type: ignore

    def test_schema_extra_forbid(self):
        with pytest.raises(Exception):
            ImportStatement(
                source_file="app.py",
                line_number=1,
                raw_module="os",
                canonical_package="os",
                unexpected_field=123,  # type: ignore
            )

    def test_evaluation_result_range(self):
        res = ReachabilityEvaluationResult(
            package_name="express",
            ecosystem=Ecosystem.NPM,
            resolved_version="4.18.2",
            graph_depth=1,
            reachability=ReachabilityStatus.DIRECT_IMPORTED,
            exposure_factor=1.0,
            effective_exposure_factor=1.0,
        )
        assert res.exposure_factor == 1.0
        assert res.effective_exposure_factor == 1.0

        with pytest.raises(Exception):
            ReachabilityEvaluationResult(
                package_name="express",
                ecosystem=Ecosystem.NPM,
                resolved_version="4.18.2",
                reachability=ReachabilityStatus.DIRECT_IMPORTED,
                exposure_factor=1.5,  # > 1.0 invalid
                effective_exposure_factor=1.0,
            )


class TestASTScanner:
    """Verify ASTScanner workspace traversal and file parsing."""

    def test_pypi_normalization(self):
        assert normalize_pypi_name("Py_YAML") == "py-yaml"
        assert normalize_pypi_name("scikit.learn") == "scikit-learn"
        assert PYPI_IMPORT_TO_DIST["yaml"] == "pyyaml"
        assert PYPI_IMPORT_TO_DIST["cv2"] == "opencv-python"

    def test_python_scanning(self):
        scanner = ASTScanner()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            py_file = root / "service.py"
            py_file.write_text(
                """import yaml
from PIL import Image
import requests as req

def main():
    yaml.safe_load("foo: bar")
    req.get("https://example.com")
""",
                encoding="utf-8",
            )

            results, coverage = scanner.scan_workspace(root)
            assert coverage == 1.0
            assert len(results) == 1
            res = results[0]
            assert res.file_path == "service.py"
            assert res.tier == SourceTier.APPLICATION
            assert res.ecosystem == Ecosystem.PYPI
            assert res.status == FileScanStatus.SCANNED
            assert res.parse_confidence == ParseConfidence.HIGH

            canon_pkgs = {imp.canonical_package for imp in res.imports}
            assert "pyyaml" in canon_pkgs
            assert "pillow" in canon_pkgs
            assert "requests" in canon_pkgs

            call_targets = {(inv.resolved_package, inv.resolved_symbol) for inv in res.invocations}
            assert ("pyyaml", "safe_load") in call_targets
            assert ("requests", "get") in call_targets

    def test_js_ts_scanning(self):
        scanner = ASTScanner()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            ts_file = root / "index.ts"
            ts_file.write_text(
                """import express from 'express';
import { get } from 'lodash';
import { helper } from './local-helper';
export { tool } from '@org/tooling-lib';
const debug = require('debug');
const dynamicMod = import('dynamic-pkg');
""",
                encoding="utf-8",
            )

            results, coverage = scanner.scan_workspace(root)
            assert coverage == 1.0
            assert len(results) == 1
            res = results[0]
            assert res.ecosystem == Ecosystem.NPM
            assert res.status == FileScanStatus.SCANNED

            canon_pkgs = {imp.canonical_package for imp in res.imports}
            assert "express" in canon_pkgs
            assert "lodash" in canon_pkgs
            assert "@org/tooling-lib" in canon_pkgs
            assert "debug" in canon_pkgs
            assert "dynamic-pkg" in canon_pkgs
            # Local relative import './local-helper' should be ignored
            assert "./local-helper" not in canon_pkgs

    def test_tier_classification_and_excluded_dirs(self):
        scanner = ASTScanner()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            # App file
            (root / "app.py").write_text("import sys", encoding="utf-8")
            # Test file
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_app.py").write_text("import pytest", encoding="utf-8")
            # Tooling file
            (root / "webpack.config.js").write_text("import path from 'path';", encoding="utf-8")
            # Excluded dir
            nm_dir = root / "node_modules" / "some-pkg"
            nm_dir.mkdir(parents=True)
            (nm_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

            results, coverage = scanner.scan_workspace(root)
            assert coverage == 1.0
            file_tiers = {r.file_path: r.tier for r in results}
            assert file_tiers.get("app.py") == SourceTier.APPLICATION
            assert file_tiers.get("tests/test_app.py") == SourceTier.TEST
            assert file_tiers.get("webpack.config.js") == SourceTier.TOOLING
            # node_modules should not be present
            assert not any("node_modules" in r.file_path for r in results)

    def test_file_too_large_skipping(self):
        scanner = ASTScanner()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            big_file = root / "huge.py"
            # Create file slightly larger than MAX_FILE_SIZE_BYTES (5MB + 10 bytes)
            big_file.write_bytes(b"# comment\n" * (5 * 1024 * 1024 // 10 + 2))

            results, coverage = scanner.scan_workspace(root)
            assert len(results) == 1
            assert results[0].status == FileScanStatus.SKIPPED_TOO_LARGE
            assert results[0].parse_confidence == ParseConfidence.FAILED
            assert coverage == 0.0

    def test_regex_fallback(self, monkeypatch):
        scanner = ASTScanner()
        # Mock _get_tree_sitter_parser to return None to test regex fallback
        monkeypatch.setattr(scanner, "_get_tree_sitter_parser", lambda lang: None)
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            js_file = root / "server.js"
            js_file.write_text(
                """const express = require('express');
import lodash from 'lodash';
""",
                encoding="utf-8",
            )
            results, coverage = scanner.scan_workspace(root)
            assert coverage == 1.0
            assert len(results) == 1
            assert results[0].parse_confidence == ParseConfidence.LOW
            canon_pkgs = {imp.canonical_package for imp in results[0].imports}
            assert "express" in canon_pkgs
            assert "lodash" in canon_pkgs


class TestReachabilityResolver:
    """Verify ReachabilityResolver algorithms and contract invariants."""

    def test_embedded_tc01(self):
        test_reachability_5_tier_single_pass_bfs()

    def test_embedded_tc02(self):
        test_critical_exposure_floor_and_pypi_mapping()

    def test_low_coverage_fallback(self):
        resolver = ReachabilityResolver()
        graph = nx.DiGraph()
        root = "pkg:scg/target-root@local"
        graph.add_node(root, depth=0)
        purl = "pkg:npm/express@4.18.2"
        graph.add_node(purl, name="express", version="4.18.2", depth=1, is_direct=True)
        graph.add_edge(root, purl)

        res, warnings = resolver.evaluate_graph_reachability(
            graph=graph,
            scan_results=[],
            coverage=0.85,  # < 0.90
            dev_packages=set(),
            vulnerabilities_map={},
        )

        assert any("Coverage 85.0% below 90% threshold" in w for w in warnings)
        assert res[purl].reachability == ReachabilityStatus.UNKNOWN_REACHABILITY
        assert res[purl].exposure_factor == 0.6
        assert res[purl].effective_exposure_factor == 0.6

    def test_symbol_confirmed_reachable(self):
        resolver = ReachabilityResolver()
        graph = nx.DiGraph()
        root = "pkg:scg/target-root@local"
        graph.add_node(root, depth=0)

        purl = "pkg:pypi/pyyaml@5.4.1"
        graph.add_node(
            purl, name="pyyaml", version="5.4.1", depth=1, is_direct=True, ecosystem="pypi"
        )
        graph.add_edge(root, purl)

        vuln = VulnerabilityRecord(
            id="CVE-2020-1747",
            summary="Arbitrary code execution in FullLoader",
            cvss_score=9.8,
            severity=SeverityLevel.CRITICAL,
            vulnerable_symbols=["load", "full_load"],
        )

        scan_results = [
            SourceFileScanResult(
                file_path="app.py",
                tier=SourceTier.APPLICATION,
                ecosystem=Ecosystem.PYPI,
                status=FileScanStatus.SCANNED,
                parse_confidence=ParseConfidence.HIGH,
                imports=[
                    ImportStatement(
                        source_file="app.py",
                        line_number=1,
                        raw_module="yaml",
                        canonical_package="pyyaml",
                    )
                ],
                invocations=[
                    InvocationCall(
                        source_file="app.py",
                        line_number=5,
                        caller_symbol="full_load",
                        full_expression="yaml.full_load",
                        resolved_package="pyyaml",
                        resolved_symbol="full_load",
                    )
                ],
            )
        ]

        res, _ = resolver.evaluate_graph_reachability(
            graph=graph,
            scan_results=scan_results,
            coverage=1.0,
            dev_packages=set(),
            vulnerabilities_map={purl: [vuln]},
        )

        assert res[purl].reachability == ReachabilityStatus.DIRECT_IMPORTED
        assert res[purl].symbol_confirmed_reachable is True
        assert len(res[purl].evidence_call_sites) > 0

    def test_known_exploited_vulnerability_floor(self):
        resolver = ReachabilityResolver()
        graph = nx.DiGraph()
        root = "pkg:scg/target-root@local"
        graph.add_node(root, depth=0)

        purl = "pkg:pypi/dev-tool@1.0.0"
        graph.add_node(
            purl, name="dev-tool", version="1.0.0", depth=1, is_direct=True, ecosystem="pypi"
        )
        graph.add_edge(root, purl)

        # Medium severity, but known exploited
        kev_vuln = VulnerabilityRecord(
            id="CVE-2023-1111",
            summary="Known exploited flaw",
            cvss_score=5.5,
            severity=SeverityLevel.MEDIUM,
            is_known_exploited=True,
        )

        res, _ = resolver.evaluate_graph_reachability(
            graph=graph,
            scan_results=[],
            coverage=1.0,
            dev_packages={"dev-tool"},
            vulnerabilities_map={purl: [kev_vuln]},
        )

        assert res[purl].reachability == ReachabilityStatus.DEV_DEPENDENCY
        assert res[purl].exposure_factor == 0.1
        # Effective exposure must be floored at 0.6 because is_known_exploited == True
        assert res[purl].effective_exposure_factor == 0.6
