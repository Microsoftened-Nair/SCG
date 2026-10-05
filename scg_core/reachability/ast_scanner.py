"""Multi-language static AST lexing and source tree scanning engine."""

from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.reachability import (
    FileScanStatus,
    ImportStatement,
    InvocationCall,
    ParseConfidence,
    SourceFileScanResult,
    SourceTier,
)

logger = logging.getLogger(__name__)

# PEP 503 Distribution Normalization & Curated Mapping (P4-03)
PYPI_IMPORT_TO_DIST: Dict[str, str] = {
    "yaml": "pyyaml",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "pil": "pillow",
    "dateutil": "python-dateutil",
    "jwt": "pyjwt",
    "dotenv": "python-dotenv",
    "google.protobuf": "protobuf",
    "attr": "attrs",
}


def normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


class ASTScanner:
    """Multi-language static scanner utilizing tree-sitter and Python AST."""

    MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB ceiling (P4-08)
    MAX_TOTAL_SCAN_BYTES: int = 200 * 1024 * 1024  # 200 MB budget
    MAX_TRAVERSAL_DEPTH: int = 16

    EXCLUDED_DIRS: Set[str] = {
        "node_modules",
        ".git",
        ".github",
        ".vscode",
        "dist",
        "build",
        ".next",
        "out",
        "target",
        "vendor",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        "coverage",
    }

    JS_EXTENSIONS: Set[str] = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    PY_EXTENSIONS: Set[str] = {".py"}

    TEST_PATTERNS = re.compile(
        r"(?:^|[\\/])(test|tests|__tests__|spec|e2e|fixtures)(?:[\\/]|$)",
        re.IGNORECASE,
    )
    TEST_FILE_RE = re.compile(
        r"(\.test\.|\.spec\.|test_|_test\.|conftest\.py$)",
        re.IGNORECASE,
    )

    def scan_workspace(self, root_dir: Path) -> Tuple[List[SourceFileScanResult], float]:
        """Safely traverse the workspace and extract imports and symbols.

        Args:
            root_dir: Absolute path to the repository root directory.

        Returns:
            Tuple of scan results list and repository analysis coverage ratio (0.0 to 1.0).
        """
        results: List[SourceFileScanResult] = []
        discovered_count = 0
        scanned_count = 0
        total_bytes = 0

        root_depth = len(root_dir.resolve().parts)

        for root, dirs, files in os.walk(root_dir):
            current_path = Path(root).resolve()
            current_depth = len(current_path.parts) - root_depth

            if current_depth >= self.MAX_TRAVERSAL_DEPTH:
                dirs.clear()
                continue

            # Prune excluded directories and hidden dot-directories
            dirs[:] = [
                d
                for d in dirs
                if d not in self.EXCLUDED_DIRS and not d.startswith(".")
            ]

            for filename in files:
                filepath = Path(root) / filename
                suffix = filepath.suffix.lower()

                if suffix not in self.PY_EXTENSIONS and suffix not in self.JS_EXTENSIONS:
                    continue

                discovered_count += 1
                try:
                    file_size = filepath.stat().st_size
                except OSError:
                    continue

                tier = self._classify_tier(filepath, root_dir)

                if (
                    file_size > self.MAX_FILE_SIZE_BYTES
                    or (total_bytes + file_size) > self.MAX_TOTAL_SCAN_BYTES
                ):
                    try:
                        rel_str = str(filepath.relative_to(root_dir)).replace("\\", "/")
                    except ValueError:
                        rel_str = str(filepath).replace("\\", "/")

                    results.append(
                        SourceFileScanResult(
                            file_path=rel_str,
                            tier=tier,
                            ecosystem=Ecosystem.PYPI if suffix in self.PY_EXTENSIONS else Ecosystem.NPM,
                            status=FileScanStatus.SKIPPED_TOO_LARGE,
                            parse_confidence=ParseConfidence.FAILED,
                        )
                    )
                    continue

                total_bytes += file_size
                if suffix in self.PY_EXTENSIONS:
                    res = self._scan_python_file(filepath, root_dir, tier)
                else:
                    res = self._scan_js_ts_file(filepath, root_dir, tier)

                results.append(res)
                if res.status == FileScanStatus.SCANNED:
                    scanned_count += 1

        coverage = (scanned_count / discovered_count) if discovered_count > 0 else 1.0
        return results, coverage

    def _classify_tier(self, path: Path, root_dir: Path) -> SourceTier:
        """Classify a source file into APPLICATION, TEST, or TOOLING tier."""
        try:
            rel_str = str(path.relative_to(root_dir)).replace("\\", "/")
        except ValueError:
            rel_str = str(path).replace("\\", "/")

        if self.TEST_PATTERNS.search(rel_str) or self.TEST_FILE_RE.search(path.name):
            return SourceTier.TEST

        if (
            "config." in path.name
            or (path.parent == root_dir and path.name.endswith(".js"))
            or (path.parent == root_dir and path.name.endswith(".ts"))
            or rel_str.startswith("scripts/")
            or path.name.lower() in {"makefile"}
        ):
            return SourceTier.TOOLING

        return SourceTier.APPLICATION

    def _scan_python_file(
        self, file_path: Path, root_dir: Path, tier: SourceTier
    ) -> SourceFileScanResult:
        """Parse Python source file using native ast and resolve imports/calls."""
        try:
            rel_path = str(file_path.relative_to(root_dir)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path).replace("\\", "/")

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=rel_path)
        except Exception as exc:
            return SourceFileScanResult(
                file_path=rel_path,
                tier=tier,
                ecosystem=Ecosystem.PYPI,
                status=FileScanStatus.PARSE_FAILED,
                parse_confidence=ParseConfidence.FAILED,
                parse_errors=[str(exc)],
            )

        imports: List[ImportStatement] = []
        invocations: List[InvocationCall] = []
        bindings: Dict[str, Tuple[str, str]] = {}  # local_name -> (dist_name, symbol)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw_root = alias.name.split(".")[0]
                    canon = PYPI_IMPORT_TO_DIST.get(
                        raw_root.lower(), normalize_pypi_name(raw_root)
                    )
                    local_as = alias.asname or alias.name
                    bindings[local_as] = (canon, "*namespace*")
                    imports.append(
                        ImportStatement(
                            source_file=rel_path,
                            line_number=node.lineno,
                            raw_module=alias.name,
                            canonical_package=canon,
                            imported_symbols=[],
                            alias=alias.asname,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    raw_root = node.module.split(".")[0]
                    canon = PYPI_IMPORT_TO_DIST.get(
                        raw_root.lower(), normalize_pypi_name(raw_root)
                    )
                    symbols = [a.name for a in node.names]
                    for a in node.names:
                        local_as = a.asname or a.name
                        bindings[local_as] = (canon, a.name)
                    imports.append(
                        ImportStatement(
                            source_file=rel_path,
                            line_number=node.lineno,
                            raw_module=node.module,
                            canonical_package=canon,
                            imported_symbols=symbols,
                        )
                    )
            elif isinstance(node, ast.Call):
                resolved_call = self._resolve_py_call(node.func, bindings)
                if resolved_call:
                    invocations.append(
                        InvocationCall(
                            source_file=rel_path,
                            line_number=node.lineno,
                            caller_symbol=resolved_call[1],
                            full_expression=resolved_call[2],
                            resolved_package=resolved_call[0],
                            resolved_symbol=resolved_call[1],
                        )
                    )

        return SourceFileScanResult(
            file_path=rel_path,
            tier=tier,
            ecosystem=Ecosystem.PYPI,
            status=FileScanStatus.SCANNED,
            parse_confidence=ParseConfidence.HIGH,
            imports=imports,
            invocations=invocations,
        )

    def _resolve_py_call(
        self, func_node: ast.AST, bindings: Dict[str, Tuple[str, str]]
    ) -> Optional[Tuple[str, str, str]]:
        """Resolve a Python AST Call node to (dist_package, symbol, full_expression)."""
        if isinstance(func_node, ast.Name):
            if func_node.id in bindings:
                pkg, sym = bindings[func_node.id]
                return pkg, sym, func_node.id
        elif isinstance(func_node, ast.Attribute):
            if (
                isinstance(func_node.value, ast.Name)
                and func_node.value.id in bindings
            ):
                pkg, sym = bindings[func_node.value.id]
                full_expr = f"{func_node.value.id}.{func_node.attr}"
                return pkg, func_node.attr, full_expr
        return None

    def _get_tree_sitter_parser(self, lang: str) -> Optional[Any]:
        """Attempt to obtain a tree-sitter parser from available libraries."""
        try:
            from tree_sitter_languages import get_parser

            return get_parser(lang)
        except Exception:
            pass

        try:
            from tree_sitter import Language, Parser

            if lang == "typescript":
                import tree_sitter_typescript as tsts

                ts_func = getattr(tsts, "language_typescript", None) or getattr(
                    tsts, "language", None
                )
                lang_obj = Language(ts_func())
            else:
                import tree_sitter_javascript as tsjs

                lang_obj = Language(tsjs.language())

            try:
                return Parser(lang_obj)
            except Exception:
                p = Parser()
                p.set_language(lang_obj)
                return p
        except Exception:
            pass

        return None

    def _scan_js_ts_file(
        self, file_path: Path, root_dir: Path, tier: SourceTier
    ) -> SourceFileScanResult:
        """Parse JS/TS file using tree-sitter or regex fallback."""
        try:
            rel_path = str(file_path.relative_to(root_dir)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path).replace("\\", "/")

        content = file_path.read_text(encoding="utf-8", errors="replace")

        imports: List[ImportStatement] = []
        invocations: List[InvocationCall] = []

        suffix = file_path.suffix.lower()
        lang = "typescript" if suffix in {".ts", ".tsx"} else "javascript"

        parser = self._get_tree_sitter_parser(lang)
        if parser is not None:
            try:
                tree = parser.parse(bytes(content, "utf8"))
                confidence = ParseConfidence.HIGH
                self._extract_tree_sitter_nodes(
                    tree.root_node, rel_path, imports, invocations
                )
            except Exception as exc:
                logger.warning(f"Tree-sitter parse error for {rel_path}: {exc}")
                confidence = ParseConfidence.LOW
                self._fallback_regex_extract(content, rel_path, imports)
        else:
            confidence = ParseConfidence.LOW
            self._fallback_regex_extract(content, rel_path, imports)

        return SourceFileScanResult(
            file_path=rel_path,
            tier=tier,
            ecosystem=Ecosystem.NPM,
            status=FileScanStatus.SCANNED,
            parse_confidence=confidence,
            imports=imports,
            invocations=invocations,
        )

    def _extract_tree_sitter_nodes(
        self,
        root_node: Any,
        rel_path: str,
        imports: List[ImportStatement],
        invocations: List[InvocationCall],
    ) -> None:
        """Extract imports and invocations recursively from tree-sitter syntax tree."""
        def walk(node: Any) -> None:
            # import_statement: import x from 'pkg';
            if node.type == "import_statement":
                src = self._get_child_by_type(node, "string")
                if src:
                    raw_mod = src.text.decode("utf8").strip("'\"`")
                    canon = self._normalize_js_pkg_name(raw_mod)
                    if canon:
                        line = node.start_point[0] + 1
                        imports.append(
                            ImportStatement(
                                source_file=rel_path,
                                line_number=line,
                                raw_module=raw_mod,
                                canonical_package=canon,
                            )
                        )
            # export_statement with source: export { x } from 'pkg'; (P4-04)
            elif node.type == "export_statement":
                src = self._get_child_by_type(node, "string")
                if src:
                    raw_mod = src.text.decode("utf8").strip("'\"`")
                    canon = self._normalize_js_pkg_name(raw_mod)
                    if canon:
                        line = node.start_point[0] + 1
                        imports.append(
                            ImportStatement(
                                source_file=rel_path,
                                line_number=line,
                                raw_module=raw_mod,
                                canonical_package=canon,
                                is_reexport=True,
                            )
                        )
            # call_expression: require('pkg') or dynamic import('pkg')
            elif node.type == "call_expression":
                fn_node = getattr(node, "child_by_field_name", lambda _: None)("function")
                if not fn_node:
                    for ch in node.children:
                        if ch.type in {"identifier", "import"}:
                            fn_node = ch
                            break

                args_node = getattr(node, "child_by_field_name", lambda _: None)("arguments")
                if not args_node:
                    args_node = self._get_child_by_type(node, "arguments")

                fn_name = fn_node.text.decode("utf8") if fn_node and fn_node.text else ""
                if fn_name in {"require", "import"} and args_node:
                    str_node = self._get_child_by_type(args_node, "string")
                    if str_node:
                        raw_mod = str_node.text.decode("utf8").strip("'\"`")
                        canon = self._normalize_js_pkg_name(raw_mod)
                        if canon:
                            line = node.start_point[0] + 1
                            imports.append(
                                ImportStatement(
                                    source_file=rel_path,
                                    line_number=line,
                                    raw_module=raw_mod,
                                    canonical_package=canon,
                                    is_dynamic=True,
                                )
                            )

            for child in node.children:
                walk(child)

        walk(root_node)

    def _get_child_by_type(self, node: Any, node_type: str) -> Optional[Any]:
        """Find the first direct child matching the given node type."""
        for ch in node.children:
            if ch.type == node_type:
                return ch
        return None

    def _normalize_js_pkg_name(self, raw_path: str) -> Optional[str]:
        """Normalize JS/TS import path to canonical package name."""
        if raw_path.startswith(".") or raw_path.startswith("/"):
            return None
        parts = raw_path.split("/")
        if raw_path.startswith("@") and len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return parts[0]

    def _fallback_regex_extract(
        self, content: str, rel_path: str, imports: List[ImportStatement]
    ) -> None:
        """Low-confidence fallback regex handler for JavaScript/TypeScript."""
        patterns = [
            r"""(?:import|export)\s+.*?from\s*['"]([^'"]+)['"]""",
            r"""(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)""",
            r"""import\s+['"]([^'"]+)['"]""",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                raw = match.group(1)
                canon = self._normalize_js_pkg_name(raw)
                if canon:
                    imports.append(
                        ImportStatement(
                            source_file=rel_path,
                            line_number=1,
                            raw_module=raw,
                            canonical_package=canon,
                        )
                    )
