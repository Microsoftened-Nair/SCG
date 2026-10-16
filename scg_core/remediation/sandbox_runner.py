"""Isolated container sandbox runner for Supply Chain Guardian Track E.

Executes package manager CLI operations inside an unprivileged, network-filtered
container sandbox with lifecycle scripts disabled (--ignore-scripts) and egress
routed through an allowlisting proxy. Performs post-execution lockfile verification
and manifest-only fallback.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set

# Ensure repository root is on sys.path when executed directly
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import (
    ManifestUpdateMode,
    RemediationCandidate,
    RemediationOutcome,
    RemediationStrategy,
    RemediationVerification,
    SandboxExecutionResult,
    UpgradeSafetyClassification,
    VersionChange,
)


class SandboxRunner:
    """Manages secure sandboxed dependency remediation and verification."""

    PINNED_NODE_DIGEST: str = (
        "node:20-alpine@sha256:d826a7c413ea4b80b72c91a0c8b6b21aa80c44ec93e7f4c4a4e9b9868777fa9f"
    )
    EXECUTION_TIMEOUT_SECONDS: float = 60.0

    @classmethod
    def _inject_npm_override(
        cls,
        manifest_path: Path,
        candidate: RemediationCandidate,
    ) -> None:
        """Safely injects scoped or global override into package.json.

        If candidate.parent_package is present:
            overrides[candidate.parent_package][candidate.package_name] = f"^{candidate.target_version}"
        Otherwise:
            overrides[candidate.package_name] = f"^{candidate.target_version}"

        Preserves valid JSON formatting with indent=2.
        """
        if not manifest_path.exists():
            return

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        if "overrides" not in manifest or not isinstance(manifest["overrides"], dict):
            manifest["overrides"] = {}

        target_constraint = (
            candidate.target_version
            if candidate.target_version.startswith(("^", "~", ">=", ">", "="))
            else f"^{candidate.target_version}"
        )

        if candidate.parent_package:
            parent_overrides = manifest["overrides"].get(candidate.parent_package)
            if not isinstance(parent_overrides, dict):
                parent_overrides = {}
                manifest["overrides"][candidate.parent_package] = parent_overrides
            parent_overrides[candidate.package_name] = target_constraint
        else:
            manifest["overrides"][candidate.package_name] = target_constraint

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")

    @classmethod
    def _update_direct_manifest(
        cls,
        manifest_path: Path,
        candidate: RemediationCandidate,
    ) -> None:
        """Updates direct package constraint inside dependencies or devDependencies.

        Preserves valid JSON formatting with indent=2.
        """
        if not manifest_path.exists():
            return

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        target_constraint = (
            candidate.target_version
            if candidate.target_version.startswith(("^", "~", ">=", ">", "="))
            else f"^{candidate.target_version}"
        )

        if "dependencies" in manifest and candidate.package_name in manifest["dependencies"]:
            manifest["dependencies"][candidate.package_name] = target_constraint
        elif "devDependencies" in manifest and candidate.package_name in manifest["devDependencies"]:
            manifest["devDependencies"][candidate.package_name] = target_constraint
        else:
            manifest.setdefault("dependencies", {})[candidate.package_name] = target_constraint

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")

    @classmethod
    def _verify_lockfile(
        cls,
        lockfile_path: Path,
        candidate: RemediationCandidate,
    ) -> RemediationVerification:
        """Verifies package-lock.json v2/v3 after sandbox remediation execution.

        Reads package-lock.json, searches packages map for candidate package,
        and verifies if recorded version matches candidate.target_version.
        """
        if not lockfile_path.exists():
            return RemediationVerification(
                target_version_resolved=False,
                advisory_still_matches=True,
                lockfile_parses=False,
                unexpected_version_changes=[],
                verdict="FAILED",
            )

        try:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return RemediationVerification(
                target_version_resolved=False,
                advisory_still_matches=True,
                lockfile_parses=False,
                unexpected_version_changes=[],
                verdict="FAILED",
            )

        packages = data.get("packages")
        target_resolved = False

        if isinstance(packages, dict):
            for pkg_path, pkg_info in packages.items():
                if not pkg_path or not isinstance(pkg_info, dict):
                    continue

                clean_name = (
                    pkg_path.split("node_modules/")[-1]
                    if "node_modules/" in pkg_path
                    else pkg_path.lstrip("/")
                )

                if clean_name == candidate.package_name:
                    recorded_version = pkg_info.get("version")
                    if recorded_version == candidate.target_version:
                        target_resolved = True
                        break

        # Fallback inspection for v1 lockfiles with top-level dependencies map
        if not target_resolved and isinstance(data.get("dependencies"), dict):
            target_resolved = cls._check_v1_dependencies(
                data["dependencies"],
                candidate.package_name,
                candidate.target_version,
            )

        if target_resolved:
            return RemediationVerification(
                target_version_resolved=True,
                advisory_still_matches=False,
                lockfile_parses=True,
                unexpected_version_changes=[],
                verdict="VERIFIED",
            )

        return RemediationVerification(
            target_version_resolved=False,
            advisory_still_matches=True,
            lockfile_parses=True,
            unexpected_version_changes=[],
            verdict="FAILED",
        )

    @classmethod
    def _check_v1_dependencies(
        cls,
        deps: Dict[str, Any],
        target_pkg: str,
        target_version: str,
    ) -> bool:
        """Recursively checks v1 lockfile dependencies map."""
        if target_pkg in deps and isinstance(deps[target_pkg], dict):
            if deps[target_pkg].get("version") == target_version:
                return True
        for dep_info in deps.values():
            if isinstance(dep_info, dict) and "dependencies" in dep_info:
                if cls._check_v1_dependencies(dep_info["dependencies"], target_pkg, target_version):
                    return True
        return False

    @classmethod
    def _execute_manifest_fallback(
        cls,
        manifest_path: Path,
        candidate: RemediationCandidate,
    ) -> None:
        """Applies manifest-only changes when sandbox execution fails."""
        if not manifest_path.exists():
            return
        if candidate.is_direct:
            cls._update_direct_manifest(manifest_path, candidate)
        else:
            cls._inject_npm_override(manifest_path, candidate)

    @classmethod
    def _execute_container(
        cls,
        cmd: List[str],
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        """Executes docker container subprocess strictly without shell=True."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )

    @classmethod
    def apply_remediation(
        cls,
        workspace_dir: Path,
        candidate: RemediationCandidate,
    ) -> SandboxExecutionResult:
        """Executes sandboxed npm remediation in an isolated container.

        Performs:
        1. Pre-execution manifest verification and modification.
        2. Docker CLI invocation with strict containment parameters.
        3. Post-execution lockfile verification.
        4. Manifest-only fallback on execution failure.
        """
        manifest_path = workspace_dir / (candidate.manifest_path or "package.json")
        lockfile_path = workspace_dir / (candidate.lockfile_path or "package-lock.json")

        # 1. If package.json is absent, return SANDBOX_ERROR immediately.
        if not manifest_path.exists():
            return SandboxExecutionResult(
                outcome=RemediationOutcome.SANDBOX_ERROR,
                exit_code=None,
                modified_files=[],
                stderr_excerpt="package.json absent in workspace directory",
                duration_seconds=0.0,
                verification=None,
            )

        modified_files: Set[str] = set()

        # 2. Modify manifest if applicable
        try:
            if not candidate.is_direct and candidate.strategy in (
                RemediationStrategy.SCOPED_OVERRIDE,
                RemediationStrategy.GLOBAL_OVERRIDE,
            ):
                cls._inject_npm_override(manifest_path, candidate)
                modified_files.add(manifest_path.name)
            elif candidate.is_direct and candidate.manifest_mode in (
                ManifestUpdateMode.RAISE_FLOOR,
                ManifestUpdateMode.WIDEN_RANGE,
            ):
                cls._update_direct_manifest(manifest_path, candidate)
                modified_files.add(manifest_path.name)
        except Exception as exc:
            return SandboxExecutionResult(
                outcome=RemediationOutcome.SANDBOX_ERROR,
                exit_code=None,
                modified_files=sorted(list(modified_files)),
                stderr_excerpt=f"Manifest preparation error: {exc}"[:8192],
                duration_seconds=0.0,
                verification=None,
            )

        # 3. Build Docker CLI argument vector strictly without shell=True
        cmd: List[str] = [
            "docker", "run", "--rm",
            "--user", "65534:65534",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/home/nobody/.npm:rw,noexec,nosuid,size=256m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            "--memory", "512m",
            "--memory-swap", "512m",
            "--cpus", "1.0",
            "--network", "scg-egress",
            "--env", "HTTPS_PROXY=http://scg-proxy:3128",
            "--env", "npm_config_audit=false",
            "--env", "npm_config_fund=false",
            "--volume", f"{workspace_dir.resolve()}:/work:rw",
            "--workdir", "/work",
            cls.PINNED_NODE_DIGEST,
            "npm", "install",
        ]
        if candidate.is_direct:
            cmd.append(f"{candidate.package_name}@{candidate.target_version}")

        cmd.extend([
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ])

        # 4. Execute with 60-second subprocess timeout
        start_time = time.perf_counter()
        try:
            proc = cls._execute_container(cmd, timeout=cls.EXECUTION_TIMEOUT_SECONDS)
            duration = time.perf_counter() - start_time
            stderr_excerpt = proc.stderr[:8192] if proc.stderr else None

            if proc.returncode == 0 and lockfile_path.exists():
                modified_files.add(lockfile_path.name)
                verif = cls._verify_lockfile(lockfile_path, candidate)
                if verif.verdict != "VERIFIED":
                    return SandboxExecutionResult(
                        outcome=RemediationOutcome.VERIFICATION_FAILED,
                        exit_code=0,
                        modified_files=sorted(list(modified_files)),
                        stderr_excerpt=stderr_excerpt,
                        duration_seconds=duration,
                        verification=verif,
                    )
                return SandboxExecutionResult(
                    outcome=RemediationOutcome.LOCKFILE_UPDATED,
                    exit_code=0,
                    modified_files=sorted(list(modified_files)),
                    stderr_excerpt=stderr_excerpt,
                    duration_seconds=duration,
                    verification=verif,
                )

            # Subprocess returned non-zero or lockfile was not generated
            cls._execute_manifest_fallback(manifest_path, candidate)
            modified_files.add(manifest_path.name)
            return SandboxExecutionResult(
                outcome=RemediationOutcome.MANIFEST_ONLY_FALLBACK,
                exit_code=proc.returncode,
                modified_files=sorted(list(modified_files)),
                stderr_excerpt=stderr_excerpt,
                duration_seconds=duration,
                verification=None,
            )

        except Exception as exc:
            duration = time.perf_counter() - start_time
            cls._execute_manifest_fallback(manifest_path, candidate)
            modified_files.add(manifest_path.name)
            return SandboxExecutionResult(
                outcome=RemediationOutcome.MANIFEST_ONLY_FALLBACK,
                exit_code=-1,
                modified_files=sorted(list(modified_files)),
                stderr_excerpt=str(exc)[:8192],
                duration_seconds=duration,
                verification=None,
            )


if __name__ == "__main__":
    import tempfile

    print("Running SandboxRunner REQ-P6-08 self-tests...")

    # 1. Scoped override injection writes correct structure to a dummy package.json
    with tempfile.TemporaryDirectory() as tmpdir:
        m_path = Path(tmpdir) / "package.json"
        m_path.write_text(json.dumps({"name": "test-pkg", "dependencies": {}}, indent=2))

        c_transitive = RemediationCandidate(
            package_name="semver",
            ecosystem=Ecosystem.NPM,
            current_version="7.3.0",
            target_version="7.5.4",
            classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
            strategy=RemediationStrategy.SCOPED_OVERRIDE,
            manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
            cves_resolved=["CVE-2022-25883"],
            is_direct=False,
            manifest_path="package.json",
            parent_package="react-scripts",
        )
        SandboxRunner._inject_npm_override(m_path, c_transitive)
        updated_manifest = json.loads(m_path.read_text())
        assert "overrides" in updated_manifest, "Missing 'overrides' key in package.json"
        assert "react-scripts" in updated_manifest["overrides"], "Missing parent package in overrides"
        assert (
            updated_manifest["overrides"]["react-scripts"]["semver"] == "^7.5.4"
        ), f"Unexpected override constraint: {updated_manifest['overrides']['react-scripts']['semver']}"
        print("✓ Scoped override injection verified successfully.")

    # 2. _verify_lockfile correctly detects target version and flags failures when old versions persist
    with tempfile.TemporaryDirectory() as tmpdir:
        l_path = Path(tmpdir) / "package-lock.json"
        lockfile_data = {
            "name": "test-pkg",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-pkg", "version": "1.0.0"},
                "node_modules/semver": {"version": "7.5.4"},
            },
        }
        l_path.write_text(json.dumps(lockfile_data, indent=2))

        # Target version matches recorded version (7.5.4)
        c_verified = RemediationCandidate(
            package_name="semver",
            ecosystem=Ecosystem.NPM,
            current_version="7.3.0",
            target_version="7.5.4",
            classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
            strategy=RemediationStrategy.DIRECT_BUMP,
            manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
            cves_resolved=["CVE-2022-25883"],
            is_direct=True,
            manifest_path="package.json",
        )
        v_res = SandboxRunner._verify_lockfile(l_path, c_verified)
        assert v_res.verdict == "VERIFIED", f"Expected VERIFIED, got {v_res.verdict}"
        assert v_res.target_version_resolved is True, "Expected target_version_resolved=True"
        assert v_res.advisory_still_matches is False, "Expected advisory_still_matches=False"

        # Old version persists (candidate target is 7.5.5, but lockfile has 7.5.4)
        c_persisting = RemediationCandidate(
            package_name="semver",
            ecosystem=Ecosystem.NPM,
            current_version="7.3.0",
            target_version="7.5.5",
            classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
            strategy=RemediationStrategy.DIRECT_BUMP,
            manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
            cves_resolved=["CVE-2022-25883"],
            is_direct=True,
            manifest_path="package.json",
        )
        v_fail = SandboxRunner._verify_lockfile(l_path, c_persisting)
        assert v_fail.verdict == "FAILED", f"Expected FAILED, got {v_fail.verdict}"
        assert v_fail.target_version_resolved is False, "Expected target_version_resolved=False"
        assert v_fail.advisory_still_matches is True, "Expected advisory_still_matches=True"
        print("✓ Lockfile verification (match and failure) verified successfully.")

    # 3. Fallback mechanism correctly handles non-zero exit simulation
    with tempfile.TemporaryDirectory() as tmpdir:
        m_path = Path(tmpdir) / "package.json"
        m_path.write_text(json.dumps({"name": "test-pkg", "dependencies": {"semver": "^7.3.0"}}, indent=2))

        c_direct = RemediationCandidate(
            package_name="semver",
            ecosystem=Ecosystem.NPM,
            current_version="7.3.0",
            target_version="7.5.4",
            classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
            strategy=RemediationStrategy.DIRECT_BUMP,
            manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
            cves_resolved=["CVE-2022-25883"],
            is_direct=True,
            manifest_path="package.json",
        )

        # In this environment, docker network scg-egress or container execution fails non-zero,
        # triggering _execute_manifest_fallback cleanly
        res = SandboxRunner.apply_remediation(Path(tmpdir), c_direct)
        assert (
            res.outcome == RemediationOutcome.MANIFEST_ONLY_FALLBACK
        ), f"Expected MANIFEST_ONLY_FALLBACK, got {res.outcome}"

        updated_m = json.loads(m_path.read_text())
        assert (
            updated_m["dependencies"]["semver"] == "^7.5.4"
        ), f"Fallback did not update direct manifest constraint: {updated_m}"
        print("✓ Manifest-only fallback mechanism verified successfully.")

    print("All SandboxRunner self-tests passed successfully!")
