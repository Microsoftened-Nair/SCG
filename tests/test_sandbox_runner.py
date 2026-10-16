"""Unit tests for SandboxRunner isolated container remediation and lockfile verification."""

import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from scg_core.remediation.sandbox_runner import SandboxRunner
from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import (
    ManifestUpdateMode,
    RemediationCandidate,
    RemediationOutcome,
    RemediationStrategy,
    UpgradeSafetyClassification,
)


def test_constants():
    """Validates REQ-P6-04: SandboxRunner pinned digest and execution timeout."""
    assert (
        SandboxRunner.PINNED_NODE_DIGEST
        == "node:20-alpine@sha256:d826a7c413ea4b80b72c91a0c8b6b21aa80c44ec93e7f4c4a4e9b9868777fa9f"
    )
    assert SandboxRunner.EXECUTION_TIMEOUT_SECONDS == 60.0


def test_inject_npm_override_scoped_and_global(tmp_path: Path):
    """Validates REQ-P6-05: scoped and global override injection preserving formatting."""
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(json.dumps({"name": "my-app", "dependencies": {}}, indent=2))

    # 1. Scoped override
    cand_scoped = RemediationCandidate(
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
    SandboxRunner._inject_npm_override(manifest_path, cand_scoped)
    data = json.loads(manifest_path.read_text())
    assert data["overrides"]["react-scripts"]["semver"] == "^7.5.4"

    # 2. Global override
    cand_global = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.20",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.GLOBAL_OVERRIDE,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=False,
        manifest_path="package.json",
        parent_package=None,
    )
    SandboxRunner._inject_npm_override(manifest_path, cand_global)
    data2 = json.loads(manifest_path.read_text())
    assert data2["overrides"]["react-scripts"]["semver"] == "^7.5.4"
    assert data2["overrides"]["lodash"] == "^4.17.21"


def test_update_direct_manifest(tmp_path: Path):
    """Validates REQ-P6-05: direct manifest constraint updates."""
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(
        json.dumps(
            {
                "name": "my-app",
                "dependencies": {"express": "^4.17.1"},
                "devDependencies": {"jest": "^26.0.0"},
            },
            indent=2,
        )
    )

    # Update dependencies entry
    cand_dep = RemediationCandidate(
        package_name="express",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.1",
        target_version="4.18.2",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2022-24999"],
        is_direct=True,
        manifest_path="package.json",
    )
    SandboxRunner._update_direct_manifest(manifest_path, cand_dep)

    # Update devDependencies entry
    cand_dev = RemediationCandidate(
        package_name="jest",
        ecosystem=Ecosystem.NPM,
        current_version="26.0.0",
        target_version="26.6.3",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-1234"],
        is_direct=True,
        manifest_path="package.json",
    )
    SandboxRunner._update_direct_manifest(manifest_path, cand_dev)

    data = json.loads(manifest_path.read_text())
    assert data["dependencies"]["express"] == "^4.18.2"
    assert data["devDependencies"]["jest"] == "^26.6.3"


def test_verify_lockfile_scenarios(tmp_path: Path):
    """Validates REQ-P6-06: lockfile verification against packages schema and failure modes."""
    lockfile_path = tmp_path / "package-lock.json"

    cand = RemediationCandidate(
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

    # 1. Missing lockfile
    v_missing = SandboxRunner._verify_lockfile(lockfile_path, cand)
    assert v_missing.lockfile_parses is False
    assert v_missing.verdict == "FAILED"
    assert v_missing.advisory_still_matches is True

    # 2. Corrupted JSON lockfile
    lockfile_path.write_text("{ corrupt json ...")
    v_corrupt = SandboxRunner._verify_lockfile(lockfile_path, cand)
    assert v_corrupt.lockfile_parses is False
    assert v_corrupt.verdict == "FAILED"

    # 3. Verified lockfile (v3 packages format)
    lockfile_data = {
        "name": "my-app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/parent/node_modules/semver": {"version": "7.5.4"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_data, indent=2))
    v_ok = SandboxRunner._verify_lockfile(lockfile_path, cand)
    assert v_ok.lockfile_parses is True
    assert v_ok.target_version_resolved is True
    assert v_ok.advisory_still_matches is False
    assert v_ok.verdict == "VERIFIED"

    # 4. Old version persisting in lockfile
    lockfile_data["packages"]["node_modules/parent/node_modules/semver"]["version"] = "7.3.0"
    lockfile_path.write_text(json.dumps(lockfile_data, indent=2))
    v_old = SandboxRunner._verify_lockfile(lockfile_path, cand)
    assert v_old.lockfile_parses is True
    assert v_old.target_version_resolved is False
    assert v_old.advisory_still_matches is True
    assert v_old.verdict == "FAILED"


def test_apply_remediation_missing_package_json(tmp_path: Path):
    """Validates immediate SANDBOX_ERROR when package.json is absent."""
    cand = RemediationCandidate(
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
    result = SandboxRunner.apply_remediation(tmp_path, cand)
    assert result.outcome == RemediationOutcome.SANDBOX_ERROR
    assert result.verification is None
    assert "package.json absent" in (result.stderr_excerpt or "")


def test_apply_remediation_docker_command_construction(tmp_path: Path):
    """Validates REQ-P6-07: Docker CLI argument vector adheres strictly to security requirements."""
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(json.dumps({"name": "test-pkg", "dependencies": {"lodash": "^4.17.20"}}))

    cand = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.20",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=True,
        manifest_path="package.json",
    )

    recorded_cmd = []

    def mock_execute_container(cmd, timeout):
        nonlocal recorded_cmd
        recorded_cmd = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="simulated failure")

    with patch.object(SandboxRunner, "_execute_container", side_effect=mock_execute_container):
        result = SandboxRunner.apply_remediation(tmp_path, cand)
        assert result.outcome == RemediationOutcome.MANIFEST_ONLY_FALLBACK

    # Verify security flags
    assert recorded_cmd[0] == "docker"
    assert recorded_cmd[1] == "run"
    assert "--rm" in recorded_cmd
    assert "--user" in recorded_cmd and recorded_cmd[recorded_cmd.index("--user") + 1] == "65534:65534"
    assert "--read-only" in recorded_cmd
    assert "--tmpfs" in recorded_cmd
    assert "/tmp:rw,noexec,nosuid,size=64m" in recorded_cmd
    assert "/home/nobody/.npm:rw,noexec,nosuid,size=256m" in recorded_cmd
    assert "--cap-drop" in recorded_cmd and recorded_cmd[recorded_cmd.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in recorded_cmd and recorded_cmd[recorded_cmd.index("--security-opt") + 1] == "no-new-privileges"
    assert "--pids-limit" in recorded_cmd and recorded_cmd[recorded_cmd.index("--pids-limit") + 1] == "256"
    assert "--memory" in recorded_cmd and recorded_cmd[recorded_cmd.index("--memory") + 1] == "512m"
    assert "--network" in recorded_cmd and recorded_cmd[recorded_cmd.index("--network") + 1] == "scg-egress"
    assert "--env" in recorded_cmd
    assert "HTTPS_PROXY=http://scg-proxy:3128" in recorded_cmd
    assert "npm_config_audit=false" in recorded_cmd
    assert "npm_config_fund=false" in recorded_cmd
    assert SandboxRunner.PINNED_NODE_DIGEST in recorded_cmd
    assert "npm" in recorded_cmd
    assert "install" in recorded_cmd
    assert "lodash@4.17.21" in recorded_cmd
    assert "--package-lock-only" in recorded_cmd
    assert "--ignore-scripts" in recorded_cmd
    assert "--no-audit" in recorded_cmd
    assert "--no-fund" in recorded_cmd


def test_apply_remediation_success_lockfile_updated(tmp_path: Path):
    """Validates successful remediation flow yielding LOCKFILE_UPDATED."""
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(json.dumps({"name": "test-pkg", "dependencies": {"lodash": "^4.17.20"}}))

    lockfile_path = tmp_path / "package-lock.json"

    cand = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.20",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=True,
        manifest_path="package.json",
    )

    def mock_execute_success(cmd, timeout):
        # Simulate successful npm install creating valid lockfile
        lockfile_path.write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "test-pkg", "version": "1.0.0"},
                        "node_modules/lodash": {"version": "4.17.21"},
                    },
                }
            )
        )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch.object(SandboxRunner, "_execute_container", side_effect=mock_execute_success):
        result = SandboxRunner.apply_remediation(tmp_path, cand)
        assert result.outcome == RemediationOutcome.LOCKFILE_UPDATED
        assert result.exit_code == 0
        assert result.verification is not None
        assert result.verification.verdict == "VERIFIED"
        assert result.verification.target_version_resolved is True


def test_apply_remediation_verification_failed(tmp_path: Path):
    """Validates VERIFICATION_FAILED when lockfile generates but target version does not resolve."""
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(json.dumps({"name": "test-pkg", "dependencies": {"lodash": "^4.17.20"}}))

    lockfile_path = tmp_path / "package-lock.json"

    cand = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="4.17.20",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.PATCH_FIX_SAFE,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=True,
        manifest_path="package.json",
    )

    def mock_execute_stale_lockfile(cmd, timeout):
        # Generates lockfile with old version
        lockfile_path.write_text(
            json.dumps(
                {
                    "name": "test-pkg",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "test-pkg", "version": "1.0.0"},
                        "node_modules/lodash": {"version": "4.17.20"},
                    },
                }
            )
        )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch.object(SandboxRunner, "_execute_container", side_effect=mock_execute_stale_lockfile):
        result = SandboxRunner.apply_remediation(tmp_path, cand)
        assert result.outcome == RemediationOutcome.VERIFICATION_FAILED
        assert result.exit_code == 0
        assert result.verification is not None
        assert result.verification.verdict == "FAILED"
