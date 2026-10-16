"""Phase 6 Track E Level 5 Remediation unit tests."""

from decimal import Decimal
import json
from pathlib import Path
from unittest.mock import MagicMock

import github
from github import GithubException
import pytest

from scg_core.remediation.pr_synthesizer import PullRequestSynthesizer
from scg_core.remediation.sandbox_runner import SandboxRunner
from scg_core.remediation.semver_solver import SemVerSolver
from scg_core.schemas.base import Ecosystem
from scg_core.schemas.remediation import (
    ManifestUpdateMode,
    RemediationCandidate,
    RemediationOutcome,
    RemediationStrategy,
    SandboxExecutionResult,
    ScoreComputationMode,
    UpgradeSafetyClassification,
)


def test_semver_zero_x_and_calver_rules():
    """Validates REQ-P6-10.1: SemVer 0.x.y breaking dynamics and CalVer detection rules."""
    # Assert 0.2.3 -> 0.3.0 is MAJOR_BREAKING
    c1 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.3.0")
    assert c1 == UpgradeSafetyClassification.MAJOR_BREAKING

    # Assert 0.2.3 -> 0.2.4 is PATCH_FIX_SAFE
    c2 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "0.2.3", "0.2.4")
    assert c2 == UpgradeSafetyClassification.PATCH_FIX_SAFE

    # Assert 1.2.0 -> 1.3.0 is MINOR_FEATURE_SAFE
    c3 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.2.0", "1.3.0")
    assert c3 == UpgradeSafetyClassification.MINOR_FEATURE_SAFE

    # Assert 2021.3.17 -> 2021.4.1 is REQUIRES_REVIEW
    c4 = SemVerSolver.classify_upgrade(Ecosystem.PYPI, "2021.3.17", "2021.4.1")
    assert c4 == UpgradeSafetyClassification.REQUIRES_REVIEW

    # Assert 1.0.0 -> 1.0.1-rc1 is REQUIRES_REVIEW
    c5 = SemVerSolver.classify_upgrade(Ecosystem.NPM, "1.0.0", "1.0.1-rc1")
    assert c5 == UpgradeSafetyClassification.REQUIRES_REVIEW


def test_lockfile_verification_blocks_unsuccessful_resolutions(tmp_path: Path):
    """Validates REQ-P6-10.2 (REMED-TC-02): lockfile verification blocks unsuccessful resolutions."""
    lockfile_path = tmp_path / "package-lock.json"
    dummy_lockfile = {
        "name": "target-project",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "target-project", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
        },
    }
    lockfile_path.write_text(json.dumps(dummy_lockfile, indent=2))

    # Candidate intends to bump lodash to 4.17.21, but lockfile still has 4.17.20
    candidate = RemediationCandidate(
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

    verif = SandboxRunner._verify_lockfile(lockfile_path, candidate)
    assert verif.target_version_resolved is False
    assert verif.advisory_still_matches is True
    assert verif.lockfile_parses is True
    assert verif.verdict == "FAILED"


def test_pr_synthesis_aborts_on_verification_failure():
    """Validates REQ-P6-10.3: publish_remediation_pr returns pr_created=False if outcome is VERIFICATION_FAILED."""
    mock_gh = MagicMock()
    synthesizer = PullRequestSynthesizer("dummy_token", github_client=mock_gh)

    candidate = RemediationCandidate(
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

    failed_sandbox = SandboxExecutionResult(
        outcome=RemediationOutcome.VERIFICATION_FAILED,
        exit_code=0,
        modified_files=["package-lock.json"],
        stderr_excerpt="Advisory still matching target lockfile",
        duration_seconds=2.5,
        verification=None,
    )

    result = synthesizer.publish_remediation_pr(
        repo_name="org/repo",
        base_branch="main",
        expected_base_sha="abcdef1234567890",
        candidate=candidate,
        sandbox_res=failed_sandbox,
        changed_contents={"package-lock.json": "{}"},
        score_before=Decimal("60.00"),
        score_after=Decimal("75.00"),
    )

    assert result.pr_created is False
    assert "VERIFICATION_FAILED" in (result.skipped_reason or "")
    mock_gh.get_repo.assert_not_called()


def test_rejection_retention_suppresses_pr():
    """Validates REQ-P6-10.4: mocks GitHub repo with closed unmerged PR and asserts SUPPRESSED_BY_PRIOR_REJECTION."""
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    mock_gh.get_repo.return_value = mock_repo
    mock_repo.owner.login = "test-owner"

    # Base alignment matches
    mock_ref = MagicMock()
    mock_ref.object.sha = "base_sha_123"
    mock_repo.get_git_ref.return_value = mock_ref

    # Closed unmerged PR exists matching head
    closed_unmerged_pr = MagicMock()
    closed_unmerged_pr.state = "closed"
    closed_unmerged_pr.merged = False
    closed_unmerged_pr.number = 101
    closed_unmerged_pr.html_url = "https://github.com/test-owner/test-repo/pull/101"
    closed_unmerged_pr.head.ref = "scg/remediation-lodash-4.17.21"

    mock_repo.get_pulls.return_value = [closed_unmerged_pr]

    synthesizer = PullRequestSynthesizer("dummy_token", github_client=mock_gh)

    candidate = RemediationCandidate(
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

    success_sandbox = SandboxExecutionResult(
        outcome=RemediationOutcome.LOCKFILE_UPDATED,
        exit_code=0,
        modified_files=["package-lock.json"],
        duration_seconds=1.2,
    )

    result = synthesizer.publish_remediation_pr(
        repo_name="test-owner/test-repo",
        base_branch="main",
        expected_base_sha="base_sha_123",
        candidate=candidate,
        sandbox_res=success_sandbox,
        changed_contents={"package-lock.json": "{}"},
        score_before=Decimal("60.00"),
        score_after=Decimal("75.00"),
    )

    assert result.pr_created is False
    assert result.skipped_reason == "SUPPRESSED_BY_PRIOR_REJECTION"
    assert result.pr_number == 101
    mock_repo.create_pull.assert_not_called()


def test_base_branch_moved_aborts_pr():
    """Validates base alignment check aborts with BASE_BRANCH_MOVED if SHA mismatches."""
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    mock_gh.get_repo.return_value = mock_repo

    mock_ref = MagicMock()
    mock_ref.object.sha = "actual_remote_sha"
    mock_repo.get_git_ref.return_value = mock_ref

    synthesizer = PullRequestSynthesizer("dummy_token", github_client=mock_gh)

    candidate = RemediationCandidate(
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

    sandbox_res = SandboxExecutionResult(
        outcome=RemediationOutcome.LOCKFILE_UPDATED,
        exit_code=0,
        modified_files=["package-lock.json"],
        duration_seconds=1.0,
    )

    result = synthesizer.publish_remediation_pr(
        repo_name="org/repo",
        base_branch="main",
        expected_base_sha="stale_expected_sha",
        candidate=candidate,
        sandbox_res=sandbox_res,
        changed_contents={"package-lock.json": "{}"},
        score_before=Decimal("50.00"),
        score_after=Decimal("70.00"),
    )

    assert result.pr_created is False
    assert result.skipped_reason == "BASE_BRANCH_MOVED"
    mock_repo.create_git_commit.assert_not_called()


def test_major_breaking_guardrail():
    """Validates MAJOR_BREAKING candidates are skipped before any remote API calls."""
    mock_gh = MagicMock()
    synthesizer = PullRequestSynthesizer("dummy_token", github_client=mock_gh)

    candidate = RemediationCandidate(
        package_name="lodash",
        ecosystem=Ecosystem.NPM,
        current_version="3.10.1",
        target_version="4.17.21",
        classification=UpgradeSafetyClassification.MAJOR_BREAKING,
        strategy=RemediationStrategy.DIRECT_BUMP,
        manifest_mode=ManifestUpdateMode.RAISE_FLOOR,
        cves_resolved=["CVE-2021-23337"],
        is_direct=True,
        manifest_path="package.json",
    )

    sandbox_res = SandboxExecutionResult(
        outcome=RemediationOutcome.LOCKFILE_UPDATED,
        exit_code=0,
        duration_seconds=1.0,
    )

    result = synthesizer.publish_remediation_pr(
        repo_name="org/repo",
        base_branch="main",
        expected_base_sha="sha123",
        candidate=candidate,
        sandbox_res=sandbox_res,
        changed_contents={"package.json": "{}"},
        score_before=Decimal("40.00"),
        score_after=Decimal("80.00"),
    )

    assert result.pr_created is False
    assert "MAJOR_BREAKING" in (result.skipped_reason or "")
    mock_gh.get_repo.assert_not_called()


def test_successful_pr_publication():
    """Validates successful Git Data API branch, commit, and PR creation."""
    mock_gh = MagicMock()
    mock_repo = MagicMock()
    mock_gh.get_repo.return_value = mock_repo
    mock_repo.owner.login = "octocat"

    # Base ref matches
    mock_ref = MagicMock()
    mock_ref.object.sha = "base_sha_abc"
    mock_repo.get_git_ref.return_value = mock_ref

    # No existing PRs
    mock_repo.get_pulls.return_value = []

    # Commit and tree creation mocks
    mock_base_commit = MagicMock()
    mock_base_commit.tree = MagicMock()
    mock_repo.get_git_commit.return_value = mock_base_commit

    mock_new_tree = MagicMock()
    mock_repo.create_git_tree.return_value = mock_new_tree

    mock_new_commit = MagicMock()
    mock_new_commit.sha = "new_commit_sha_xyz"
    mock_repo.create_git_commit.return_value = mock_new_commit

    # Pull creation mock
    mock_pull = MagicMock()
    mock_pull.number = 42
    mock_pull.html_url = "https://github.com/octocat/repo/pull/42"
    mock_repo.create_pull.return_value = mock_pull

    synthesizer = PullRequestSynthesizer("dummy_token", github_client=mock_gh)

    candidate = RemediationCandidate(
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

    sandbox_res = SandboxExecutionResult(
        outcome=RemediationOutcome.LOCKFILE_UPDATED,
        exit_code=0,
        modified_files=["package.json", "package-lock.json"],
        duration_seconds=1.8,
    )

    result = synthesizer.publish_remediation_pr(
        repo_name="octocat/repo",
        base_branch="main",
        expected_base_sha="base_sha_abc",
        candidate=candidate,
        sandbox_res=sandbox_res,
        changed_contents={"package.json": "{}", "package-lock.json": "{}"},
        score_before=Decimal("65.25"),
        score_after=Decimal("85.50"),
    )

    assert result.pr_created is True
    assert result.pr_number == 42
    assert result.pr_url == "https://github.com/octocat/repo/pull/42"
    assert result.branch_name == "scg/remediation-semver-7.5.4"
    assert result.score_before == Decimal("65.25")
    assert result.score_after == Decimal("85.50")
    assert result.score_computation == ScoreComputationMode.RECOMPUTED

    # Verify Git Data API calls
    mock_repo.create_git_tree.assert_called_once()
    mock_repo.create_git_commit.assert_called_once()
    mock_repo.create_git_ref.assert_called_once_with(
        "refs/heads/scg/remediation-semver-7.5.4",
        sha="new_commit_sha_xyz",
    )

    # Verify create_pull call and body requirements
    mock_repo.create_pull.assert_called_once()
    call_kwargs = mock_repo.create_pull.call_args.kwargs
    assert "NO_AUTO_MERGE_INVARIANT" in call_kwargs["body"]
    assert "CVE-2022-25883" in call_kwargs["body"]
    assert "+20.25" in call_kwargs["body"]
    assert call_kwargs["head"] == "scg/remediation-semver-7.5.4"
    assert call_kwargs["base"] == "main"
