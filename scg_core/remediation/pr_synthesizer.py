"""Pull Request Synthesizer for Supply Chain Guardian Track E.

Publishes verified automated remediation pull requests via the GitHub Git Data API.
Enforces base SHA alignment, rejection retention (SUPPRESSED_BY_PRIOR_REJECTION),
idempotency, and the strict NO_AUTO_MERGE invariant.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
import sys
from typing import Any, Dict, Optional

# Ensure repository root is on sys.path when executed directly
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import github
from github import Github, InputGitTreeElement

from scg_core.schemas.remediation import (
    PullRequestResult,
    RemediationCandidate,
    RemediationOutcome,
    ScoreComputationMode,
    UpgradeSafetyClassification,
)


class PullRequestSynthesizer:
    """Synthesizes and publishes verified remediation pull requests using Git Data API."""

    MAX_PRS_PER_RUN: int = 5

    def __init__(
        self,
        installation_token: str,
        github_client: Optional[Github] = None,
    ) -> None:
        """Initialize the synthesizer with GitHub App or installation credentials."""
        if github_client is not None:
            self.gh = github_client
        else:
            try:
                auth = github.Auth.Token(installation_token)
                self.gh = Github(auth=auth)
            except Exception:
                self.gh = Github(installation_token)
        self._created_pr_count = 0

    @classmethod
    def format_branch_name(cls, candidate: RemediationCandidate) -> str:
        """Derives a deterministic git branch name for the remediation candidate."""
        clean_name = candidate.package_name.replace("/", "-").lstrip("@")
        return f"scg/remediation-{clean_name}-{candidate.target_version}"

    @classmethod
    def generate_pr_body(
        cls,
        candidate: RemediationCandidate,
        score_before: Decimal,
        score_after: Decimal,
    ) -> str:
        """Formats comprehensive PR description including score delta and NO_AUTO_MERGE notice."""
        delta = score_after - score_before
        delta_str = f"+{delta}" if delta > 0 else str(delta)

        cves_formatted = (
            "\n".join(f"- `{cve}`" for cve in candidate.cves_resolved)
            if candidate.cves_resolved
            else "- *No specific CVE identifiers referenced*"
        )

        eco_val = getattr(candidate.ecosystem, "value", str(candidate.ecosystem))
        strat_val = getattr(candidate.strategy, "value", str(candidate.strategy))
        mode_val = getattr(candidate.manifest_mode, "value", str(candidate.manifest_mode))
        safety_val = getattr(candidate.classification, "value", str(candidate.classification))

        return f"""## Supply Chain Guardian: Automated Remediation

Remediates `{candidate.package_name}` from `{candidate.current_version}` to `{candidate.target_version}`.

### Trust Score Impact
| Metric | Before | After | Delta |
| :--- | :--- | :--- | :--- |
| **Overall Project Trust Score** | {score_before:.2f} | {score_after:.2f} | **{delta_str}** |

### Resolved Vulnerabilities
{cves_formatted}

### Remediation Details
- **Package**: `{candidate.package_name}`
- **Ecosystem**: `{eco_val}`
- **Remediation Strategy**: `{strat_val}`
- **Manifest Mode**: `{mode_val}`
- **Safety Classification**: `{safety_val}`

---

### Safety & Compliance Notice (NO_AUTO_MERGE)
> [!IMPORTANT]
> **Automated merging is strictly prohibited by SCG policy (NO_AUTO_MERGE_INVARIANT).**
> Human review, approval, and CI gate passage are required prior to merging this pull request.
"""

    def publish_remediation_pr(
        self,
        repo_name: str,
        base_branch: str,
        expected_base_sha: str,
        candidate: RemediationCandidate,
        sandbox_res: Any,
        changed_contents: Dict[str, str],
        score_before: Decimal,
        score_after: Decimal,
    ) -> PullRequestResult:
        """Publishes a remediation pull request via GitHub Git Data API.

        Args:
            repo_name: Full repository name ('owner/repo').
            base_branch: Target base branch (e.g. 'main').
            expected_base_sha: Commit SHA of base_branch expected by orchestrator.
            candidate: Remediation proposal metadata.
            sandbox_res: Result of sandbox execution.
            changed_contents: Mapping of repository relative paths to updated file contents.
            score_before: Trust score prior to remediation.
            score_after: Recomputed trust score post-remediation.

        Returns:
            PullRequestResult with outcome, pr_number/url or skipped reason.
        """
        branch_name = self.format_branch_name(candidate)

        # 1. Guardrails
        if candidate.classification == UpgradeSafetyClassification.MAJOR_BREAKING:
            return PullRequestResult(
                pr_created=False,
                pr_number=None,
                pr_url=None,
                branch_name=branch_name,
                skipped_reason="MAJOR_BREAKING upgrades require manual intervention",
                score_before=score_before,
                score_after=score_after,
                score_computation=ScoreComputationMode.RECOMPUTED,
            )

        if sandbox_res.outcome in (
            RemediationOutcome.VERIFICATION_FAILED,
            RemediationOutcome.SANDBOX_ERROR,
            "VERIFICATION_FAILED",
            "SANDBOX_ERROR",
        ):
            outcome_val = getattr(sandbox_res.outcome, "value", str(sandbox_res.outcome))
            return PullRequestResult(
                pr_created=False,
                pr_number=None,
                pr_url=None,
                branch_name=branch_name,
                skipped_reason=f"Sandbox remediation unsuccessful: {outcome_val}",
                score_before=score_before,
                score_after=score_after,
                score_computation=ScoreComputationMode.RECOMPUTED,
            )

        if self._created_pr_count >= self.MAX_PRS_PER_RUN:
            return PullRequestResult(
                pr_created=False,
                pr_number=None,
                pr_url=None,
                branch_name=branch_name,
                skipped_reason=f"Maximum PR limit ({self.MAX_PRS_PER_RUN}) per run reached",
                score_before=score_before,
                score_after=score_after,
                score_computation=ScoreComputationMode.RECOMPUTED,
            )

        repo = self.gh.get_repo(repo_name)

        # 2. Base Alignment (P6-01)
        base_ref = repo.get_git_ref(f"heads/{base_branch}")
        current_base_sha = base_ref.object.sha
        if current_base_sha != expected_base_sha:
            return PullRequestResult(
                pr_created=False,
                pr_number=None,
                pr_url=None,
                branch_name=branch_name,
                skipped_reason="BASE_BRANCH_MOVED",
                score_before=score_before,
                score_after=score_after,
                score_computation=ScoreComputationMode.RECOMPUTED,
            )

        # 3. Idempotency Check (P6-09)
        owner_login = getattr(getattr(repo, "owner", None), "login", "")
        head_query = f"{owner_login}:{branch_name}" if owner_login else branch_name
        try:
            existing_prs = repo.get_pulls(state="all", head=head_query)
        except Exception:
            existing_prs = repo.get_pulls(state="all")

        for pr in existing_prs:
            # Match branch name if present
            pr_head_ref = getattr(getattr(pr, "head", None), "ref", None)
            if pr_head_ref and pr_head_ref != branch_name:
                continue

            if pr.state == "closed" and not getattr(pr, "merged", False):
                return PullRequestResult(
                    pr_created=False,
                    pr_number=getattr(pr, "number", None),
                    pr_url=getattr(pr, "html_url", None),
                    branch_name=branch_name,
                    skipped_reason="SUPPRESSED_BY_PRIOR_REJECTION",
                    score_before=score_before,
                    score_after=score_after,
                    score_computation=ScoreComputationMode.RECOMPUTED,
                )
            if pr.state == "open":
                return PullRequestResult(
                    pr_created=False,
                    pr_number=getattr(pr, "number", None),
                    pr_url=getattr(pr, "html_url", None),
                    branch_name=branch_name,
                    skipped_reason="Pull request already open",
                    score_before=score_before,
                    score_after=score_after,
                    score_computation=ScoreComputationMode.RECOMPUTED,
                )

        # 4. Git Data API Commit & Branch (P6-01)
        tree_elements = [
            InputGitTreeElement(
                path=file_path,
                mode="100644",
                type="blob",
                content=file_content,
            )
            for file_path, file_content in changed_contents.items()
        ]

        base_commit = repo.get_git_commit(current_base_sha)
        new_tree = repo.create_git_tree(tree_elements, base_tree=base_commit.tree)
        commit_msg = (
            f"fix(security): remediate {candidate.package_name} to {candidate.target_version}"
        )
        new_commit = repo.create_git_commit(
            message=commit_msg,
            tree=new_tree,
            parents=[base_commit],
        )

        ref_name = f"refs/heads/{branch_name}"
        try:
            repo.create_git_ref(ref_name, sha=new_commit.sha)
        except github.GithubException as ge:
            if ge.status == 422:
                # Fast-forward edit if branch ref exists; never force-push
                branch_ref = repo.get_git_ref(f"heads/{branch_name}")
                branch_ref.edit(sha=new_commit.sha, force=False)
            else:
                raise

        # 5. Create Pull Request
        pr_title = (
            f"fix(security): bump {candidate.package_name} "
            f"from {candidate.current_version} to {candidate.target_version}"
        )
        pr_body = self.generate_pr_body(candidate, score_before, score_after)

        pull = repo.create_pull(
            title=pr_title,
            body=pr_body,
            base=base_branch,
            head=branch_name,
        )

        self._created_pr_count += 1

        return PullRequestResult(
            pr_created=True,
            pr_number=pull.number,
            pr_url=pull.html_url,
            branch_name=branch_name,
            skipped_reason=None,
            score_before=score_before,
            score_after=score_after,
            score_computation=ScoreComputationMode.RECOMPUTED,
        )
