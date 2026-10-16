"""Repository-level policy loader and suppression validator for Supply Chain Guardian (SCG).

Enforces RFC 2119 and SCG Phase 5 governance rules:
Malformed .scgrc.json policy files MUST NOT silently fall back to default configurations;
they MUST raise a fatal PolicyParseError. Active suppressions are validated against current
UTC timestamps, and expired suppressions are logged and excluded.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Optional, Tuple, Union

from pydantic import ValidationError

from scg_core.schemas.scoring import SCGPolicyConfig, Suppression


class PolicyParseError(Exception):
    """Raised when .scgrc.json is unparseable or fails schema validation."""


class PolicyLoader:
    """Loads and validates repository-level governance policies from .scgrc.json."""

    POLICY_FILENAME: str = ".scgrc.json"

    @classmethod
    def load_policy(
        cls,
        repo_root: Optional[Union[Path, str]] = None,
    ) -> Tuple[SCGPolicyConfig, List[str]]:
        """Loads and parses the repository policy file, filtering expired suppressions.

        Args:
            repo_root: Directory path containing .scgrc.json, or None.

        Returns:
            Tuple of (effective SCGPolicyConfig with active suppressions, list of warnings).

        Raises:
            PolicyParseError: If .scgrc.json exists but contains invalid JSON or violates the policy schema.
        """
        if repo_root is None:
            return SCGPolicyConfig(), []

        root_path = Path(repo_root)
        policy_path = root_path / cls.POLICY_FILENAME

        if not policy_path.exists():
            return SCGPolicyConfig(), []

        if policy_path.is_dir():
            raise PolicyParseError(
                f"Policy path '{policy_path}' is a directory, expected a file."
            )

        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as exc:
            raise PolicyParseError(
                f"Failed to read policy configuration at '{policy_path}': {exc}"
            ) from exc

        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise PolicyParseError(
                f"Malformed JSON in policy file '{policy_path}': {exc}"
            ) from exc

        try:
            config = SCGPolicyConfig.model_validate(raw_data)
        except (ValidationError, ValueError) as exc:
            raise PolicyParseError(
                f"Schema validation failed for policy file '{policy_path}': {exc}"
            ) from exc

        # Suppression Evaluation
        now = datetime.now(timezone.utc)
        active_suppressions: List[Suppression] = []
        warnings: List[str] = []

        for supp in config.suppressions:
            if supp.expires_at <= now:
                warnings.append(
                    f"EXPIRED_SUPPRESSION: Rule {supp.rule_id} for target '{supp.target}' expired on {supp.expires_at}"
                )
            else:
                active_suppressions.append(supp)

        effective_config = config.model_copy(update={"suppressions": active_suppressions})
        return effective_config, warnings


if __name__ == "__main__":
    import tempfile
    from decimal import Decimal

    print("Running self-test for scg_core.scoring.policy_loader...")

    # 1. Loading from None returns default policy without warnings
    default_policy, default_warnings = PolicyLoader.load_policy(None)
    assert isinstance(default_policy, SCGPolicyConfig)
    assert default_warnings == []
    assert default_policy.min_acceptable_score == Decimal("70.00")
    assert len(default_policy.suppressions) == 0
    print("✓ 1. Loading from None returns default policy without warnings.")

    # 2. Valid .scgrc.json parses correctly
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        valid_policy = {
            "schema_version": "1.0",
            "min_acceptable_score": "85.00",
            "weights": {
                "vuln": "0.60",
                "hygiene": "0.20",
                "behavior": "0.20",
            },
            "allowed_install_scripts": ["build"],
            "suppressions": [
                {
                    "rule_id": "RULE-ACTIVE-01",
                    "scope": "PACKAGE",
                    "target": "pkg:npm/lodash@4.17.20",
                    "reason": "Compensating security controls active in API gateway",
                    "approved_by": "security-lead@scg.io",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ],
        }
        (dir_path / PolicyLoader.POLICY_FILENAME).write_text(json.dumps(valid_policy), encoding="utf-8")

        parsed_policy, warnings = PolicyLoader.load_policy(dir_path)
        assert parsed_policy.min_acceptable_score == Decimal("85.00")
        assert parsed_policy.weights.vuln == Decimal("0.6000")
        assert len(parsed_policy.suppressions) == 1
        assert parsed_policy.suppressions[0].rule_id == "RULE-ACTIVE-01"
        assert warnings == []
        print("✓ 2. Valid .scgrc.json parses correctly.")

    # 3. Expired suppressions are filtered into the warnings list
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        policy_with_expired = {
            "schema_version": "1.0",
            "suppressions": [
                {
                    "rule_id": "RULE-EXPIRED-01",
                    "scope": "GLOBAL",
                    "target": None,
                    "reason": "Temporary waiver during infrastructure migration phase",
                    "approved_by": "ciso@scg.io",
                    "expires_at": "2020-01-01T00:00:00Z",
                },
                {
                    "rule_id": "RULE-ACTIVE-02",
                    "scope": "ADVISORY",
                    "target": "GHSA-xxxx-yyyy",
                    "reason": "Downstream runtime path verified completely unreachable",
                    "approved_by": "analyst@scg.io",
                    "expires_at": "2099-01-01T00:00:00Z",
                },
            ],
        }
        (dir_path / PolicyLoader.POLICY_FILENAME).write_text(json.dumps(policy_with_expired), encoding="utf-8")

        parsed_policy, warnings = PolicyLoader.load_policy(dir_path)
        assert len(parsed_policy.suppressions) == 1
        assert parsed_policy.suppressions[0].rule_id == "RULE-ACTIVE-02"
        assert len(warnings) == 1
        assert "EXPIRED_SUPPRESSION: Rule RULE-EXPIRED-01 for target 'None' expired on 2020-01-01 00:00:00+00:00" in warnings[0]
        print("✓ 3. Expired suppressions are filtered into the warnings list.")

    # 4. Invalid JSON or schema breaches (e.g. reason < 20 chars) raise PolicyParseError
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        (dir_path / PolicyLoader.POLICY_FILENAME).write_text("{ malformed: json ", encoding="utf-8")

        try:
            PolicyLoader.load_policy(dir_path)
            raise AssertionError("Failed to raise PolicyParseError on malformed JSON")
        except PolicyParseError as exc:
            assert "Malformed JSON" in str(exc)
        print("✓ 4a. Malformed JSON raises PolicyParseError.")

    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        schema_breach_policy = {
            "schema_version": "1.0",
            "suppressions": [
                {
                    "rule_id": "RULE-BAD-01",
                    "scope": "GLOBAL",
                    "reason": "Too short",  # < 20 chars
                    "approved_by": "sec",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ],
        }
        (dir_path / PolicyLoader.POLICY_FILENAME).write_text(json.dumps(schema_breach_policy), encoding="utf-8")

        try:
            PolicyLoader.load_policy(dir_path)
            raise AssertionError("Failed to raise PolicyParseError on schema breach (reason < 20 chars)")
        except PolicyParseError as exc:
            assert "Schema validation failed" in str(exc)
        print("✓ 4b. Schema breach (reason < 20 chars) raises PolicyParseError.")

    print("\nAll self-test assertions in policy_loader passed successfully!")
