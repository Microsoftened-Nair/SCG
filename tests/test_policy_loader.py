"""Unit tests for PolicyLoader and PolicyParseError (SCG Phase 5 Track D)."""

from datetime import datetime, timezone, timedelta
from decimal import Decimal
import json
from pathlib import Path
import pytest

from scg_core.schemas.scoring import SCGPolicyConfig, SuppressionScope
from scg_core.scoring.policy_loader import PolicyLoader, PolicyParseError


def test_policy_parse_error_is_exception():
    """Validates REQ-P5-06: PolicyParseError is an Exception."""
    err = PolicyParseError("Fatal configuration error")
    assert isinstance(err, Exception)
    assert str(err) == "Fatal configuration error"


def test_load_policy_none():
    """Validates REQ-P5-07: repo_root=None returns default SCGPolicyConfig and empty warnings."""
    config, warnings = PolicyLoader.load_policy(None)
    assert isinstance(config, SCGPolicyConfig)
    assert warnings == []
    assert config.min_acceptable_score == Decimal("70.00")
    assert config.suppressions == []


def test_load_policy_file_not_found(tmp_path: Path):
    """Validates REQ-P5-07: missing .scgrc.json returns default SCGPolicyConfig and empty warnings."""
    config, warnings = PolicyLoader.load_policy(tmp_path)
    assert isinstance(config, SCGPolicyConfig)
    assert warnings == []
    assert config.min_acceptable_score == Decimal("70.00")


def test_load_policy_valid(tmp_path: Path):
    """Validates REQ-P5-07: reading and parsing valid .scgrc.json."""
    policy_file = tmp_path / PolicyLoader.POLICY_FILENAME
    content = {
        "schema_version": "1.0",
        "min_acceptable_score": "80.00",
        "weights": {
            "vuln": "0.50",
            "hygiene": "0.25",
            "behavior": "0.25",
        },
        "allowed_install_scripts": ["install-native"],
        "suppressions": [
            {
                "rule_id": "VULN-REACHABLE-CRIT",
                "scope": "PACKAGE",
                "target": "pkg:npm/lodash@4.17.20",
                "reason": "Compensating controls active in reverse proxy layer",
                "approved_by": "sec-ops@scg.io",
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            }
        ],
    }
    policy_file.write_text(json.dumps(content), encoding="utf-8")

    config, warnings = PolicyLoader.load_policy(tmp_path)
    assert config.min_acceptable_score == Decimal("80.00")
    assert config.allowed_install_scripts == ["install-native"]
    assert len(config.suppressions) == 1
    assert config.suppressions[0].rule_id == "VULN-REACHABLE-CRIT"
    assert config.suppressions[0].scope == SuppressionScope.PACKAGE
    assert warnings == []


def test_load_policy_suppression_expiry(tmp_path: Path):
    """Validates REQ-P5-07: expired suppressions are filtered into warnings."""
    policy_file = tmp_path / PolicyLoader.POLICY_FILENAME
    past_time = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    future_time = datetime.now(timezone.utc) + timedelta(days=90)

    content = {
        "schema_version": "1.0",
        "suppressions": [
            {
                "rule_id": "RULE-EXPIRED",
                "scope": "GLOBAL",
                "target": None,
                "reason": "Temporary waiver granted during incident response window",
                "approved_by": "ciso@scg.io",
                "expires_at": past_time.isoformat(),
            },
            {
                "rule_id": "RULE-ACTIVE",
                "scope": "PACKAGE",
                "target": "pkg:npm/debug@4.3.1",
                "reason": "AST reachability verified completely unreferenced in build",
                "approved_by": "sec-team@scg.io",
                "expires_at": future_time.isoformat(),
            },
        ],
    }
    policy_file.write_text(json.dumps(content), encoding="utf-8")

    config, warnings = PolicyLoader.load_policy(tmp_path)
    assert len(config.suppressions) == 1
    assert config.suppressions[0].rule_id == "RULE-ACTIVE"
    assert len(warnings) == 1
    expected_warning = f"EXPIRED_SUPPRESSION: Rule RULE-EXPIRED for target 'None' expired on {past_time}"
    assert warnings[0] == expected_warning


def test_load_policy_malformed_json(tmp_path: Path):
    """Validates REQ-P5-07: malformed JSON raises PolicyParseError."""
    policy_file = tmp_path / PolicyLoader.POLICY_FILENAME
    policy_file.write_text("{ \"schema_version\": \"1.0\", ", encoding="utf-8")

    with pytest.raises(PolicyParseError) as exc_info:
        PolicyLoader.load_policy(tmp_path)
    assert "Malformed JSON" in str(exc_info.value)


def test_load_policy_reason_too_short(tmp_path: Path):
    """Validates REQ-P5-07: reason < 20 chars raises PolicyParseError."""
    policy_file = tmp_path / PolicyLoader.POLICY_FILENAME
    content = {
        "schema_version": "1.0",
        "suppressions": [
            {
                "rule_id": "RULE-01",
                "scope": "GLOBAL",
                "reason": "short waiver",  # < 20 chars
                "approved_by": "admin",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ],
    }
    policy_file.write_text(json.dumps(content), encoding="utf-8")

    with pytest.raises(PolicyParseError) as exc_info:
        PolicyLoader.load_policy(tmp_path)
    assert "Schema validation failed" in str(exc_info.value)


def test_load_policy_forbidden_extra_fields(tmp_path: Path):
    """Validates REQ-P5-07: extra fields raise PolicyParseError due to extra='forbid'."""
    policy_file = tmp_path / PolicyLoader.POLICY_FILENAME
    content = {
        "schema_version": "1.0",
        "unauthorized_key": "malicious_override",
    }
    policy_file.write_text(json.dumps(content), encoding="utf-8")

    with pytest.raises(PolicyParseError) as exc_info:
        PolicyLoader.load_policy(tmp_path)
    assert "Schema validation failed" in str(exc_info.value)


def test_load_policy_directory_as_policy_file(tmp_path: Path):
    """Validates REQ-P5-07: directory named .scgrc.json raises PolicyParseError."""
    policy_dir = tmp_path / PolicyLoader.POLICY_FILENAME
    policy_dir.mkdir()

    with pytest.raises(PolicyParseError) as exc_info:
        PolicyLoader.load_policy(tmp_path)
    assert "is a directory" in str(exc_info.value)
