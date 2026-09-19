"""Canonical serialization mapping layer for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-1-2026-REV-2.1 (Section 7.8).
Decouples the wire contract RepositoryScanReport from relational database persistence
by providing bidirectional translations for SQLAlchemy or SQLite storage engines.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from scg_core.exceptions import TenantIsolationError
from scg_core.schemas.base import (
    DependencyNode,
    RepositoryScanReport,
    TrustScoreBreakdown,
)


def report_to_db_record(report: RepositoryScanReport) -> Dict[str, Any]:
    """Converts a RepositoryScanReport into a flat relational dictionary representation.

    Translates the domain model into a representation suitable for the scan_reports table,
    enforcing tenant isolation and serializing nested dependencies and trust breakdowns.

    Args:
        report: Validated RepositoryScanReport instance.

    Returns:
        Dictionary mapping column names to serializable SQL/JSON datatypes.

    Raises:
        TenantIsolationError: If tenant_id is empty, whitespace-only, or missing.
    """
    if not report.tenant_id or not report.tenant_id.strip():
        raise TenantIsolationError(
            message="Tenant ID cannot be missing or empty for database mapping.",
            tenant_id=report.tenant_id,
            details={"violation": "EMPTY_OR_BLANK_TENANT_ID"},
        )

    # Format scanned_at as ISO-8601 UTC string
    scanned_at_iso = report.scanned_at.isoformat()

    # Serialize nested dependencies into JSON-compatible list of dicts
    dependencies_json = [dep.model_dump(mode="json") for dep in report.dependencies]

    # Serialize summary_breakdown into JSON-compatible dict
    summary_breakdown_json = report.summary_breakdown.model_dump(mode="json")

    return {
        "scan_id": report.scan_id,
        "tenant_id": report.tenant_id,
        "repository_url": report.repository_url,
        "commit_hash": report.commit_hash,
        "scanned_at": scanned_at_iso,
        "overall_trust_score": report.overall_trust_score,
        "dependency_count": report.dependency_count,
        "vulnerable_dependency_count": report.vulnerable_dependency_count,
        "dependencies": dependencies_json,
        "summary_breakdown": summary_breakdown_json,
    }


def db_record_to_report(record: Dict[str, Any]) -> RepositoryScanReport:
    """Reconstructs and validates a full RepositoryScanReport from a relational database record.

    Performs inverse mapping from the scan_reports table, restoring nested dependency trees
    and ensuring ISO-8601 strings are validated as timezone-aware UTC datetimes.

    Args:
        record: Dictionary containing relational fields from the database.

    Returns:
        Fully reconstructed and validated RepositoryScanReport instance.

    Raises:
        TenantIsolationError: If the database record contains a missing or empty tenant_id.
    """
    tenant_id = record.get("tenant_id")
    if not tenant_id or not str(tenant_id).strip():
        raise TenantIsolationError(
            message="Database record missing required tenant_id for tenant isolation.",
            tenant_id=str(tenant_id) if tenant_id is not None else None,
            details={"violation": "MISSING_RECORD_TENANT_ID"},
        )

    record_data = dict(record)

    # Ensure ISO-8601 timestamps are parsed into timezone-aware UTC datetimes
    scanned_at_val = record_data.get("scanned_at")
    if isinstance(scanned_at_val, str):
        dt = datetime.fromisoformat(scanned_at_val)
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        record_data["scanned_at"] = dt.astimezone(timezone.utc)

    return RepositoryScanReport.model_validate(record_data)


if __name__ == "__main__":
    from uuid import uuid4
    from scg_core.schemas.base import (
        CvssSource,
        Ecosystem,
        PackageHealthData,
        ReachabilityStatus,
        SeverityLevel,
        VersionParseStatus,
        VulnerabilityRecord,
    )

    print("Executing verification harness for scg_core/db/mappers.py (SRS Rev 2.1)...")

    # 1. Create a dummy RepositoryScanReport with 1 dependency node
    dummy_health = PackageHealthData(
        published_date=datetime(2024, 1, 10, 0, 0, 0, tzinfo=timezone.utc),
        last_registry_activity=datetime(2024, 2, 1, 12, 0, 0, tzinfo=timezone.utc),
        maintainer_count=4,
        weekly_downloads=1250000,
        has_install_scripts=False,
        openssf_scorecard_score=8.5,
        is_deprecated=False,
    )

    dummy_vuln = VulnerabilityRecord(
        id="GHSA-mapper-test-001",
        aliases=["CVE-2024-9999"],
        summary="Command injection vulnerability in CLI parsing",
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_source=CvssSource.PUBLISHED_VECTOR,
        severity=SeverityLevel.HIGH,
        epss_score=0.45,
        epss_percentile=0.88,
        is_known_exploited=False,
        published=datetime(2024, 1, 15, 8, 30, 0, tzinfo=timezone.utc),
        withdrawn=None,
        fixed_versions=["2.0.1"],
        vulnerable_version_ranges=["< 2.0.1"],
        vulnerable_symbols=["parseCliArgs"],
    )

    dummy_dep = DependencyNode(
        package_name="cli-utils",
        ecosystem=Ecosystem.NPM,
        resolved_version="2.0.0",
        version_parse_status=VersionParseStatus.PARSED,
        is_direct=True,
        graph_depth=1,
        declared_range="^2.0.0",
        reachability=ReachabilityStatus.DIRECT_IMPORTED,
        vulnerabilities=[dummy_vuln],
        health=dummy_health,
    )

    dummy_breakdown = TrustScoreBreakdown(
        vulnerability_facet=65.0,
        hygiene_facet=85.0,
        behavior_facet=90.0,
        composite_score=76.25,
        deductions={"HIGH_VULN_DIRECT": -20.0},
    )

    dummy_report = RepositoryScanReport(
        scan_id=str(uuid4()),
        tenant_id="tenant-acme-corp",
        repository_url="https://github.com/acme/supply-chain-app",
        commit_hash="1234567890abcdef1234567890abcdef12345678",
        scanned_at=datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc),
        overall_trust_score=76.25,
        dependency_count=1,
        vulnerable_dependency_count=1,
        dependencies=[dummy_dep],
        summary_breakdown=dummy_breakdown,
    )

    # 2. Invoke record = report_to_db_record(report)
    db_record = report_to_db_record(dummy_report)

    # 3. Assert record["tenant_id"] == report.tenant_id
    assert db_record["tenant_id"] == dummy_report.tenant_id, "Tenant ID was not preserved in DB record"
    assert isinstance(db_record["dependencies"], list), "Dependencies must be a serialized list"
    assert isinstance(db_record["summary_breakdown"], dict), "Summary breakdown must be a serialized dict"
    assert isinstance(db_record["scanned_at"], str), "scanned_at must be an ISO-8601 formatted string"
    print("✓ [1/4] report_to_db_record correctly serialized fields and preserved tenant_id.")

    # 4. Invoke restored = db_record_to_report(record)
    restored_report = db_record_to_report(db_record)

    # 5. Assert restored == report (verifying lossless round-trip fidelity)
    assert restored_report == dummy_report, "Lossless round-trip fidelity check failed"
    print("✓ [2/4] db_record_to_report restored the exact RepositoryScanReport instance.")

    # 6. Verify that passing an empty tenant_id="" raises TenantIsolationError
    empty_tenant_report = RepositoryScanReport(
        scan_id=str(uuid4()),
        tenant_id="",  # Empty tenant ID
        repository_url="https://github.com/acme/supply-chain-app",
        commit_hash="1234567890abcdef1234567890abcdef12345678",
        scanned_at=datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc),
        overall_trust_score=76.25,
        dependency_count=1,
        vulnerable_dependency_count=1,
        dependencies=[dummy_dep],
        summary_breakdown=dummy_breakdown,
    )

    try:
        report_to_db_record(empty_tenant_report)
        raise AssertionError("Failed to raise TenantIsolationError for empty tenant_id in report_to_db_record")
    except TenantIsolationError:
        print("✓ [3/4] Empty tenant_id in report correctly raised TenantIsolationError.")

    try:
        invalid_record = dict(db_record)
        invalid_record["tenant_id"] = "   "  # Whitespace-only tenant ID
        db_record_to_report(invalid_record)
        raise AssertionError("Failed to raise TenantIsolationError for blank tenant_id in db_record_to_report")
    except TenantIsolationError:
        print("✓ [4/4] Blank tenant_id in DB record correctly raised TenantIsolationError.")

    # 7. Print success output
    print("PHASE 1 REV 2.1 DB MAPPERS VALIDATION: SUCCESS")
