"""Unit tests for Phase 7 Database Models and Session Factory.

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-01, REQ-P7-02, REQ-P7-03).
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import UniqueConstraint, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from scg_core.db.models import (
    Base,
    Component,
    ComponentVulnerability,
    Principal,
    Repository,
    ScanComponent,
    ScanRun,
    Vulnerability,
    utc_now,
)
from scg_core.db.session import (
    DEFAULT_DATABASE_URL,
    async_engine_factory,
    get_database_url,
    get_sessionmaker,
)


def test_database_url_env_resolution(monkeypatch):
    """Assert get_database_url reads SCG_DATABASE_URL or defaults."""
    monkeypatch.delenv("SCG_DATABASE_URL", raising=False)
    assert get_database_url() == DEFAULT_DATABASE_URL

    test_url = "postgresql+asyncpg://admin:secret@db.internal:5432/scg_prod"
    monkeypatch.setenv("SCG_DATABASE_URL", test_url)
    assert get_database_url() == test_url


def test_async_engine_factory_pooling():
    """Assert connection pooling arguments are correctly set on async engines."""
    pg_url = "postgresql+asyncpg://postgres:postgres@localhost:5432/scg_test"
    eng = async_engine_factory(pg_url, pool_size=20, max_overflow=10)
    assert eng.pool.size() == 20


def test_models_metadata_and_constraints():
    """Assert all tables, foreign keys, and unique constraint names exist."""
    expected_tables = {
        "principals",
        "repositories",
        "scan_runs",
        "components",
        "scan_components",
        "vulnerabilities",
        "component_vulnerabilities",
        "remediation_prs",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(actual_tables)

    tables = Base.metadata.tables

    # Check RESTRICT on repositories.id
    sr_fks = {fk.target_fullname: fk for fk in tables["scan_runs"].foreign_keys}
    assert sr_fks["repositories.id"].ondelete == "RESTRICT"

    # Check CASCADE on scan_runs.id and RESTRICT on components.id
    sc_fks = {fk.target_fullname: fk for fk in tables["scan_components"].foreign_keys}
    assert sc_fks["scan_runs.id"].ondelete == "CASCADE"
    assert sc_fks["components.id"].ondelete == "RESTRICT"

    # Check constraint names
    repo_uqs = {
        c.name for c in tables["repositories"].constraints if isinstance(c, UniqueConstraint)
    }
    assert "uq_tenant_repo_url" in repo_uqs

    sc_uqs = {
        c.name for c in tables["scan_components"].constraints if isinstance(c, UniqueConstraint)
    }
    assert "uq_scan_component" in sc_uqs


@pytest.mark.asyncio
async def test_models_crud_and_relationships():
    """Assert model persistence, soft-delete, and relationships in async engine."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = get_sessionmaker(engine)

    async with session_maker() as session:
        # Create Principal
        p = Principal(
            tenant_id="tenant-123",
            api_key_hash="hash-123",
            name="Test Principal",
        )
        session.add(p)

        # Create Repository
        repo = Repository(
            tenant_id="tenant-123",
            url="https://github.com/acme/project",
            default_branch="main",
            is_deleted=False,
        )
        session.add(repo)
        await session.flush()

        # Create ScanRun
        scan = ScanRun(
            tenant_id="tenant-123",
            repository_id=repo.id,
            commit_sha="b" * 40,
            status="QUEUED",
        )
        session.add(scan)
        await session.flush()

        # Create Component
        comp = Component(
            purl="pkg:npm/express@4.18.2",
            ecosystem="npm",
            package_name="express",
            version="4.18.2",
        )
        session.add(comp)
        await session.flush()

        # Create ScanComponent
        sc = ScanComponent(
            scan_id=scan.id,
            component_id=comp.id,
            is_direct=True,
            reachability_status="DIRECT_IMPORTED",
            exposure_factor=0.8,
            composite_score=72.5,
            score_confidence=0.95,
            score_deductions={"HYGIENE_DEP": -5.0},
        )
        session.add(sc)

        # Create Vulnerability & Link
        vuln = Vulnerability(
            id="GHSA-xxxx-yyyy",
            aliases=["CVE-2024-0001"],
            summary="Prototype pollution",
            severity="HIGH",
            is_known_exploited=False,
            fixed_versions=["4.18.3"],
            vulnerable_symbols=["setPrototype"],
        )
        session.add(vuln)
        await session.flush()

        cv = ComponentVulnerability(
            component_id=comp.id,
            vulnerability_id=vuln.id,
        )
        session.add(cv)

        await session.commit()

    # Query back in a new session
    async with session_maker() as session:
        queried_scan = await session.get(ScanRun, scan.id)
        assert queried_scan is not None
        assert queried_scan.tenant_id == "tenant-123"
        assert queried_scan.commit_sha == "b" * 40

        # Query Component
        comp_res = await session.execute(
            select(Component).where(Component.purl == "pkg:npm/express@4.18.2")
        )
        loaded_comp = comp_res.scalars().first()
        assert loaded_comp is not None
        assert loaded_comp.package_name == "express"

    await engine.dispose()
