"""Level 5 Integration Tests for API Gateway, DB Models, and Health Probes.

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-10).
Validates:
- API-TC-01: Authentication enforcement (401/403) and strict tenant isolation (404 on cross-tenant access).
- PROBE-TC-01: Liveness (/healthz) strictly decoupled from readiness (/readyz) during database outages.
- API-TC-02: Deterministic ETag caching and 304 Not Modified responses on bounded graph retrieval.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from httpx import ASGITransport, AsyncClient
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from scg_core.api.main import app
from scg_core.db.models import (
    Base,
    Component,
    Principal,
    Repository,
    ScanComponent,
    ScanRun,
)
from scg_core.db.session import get_db_session
from scg_core.schemas.api import ScanStatus


@pytest_asyncio.fixture
async def async_test_engine():
    """Create an isolated in-memory SQLite database engine for testing."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield test_engine

    await test_engine.dispose()


@pytest_asyncio.fixture
async def session_factory(async_test_engine):
    """Provide an async session factory bound to the test database."""
    return async_sessionmaker(
        bind=async_test_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture
async def api_client(session_factory):
    """Provide an HTTPX AsyncClient configured with overridden database session."""
    async def _override_get_db_session():
        async with session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = _override_get_db_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def seeded_principals(session_factory):
    """Seed tenant A and tenant B principals in the test database."""
    principal_a = Principal(
        id=uuid.uuid4(),
        tenant_id="tenant-alpha",
        api_key_hash="token-secret-alpha",
        name="Tenant Alpha Principal",
        created_at=datetime.now(timezone.utc),
    )
    principal_b = Principal(
        id=uuid.uuid4(),
        tenant_id="tenant-beta",
        api_key_hash="token-secret-beta",
        name="Tenant Beta Principal",
        created_at=datetime.now(timezone.utc),
    )
    revoked_principal = Principal(
        id=uuid.uuid4(),
        tenant_id="tenant-gamma",
        api_key_hash="token-revoked-gamma",
        name="Revoked Principal",
        created_at=datetime.now(timezone.utc),
        revoked_at=datetime.now(timezone.utc),
    )

    async with session_factory() as session:
        session.add_all([principal_a, principal_b, revoked_principal])
        await session.commit()

    return {
        "alpha": principal_a,
        "beta": principal_b,
        "revoked": revoked_principal,
    }


@pytest.mark.asyncio
async def test_authentication_and_tenant_isolation(api_client, seeded_principals):
    """Reproduces API-TC-01:

    1. Assert unauthenticated requests return 401.
    2. Assert invalid/revoked tokens return 401.
    3. Assert authorized scan creation and status inquiry for tenant A.
    4. Assert foreign tenant B inquiry for tenant A scan returns 404 (never 403).
    """
    # 1. Unauthenticated request without Authorization header
    unauth_resp = await api_client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/acme/repo"},
    )
    assert unauth_resp.status_code == 401, f"Expected 401, got {unauth_resp.status_code}"

    # 2. Revoked token
    revoked_resp = await api_client.post(
        "/api/v1/scans",
        headers={"Authorization": "Bearer token-revoked-gamma"},
        json={"repository_url": "https://github.com/acme/repo"},
    )
    assert revoked_resp.status_code == 401
    assert "Invalid or revoked authorization credentials" in revoked_resp.json()["detail"]

    # 3. Valid authenticated request for Tenant Alpha
    auth_header_a = {"Authorization": "Bearer token-secret-alpha"}
    create_resp = await api_client.post(
        "/api/v1/scans",
        headers=auth_header_a,
        json={"repository_url": "https://github.com/acme/repo", "branch": "main"},
    )
    assert create_resp.status_code == 202
    create_data = create_resp.json()
    assert "scan_id" in create_data
    scan_id_str = create_data["scan_id"]
    assert create_data["status"] == "QUEUED"
    assert create_data["poll_url"] == f"/api/v1/scans/{scan_id_str}"

    # Verify Tenant Alpha can query their own scan
    get_resp_a = await api_client.get(
        f"/api/v1/scans/{scan_id_str}",
        headers=auth_header_a,
    )
    assert get_resp_a.status_code == 200
    assert get_resp_a.json()["scan_id"] == scan_id_str
    assert get_resp_a.json()["status"] == "QUEUED"

    # 4. Strict Tenant Isolation (P7-01): Tenant Beta queries Tenant Alpha's scan
    auth_header_b = {"Authorization": "Bearer token-secret-beta"}
    get_resp_b = await api_client.get(
        f"/api/v1/scans/{scan_id_str}",
        headers=auth_header_b,
    )
    assert get_resp_b.status_code == 404, "Cross-tenant access MUST return 404, never 403"
    assert get_resp_b.json()["detail"] == "Scan run not found"


@pytest.mark.asyncio
async def test_probes_liveness_readiness_isolation(api_client):
    """Reproduces PROBE-TC-01:

    1. Liveness (/healthz) returns 200 immediately.
    2. Readiness (/readyz) returns 200 when backing DB and Redis are responsive.
    3. During a simulated DB outage, /healthz remains 200 while /readyz returns 503.
    """
    # 1. Baseline Liveness probe
    health_resp = await api_client.get("/healthz")
    assert health_resp.status_code == 200
    assert health_resp.json() == {"status": "ok"}

    # 2. Healthy Readiness probe
    mock_engine_healthy = MagicMock()
    mock_conn = MagicMock()
    mock_conn.__aenter__.return_value.execute = AsyncMock()
    mock_conn.__aexit__ = AsyncMock()
    mock_engine_healthy.connect.return_value = mock_conn

    with patch("scg_core.api.probes.engine", mock_engine_healthy), \
         patch("redis.asyncio.client.Redis.ping", new_callable=AsyncMock, return_value=True), \
         patch("redis.asyncio.client.Redis.aclose", new_callable=AsyncMock):

        ready_resp = await api_client.get("/readyz")
        assert ready_resp.status_code == 200
        assert ready_resp.json() == {
            "status": "ready",
            "database": "ok",
            "redis": "ok",
        }

    # 3. Simulate DB Outage: Liveness MUST still pass (200), Readiness MUST fail (503)
    mock_engine_outage = MagicMock()
    mock_engine_outage.connect.side_effect = ConnectionError("Database offline")

    with patch("scg_core.api.probes.engine", mock_engine_outage), \
         patch("redis.asyncio.client.Redis.ping", new_callable=AsyncMock, return_value=True), \
         patch("redis.asyncio.client.Redis.aclose", new_callable=AsyncMock):

        # Decoupled invariant check: /healthz NEVER touches DB (P7-11)
        health_outage_resp = await api_client.get("/healthz")
        assert health_outage_resp.status_code == 200
        assert health_outage_resp.json() == {"status": "ok"}

        # Readiness fails with 503
        ready_outage_resp = await api_client.get("/readyz")
        assert ready_outage_resp.status_code == 503
        assert ready_outage_resp.json() == {
            "status": "unready",
            "database": "unreachable",
            "redis": "ok",
        }


@pytest.mark.asyncio
async def test_graph_caching_etag(api_client, session_factory, seeded_principals):
    """Validates API-TC-02:

    1. If scan is not COMPLETED, /graph returns 400.
    2. Completed scan returns BoundedGraphResponse with ETag and Cache-Control headers.
    3. Conditional request with matching If-None-Match header returns 304 Not Modified.
    """
    auth_header = {"Authorization": "Bearer token-secret-alpha"}
    scan_id = uuid.uuid4()
    repo_id = uuid.uuid4()
    comp_id = uuid.uuid4()

    # 1. Create a non-completed scan in QUEUED state
    async with session_factory() as session:
        repo = Repository(
            id=repo_id,
            tenant_id="tenant-alpha",
            url="https://github.com/acme/graph-repo",
            default_branch="main",
        )
        scan = ScanRun(
            id=scan_id,
            tenant_id="tenant-alpha",
            repository_id=repo_id,
            commit_sha="a" * 40,
            status=ScanStatus.QUEUED.value,
        )
        session.add_all([repo, scan])
        await session.commit()

    uncompleted_resp = await api_client.get(
        f"/api/v1/scans/{scan_id}/graph",
        headers=auth_header,
    )
    assert uncompleted_resp.status_code == 400
    assert "Scan analysis has not completed" in uncompleted_resp.json()["detail"]

    # 2. Update scan to COMPLETED and seed component
    now_utc = datetime.now(timezone.utc)
    async with session_factory() as session:
        active_scan = await session.get(ScanRun, scan_id)
        active_scan.status = ScanStatus.COMPLETED.value
        active_scan.completed_at = now_utc

        comp = Component(
            id=comp_id,
            purl="pkg:npm/lodash@4.17.21",
            ecosystem="npm",
            package_name="lodash",
            version="4.17.21",
        )
        sc = ScanComponent(
            id=uuid.uuid4(),
            scan_id=scan_id,
            component_id=comp_id,
            graph_depth=1,
            is_direct=True,
            reachability_status="DIRECT_IMPORTED",
            exposure_factor=1.0,
            composite_score=55.0,
            score_confidence=0.9,
            score_deductions={"CVE-2021-23337": -15.0},
        )
        session.add_all([comp, sc])
        await session.commit()

    # Fetch graph
    graph_resp = await api_client.get(
        f"/api/v1/scans/{scan_id}/graph",
        headers=auth_header,
    )
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert graph_data["scan_id"] == str(scan_id)
    assert graph_data["total_nodes"] == 1
    assert graph_data["truncated"] is False
    assert len(graph_data["nodes"]) == 1
    assert graph_data["nodes"][0]["package_name"] == "lodash"
    assert graph_data["nodes"][0]["risk_tier"] == "HIGH"

    etag = graph_resp.headers.get("ETag")
    assert etag is not None, "ETag header missing from response"
    assert graph_resp.headers.get("Cache-Control") == "public, max-age=31536000, immutable"

    # 3. Conditional GET with If-None-Match ETag check (P7-09)
    cached_resp = await api_client.get(
        f"/api/v1/scans/{scan_id}/graph",
        headers={**auth_header, "If-None-Match": etag},
    )
    assert cached_resp.status_code == 304, f"Expected 304 Not Modified, got {cached_resp.status_code}"
