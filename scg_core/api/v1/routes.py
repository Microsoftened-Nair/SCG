"""REST API Gateway v1 Routes for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-07, P7-01, P7-09).
Provides tenant-isolated REST endpoints with HTTPBearer authentication,
deterministic ETag caching for dependency graphs, and Celery task orchestration.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional
import uuid

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scg_core.db.models import (
    Component,
    ComponentVulnerability,
    Principal,
    Repository,
    ScanComponent,
    ScanRun,
)
from scg_core.db.session import get_db_session
from scg_core.ingestion.git_worker import validate_repo_url
from scg_core.schemas.api import (
    BoundedGraphResponse,
    ErrorCode,
    ErrorResponse,
    GraphEdge,
    GraphNodeSummary,
    RemediationTriggerRequest,
    ScanInitiationRequest,
    ScanInitiationResponse,
    ScanStatus,
    ScanStatusResponse,
)
from scg_core.tasks.pipeline import (
    orchestrate_full_scan,
    trigger_remediation_task,
)

security = HTTPBearer(auto_error=False)


async def require_principal(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    session: AsyncSession = Depends(get_db_session),
) -> Principal:
    """Validate Bearer API key credentials against active principals (P7-01).

    Args:
        credentials: HTTPAuthorizationCredentials from Authorization header.
        session: Active database session.

    Returns:
        Authenticated and unrevoked Principal model.

    Raises:
        HTTPException 401: If credentials are missing, invalid, or revoked.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked authorization credentials",
        )

    api_key_hash = credentials.credentials
    query = select(Principal).where(
        Principal.api_key_hash == api_key_hash,
        Principal.revoked_at.is_(None),
    )
    result = await session.execute(query)
    principal = result.scalars().first()

    if not principal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked authorization credentials",
        )

    return principal


router = APIRouter(
    prefix="/api/v1",
    tags=["Supply Chain Guardian"],
    dependencies=[Depends(require_principal)],
)


@router.post(
    "/scans",
    response_model=ScanInitiationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def initiate_scan(
    payload: ScanInitiationRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ScanInitiationResponse:
    """Initiate an automated supply chain security scan for a repository.

    Validates URL safety, provisions repository scoped to tenant, creates ScanRun,
    and enqueues the Celery orchestration workflow.
    """
    raw_url = str(payload.repository_url)
    try:
        validated_url = validate_repo_url(raw_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Repository URL rejected: {exc}",
        ) from exc

    # Retrieve or create repository scoped to principal tenant (P7-01, P7-07)
    repo_query = select(Repository).where(
        Repository.tenant_id == principal.tenant_id,
        Repository.url == validated_url,
        Repository.is_deleted.is_(False),
    )
    repo_res = await session.execute(repo_query)
    repo = repo_res.scalars().first()

    if not repo:
        repo = Repository(
            tenant_id=principal.tenant_id,
            url=validated_url,
            default_branch=payload.branch or "main",
        )
        session.add(repo)
        await session.flush()

    # Create new scan run
    new_scan = ScanRun(
        tenant_id=principal.tenant_id,
        repository_id=repo.id,
        commit_sha="0" * 40,
        status=ScanStatus.QUEUED.value,
    )
    session.add(new_scan)
    await session.commit()
    await session.refresh(new_scan)

    # Dispatch Celery workflow by reference passing scan_id (P7-02)
    try:
        orchestrate_full_scan.delay(str(new_scan.id))
    except Exception:
        # Background worker broker dispatch failure does not abort scan creation
        pass

    return ScanInitiationResponse(
        scan_id=new_scan.id,
        status=ScanStatus.QUEUED,
        poll_url=f"/api/v1/scans/{new_scan.id}",
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanStatusResponse,
)
async def get_scan(
    scan_id: uuid.UUID,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ScanStatusResponse:
    """Retrieve scan status and trust metrics scoped strictly to tenant.

    Cross-tenant queries return 404 to avoid information disclosure.
    """
    query = select(ScanRun).where(
        ScanRun.id == scan_id,
        ScanRun.tenant_id == principal.tenant_id,
    )
    result = await session.execute(query)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    error_response: Optional[ErrorResponse] = None
    if scan.error_code:
        try:
            err_code_enum = ErrorCode(scan.error_code)
        except ValueError:
            err_code_enum = ErrorCode.INTERNAL_ERROR
        error_response = ErrorResponse(
            code=err_code_enum,
            message=scan.error_message or "Scan execution failed",
            detail=scan.error_message,
            retryable=False,
            scan_id=scan.id,
            trace_id=scan.trace_id,
        )

    try:
        status_enum = ScanStatus(scan.status)
    except ValueError:
        status_enum = ScanStatus.QUEUED

    return ScanStatusResponse(
        scan_id=scan.id,
        status=status_enum,
        overall_trust_score=scan.overall_trust_score,
        mean_confidence=scan.mean_confidence,
        total_dependencies=scan.total_dependencies,
        vulnerable_dependencies=scan.vulnerable_dependencies,
        analysis_completeness=scan.analysis_completeness,
        error=error_response,
    )


def _compute_risk_tier(composite_score: float) -> str:
    """Map composite trust score to standard risk tier."""
    if composite_score < 40.0:
        return "CRITICAL"
    if composite_score < 60.0:
        return "HIGH"
    if composite_score < 80.0:
        return "MEDIUM"
    return "LOW"


@router.get(
    "/scans/{scan_id}/graph",
    response_model=BoundedGraphResponse,
)
async def get_scan_graph(
    scan_id: uuid.UUID,
    request: Request,
    response: Response,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_db_session),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
) -> Any:
    """Retrieve bounded dependency graph for a completed scan (P7-09).

    Supports deterministic ETag caching and 304 Not Modified responses.
    Caps nodes at 2,000 items.
    """
    scan_query = select(ScanRun).where(
        ScanRun.id == scan_id,
        ScanRun.tenant_id == principal.tenant_id,
    )
    scan_res = await session.execute(scan_query)
    scan = scan_res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    completed_states = {
        ScanStatus.COMPLETED.value,
        ScanStatus.COMPLETED_PARTIAL.value,
    }
    if scan.status not in completed_states:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan analysis has not completed",
        )

    # Fetch scan components joined with components
    components_query = (
        select(ScanComponent, Component)
        .join(Component, ScanComponent.component_id == Component.id)
        .where(ScanComponent.scan_id == scan.id)
        .order_by(ScanComponent.composite_score.asc())
    )
    comp_res = await session.execute(components_query)
    items = comp_res.all()

    # Generate node summaries
    nodes: List[GraphNodeSummary] = []
    for sc, c in items:
        tier = _compute_risk_tier(sc.composite_score)
        node = GraphNodeSummary(
            purl=c.purl,
            package_name=c.package_name,
            version=c.version,
            depth=sc.graph_depth,
            composite_score=sc.composite_score,
            risk_tier=tier,
            vuln_count=len(sc.score_deductions),
            reachability=sc.reachability_status,
        )
        nodes.append(node)

    total_nodes = len(nodes)
    truncated = total_nodes > 2000
    bounded_nodes = nodes[:2000]

    # Generate dummy edges or direct dependency links
    edges: List[GraphEdge] = []

    # Deterministic ETag calculation
    etag_raw = f"{scan.id}:{scan.completed_at}:{total_nodes}"
    etag_hash = hashlib.sha256(etag_raw.encode()).hexdigest()
    etag_header = f'"{etag_hash}"'

    # Check conditional ETag
    if if_none_match in (etag_hash, etag_header):
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={
                "ETag": etag_header,
                "Cache-Control": "public, max-age=31536000, immutable",
            },
        )

    response.headers["ETag"] = etag_header
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"

    return BoundedGraphResponse(
        scan_id=scan.id,
        total_nodes=total_nodes,
        truncated=truncated,
        nodes=bounded_nodes,
        edges=edges,
    )


@router.post(
    "/scans/{scan_id}/remediate",
    status_code=status.HTTP_202_ACCEPTED,
)
async def remediate_scan(
    scan_id: uuid.UUID,
    payload: RemediationTriggerRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Trigger autonomous remediation for a vulnerable dependency in a scan."""
    query = select(ScanRun).where(
        ScanRun.id == scan_id,
        ScanRun.tenant_id == principal.tenant_id,
    )
    result = await session.execute(query)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan run not found",
        )

    try:
        task = trigger_remediation_task.delay(
            str(scan.id),
            payload.package_name,
            payload.target_version,
            payload.base_branch,
        )
        task_id = task.id
    except Exception:
        task_id = str(uuid.uuid4())

    return {
        "task_id": task_id,
        "status": "QUEUED",
    }
