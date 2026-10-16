"""Decoupled Health and Readiness Probes for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-08, P7-11).
Strictly decouples liveness (/healthz) from readiness (/readyz):
- /healthz: Immediate process liveness response, never touching backing services.
- /readyz: Deep dependency readiness verifying PostgreSQL 16 and Redis availability
  within a strict 1.0 second timeout limit.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict

from fastapi import APIRouter, Response, status
from fastapi.responses import JSONResponse
import redis.asyncio as aioredis
from sqlalchemy import text

from scg_core.db.session import engine
from scg_core.tasks.pipeline import REDIS_URL

router = APIRouter(tags=["Health Probes"])


@router.get("/healthz", status_code=status.HTTP_200_OK)
async def liveness_probe() -> Dict[str, str]:
    """Process liveness probe (P7-11).

    Returns 200 OK immediately without issuing queries or pings to
    PostgreSQL, Redis, or upstream network dependencies.
    """
    return {"status": "ok"}


@router.get("/readyz")
async def readiness_probe() -> Response:
    """Dependency readiness probe (P7-11).

    Pings Redis and executes 'SELECT 1' on PostgreSQL with a strict 1.0 second timeout.
    Returns 200 OK only if both services respond affirmatively within budget;
    otherwise returns 503 Service Unavailable.
    """
    db_ok = False
    redis_ok = False

    # Check PostgreSQL database with 1.0s timeout
    try:
        async def _check_db() -> bool:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True

        db_ok = await asyncio.wait_for(_check_db(), timeout=1.0)
    except Exception:
        db_ok = False

    # Check Redis cache / broker with 1.0s timeout
    try:
        async def _check_redis() -> bool:
            client = aioredis.from_url(REDIS_URL, socket_timeout=1.0)
            try:
                pong = await client.ping()
                return bool(pong)
            finally:
                await client.aclose()

        redis_ok = await asyncio.wait_for(_check_redis(), timeout=1.0)
    except Exception:
        redis_ok = False

    if db_ok and redis_ok:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ready",
                "database": "ok",
                "redis": "ok",
            },
        )

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "unready",
            "database": "ok" if db_ok else "unreachable",
            "redis": "ok" if redis_ok else "unreachable",
        },
    )
