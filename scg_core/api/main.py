"""FastAPI Application Entrypoint for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-7 (REQ-P7-09).
Mounts decoupled probe endpoints at root and tenant-authenticated v1 API routes under /api/v1.
"""

from __future__ import annotations

from fastapi import FastAPI

from scg_core.api.probes import router as probe_router
from scg_core.api.v1.routes import router as v1_router

app = FastAPI(
    title="Supply Chain Guardian API",
    version="2.1",
    description="Automated software supply chain risk platform API Gateway",
)

# Unauthenticated health probes (/healthz, /readyz)
app.include_router(probe_router)

# Authenticated v1 API endpoints (/api/v1/...)
app.include_router(v1_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("scg_core.api.main:app", host="0.0.0.0", port=8000, reload=True)
