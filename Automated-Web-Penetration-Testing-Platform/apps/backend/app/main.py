import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware.rate_limiter import RateLimiterMiddleware
from app.api.routes import auth, recon, reports, scans, targets
from app.config import settings

# Ensure all models are imported so Base.metadata is populated.
from app.database import Base, engine  # noqa: F401
from app.models import (  # noqa: F401
    ReconResult,
    Report,
    RLFeedback,
    Scan,
    User,
    VerifiedTarget,
    Vulnerability,
)
from app.services.scheduler import shutdown_scheduler, start_scheduler

logging.basicConfig(level=logging.INFO if not settings.DEBUG else logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    start_scheduler()
    try:
        yield
    finally:
        shutdown_scheduler()
        await engine.dispose()


app = FastAPI(title=settings.API_TITLE, version=settings.API_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    RateLimiterMiddleware,
    max_requests=settings.RATE_LIMIT_PER_MIN,
    window_seconds=60,
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(recon.router, prefix="/api/scans", tags=["recon"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])


@app.get("/api/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": settings.API_VERSION}
