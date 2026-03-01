"""
IDS Middleware — application factory.

Creates the FastAPI application, registers all middleware and routers,
and bootstraps services in the lifespan hook.

Run with:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
    (app.py re-exports `app` from here for uvicorn compatibility)
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from api.dependencies import init_services
from api.routers import alerts, detection, system

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ids-middleware")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup: load model + wire services.  Shutdown: nothing to tear down."""
    log.info("Starting IDS Middleware ...")
    init_services()
    log.info("IDS Middleware ready.")
    yield
    log.info("IDS Middleware shutting down.")


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    application = FastAPI(
        title="Web IDS Middleware",
        description=(
            "Real-time network intrusion detection via Random Forest.\n\n"
            "Submit raw NetFlow records to `/predict` and receive an "
            "attack/normal classification with confidence and threat level."
        ),
        version="2.0.0",
        lifespan=lifespan,
    )

    # ── Global middleware ─────────────────────────────────────────────────────

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def log_requests(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - t0) * 1000
        log.info(
            "%s %s  →  %d  (%.1f ms)",
            request.method, request.url.path, response.status_code, elapsed,
        )
        return response

    # ── Routers ───────────────────────────────────────────────────────────────

    application.include_router(system.router)
    application.include_router(detection.router)
    application.include_router(alerts.router)

    return application


app = create_app()
