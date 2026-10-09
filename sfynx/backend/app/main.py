"""
SFYNX — Hybrid Security Testing Platform.

Application entry point.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import compat_router
from app.api.scans import router as scans_router
from app.core.config import get_settings

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sfynx")

settings = get_settings()

app = FastAPI(
    title="SFYNX",
    description=(
        "Hybrid Security Testing Platform. "
        "Deterministic security tools find the problems. "
        "LLM understands the problems."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — restrictive by default, open for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"] if settings.app_debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(scans_router)
app.include_router(compat_router)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "sfynx", "version": "0.1.0"}


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint with API info."""
    return {
        "service": "SFYNX",
        "version": "0.1.0",
        "docs": "/docs",
        "description": (
            "Hybrid Security Testing Platform — "
            "Let deterministic security tools find the problems. "
            "Let the LLM understand the problems."
        ),
    }
