"""Top-level API router registration."""

from fastapi import APIRouter

from app.api.routes import health, settings, source

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router, tags=["health"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(source.router, prefix="/source", tags=["source"])
