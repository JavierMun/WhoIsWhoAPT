"""Top-level API router registration."""

from fastapi import APIRouter

from app.api.routes import (
    actors,
    analyze,
    clusters,
    compare,
    custom_sets,
    export,
    health,
    matrix,
    settings,
    source,
    techniques,
)

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router, tags=["health"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(source.router, prefix="/source", tags=["source"])
api_router.include_router(actors.router, prefix="/actors", tags=["actors"])
api_router.include_router(techniques.router, prefix="/techniques", tags=["techniques"])
api_router.include_router(compare.router, prefix="/compare", tags=["compare"])
api_router.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
api_router.include_router(matrix.router, prefix="/matrix", tags=["matrix"])
api_router.include_router(clusters.router, prefix="/clusters", tags=["clusters"])
api_router.include_router(custom_sets.router, prefix="/custom-sets", tags=["custom-sets"])
api_router.include_router(export.router, prefix="/export", tags=["export"])
