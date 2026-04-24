"""Top-level API router registration."""

from fastapi import APIRouter

from app.api.routes import actors, compare, custom_sets, health, settings, source, techniques

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router, tags=["health"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(source.router, prefix="/source", tags=["source"])
api_router.include_router(actors.router, prefix="/actors", tags=["actors"])
api_router.include_router(techniques.router, prefix="/techniques", tags=["techniques"])
api_router.include_router(compare.router, prefix="/compare", tags=["compare"])
api_router.include_router(custom_sets.router, prefix="/custom-sets", tags=["custom-sets"])
