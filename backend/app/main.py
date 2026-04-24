"""FastAPI application entrypoint."""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_config
from app.database import init_db
from app.errors import register_exception_handlers
from app.logging_config import configure_logging

logger = logging.getLogger("whoiswhoapt")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()
    configure_logging(config.normalized_log_level)

    app = FastAPI(title=config.app_name, version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router)

    @app.on_event("startup")
    def on_startup() -> None:
        logger.info("Starting backend service")
        init_db()

    return app


app = create_app()
