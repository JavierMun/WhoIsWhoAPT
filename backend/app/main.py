"""FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_config
from app.database import init_db
from app.dependencies import get_settings_store
from app.errors import register_exception_handlers
from app.logging_config import configure_logging
from app import scheduler

logger = logging.getLogger("whoiswhoapt")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Starting backend service")
    init_db()

    settings = get_settings_store().load()
    if settings.active_source == "opencti":
        hours = settings.opencti.update_frequency_hours
    else:
        hours = settings.mitre.update_frequency_hours
    scheduler.reschedule(hours)
    scheduler.start()

    yield

    scheduler.shutdown()
    logger.info("Scheduler stopped")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()
    configure_logging(config.normalized_log_level)

    app = FastAPI(title=config.app_name, version="0.1.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router)

    return app


app = create_app()
