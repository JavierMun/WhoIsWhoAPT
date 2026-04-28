"""FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_config
from app.database import get_db_session, init_db
from app.errors import register_exception_handlers
from app.logging_config import configure_logging
from app.dependencies import get_settings_store

logger = logging.getLogger("whoiswhoapt")

_scheduler = BackgroundScheduler(timezone="UTC")


def _auto_refresh_job() -> None:
    """Periodic job: reload the active source if auto-update is enabled."""
    try:
        from app.ingestion import load_active_source

        store = get_settings_store()
        settings = store.load()

        if settings.active_source == "opencti":
            cfg = settings.opencti
            if not cfg.auto_update or not cfg.url or not cfg.api_token:
                return
        elif settings.active_source == "mitre":
            if not settings.mitre.auto_update:
                return
        else:
            return

        session = next(get_db_session())
        try:
            load_active_source(session, store)
            logger.info("Auto-refresh: source '%s' reloaded", settings.active_source)
        finally:
            session.close()
    except Exception:
        logger.exception("Auto-refresh job failed")


def _reschedule(frequency_hours: int) -> None:
    """Replace the auto-refresh job with a new interval."""
    if _scheduler.get_job("auto_refresh"):
        _scheduler.remove_job("auto_refresh")
    _scheduler.add_job(
        _auto_refresh_job,
        trigger="interval",
        hours=frequency_hours,
        id="auto_refresh",
        replace_existing=True,
    )
    logger.info("Auto-refresh scheduled every %d hour(s)", frequency_hours)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Starting backend service")
    init_db()

    store = get_settings_store()
    settings = store.load()
    if settings.active_source == "opencti":
        hours = settings.opencti.update_frequency_hours
    else:
        hours = settings.mitre.update_frequency_hours
    _reschedule(hours)
    _scheduler.start()

    yield

    _scheduler.shutdown(wait=False)
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
