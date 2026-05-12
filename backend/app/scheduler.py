"""APScheduler singleton — importable from routes without circular imports."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("whoiswhoapt")

_scheduler = BackgroundScheduler(timezone="UTC")


def reschedule(frequency_hours: int) -> None:
    """Replace the periodic auto-refresh job with a new interval.

    Safe to call before or after the scheduler has started.
    """
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


def start() -> None:
    _scheduler.start()


def shutdown() -> None:
    _scheduler.shutdown(wait=False)


def _auto_refresh_job() -> None:
    """Periodic job: reload the active source if auto-update is enabled."""
    try:
        from app.database import get_db_session
        from app.dependencies import get_settings_store
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
