"""Database engine and session management."""

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_config


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


def _build_engine() -> Engine:
    """Create the SQLAlchemy engine from process configuration."""
    config = get_config()
    connect_args = {"check_same_thread": False} if config.database_url.startswith("sqlite") else {}
    return create_engine(config.database_url, connect_args=connect_args)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create database tables and apply any pending column migrations."""
    from app.models import entities  # noqa: F401
    from sqlalchemy import inspect, text

    Base.metadata.create_all(bind=engine)
    _apply_column_migrations()


def _apply_column_migrations() -> None:
    """Add columns introduced after initial schema creation.

    Each migration is idempotent — it checks existing columns before
    issuing ALTER TABLE so re-running on an up-to-date DB is a no-op.
    """
    inspector = inspect(engine)

    _add_column_if_missing(inspector, "analyses", "filter_sectors", "JSON")
    _add_column_if_missing(inspector, "analyses", "filter_countries", "JSON")
    _add_column_if_missing(inspector, "campaigns", "target_sectors", "JSON")
    _add_column_if_missing(inspector, "campaigns", "target_countries", "JSON")


def _add_column_if_missing(inspector: object, table: str, column: str, col_type: str) -> None:
    from sqlalchemy import inspect as sa_inspect, text

    existing = {c["name"] for c in sa_inspect(engine).get_columns(table)}
    if column not in existing:
        with engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            conn.commit()


def get_db_session() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
