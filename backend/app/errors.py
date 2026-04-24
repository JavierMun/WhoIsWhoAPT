"""Global API error handling."""

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("whoiswhoapt.errors")


class ErrorResponse(BaseModel):
    """Consistent error response body."""

    error: str
    detail: Any | None = None
    status_code: int


class AppError(Exception):
    """Base exception for expected application errors."""

    def __init__(self, message: str, status_code: int = 400, detail: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail


def _error_response(error: str, status_code: int, detail: Any | None = None) -> JSONResponse:
    """Build a normalized JSON error response."""
    body = ErrorResponse(error=error, status_code=status_code, detail=detail)
    return JSONResponse(status_code=status_code, content=body.model_dump())


def register_exception_handlers(app: FastAPI) -> None:
    """Install application-wide exception handlers."""

    @app.exception_handler(AppError)
    async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
        return _error_response(exc.message, exc.status_code, exc.detail)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        try:
            reason = HTTPStatus(exc.status_code).phrase
        except ValueError:
            reason = "HTTP error"
        return _error_response(reason, exc.status_code, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response("Validation error", 422, exc.errors())

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled application error", exc_info=exc)
        return _error_response("Internal server error", 500)
