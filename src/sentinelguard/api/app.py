"""FastAPI application factory."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from sentinelguard.api.routes import dashboard, health, rules, scans
from sentinelguard.config import APP_NAME, APP_SUBTITLE, APP_VERSION, Settings, get_settings
from sentinelguard.errors import SentinelError
from sentinelguard.logging_config import configure_logging, request_id_ctx
from sentinelguard.persistence.database import init_db, make_engine, make_session_factory
from sentinelguard.persistence.repository import SqlAlchemyScanRepository

logger = logging.getLogger("sentinelguard.api")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MULTIPART_OVERHEAD = 256 * 1024


def error_response(
    status_code: int, code: str, message: str, details: list[str] | None = None
) -> JSONResponse:
    body: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": request_id_ctx.get(),
    }
    if details:
        body["details"] = details
    return JSONResponse(status_code=status_code, content={"error": body})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(settings.log_level, settings.log_format)
        engine = make_engine(settings.database_url)
        init_db(engine)
        app.state.engine = engine
        app.state.repository = SqlAlchemyScanRepository(make_session_factory(engine))
        logger.info("startup complete", extra={"event": "startup"})
        yield
        engine.dispose()
        logger.info("shutdown complete", extra={"event": "shutdown"})

    app = FastAPI(
        title=f"{APP_NAME} — {APP_SUBTITLE}",
        description=(
            "API-first Infrastructure-as-Code security auditing for Terraform and "
            "CloudFormation with explainable risk scoring. Uploaded IaC is analysed as data; "
            "nothing is executed and no cloud resource is ever touched."
        ),
        version=APP_VERSION,
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        response = None
        try:
            if request.method == "POST" and request.url.path == "/api/v1/scans":
                declared = request.headers.get("content-length", "")
                limit = (
                    settings.max_upload_bytes * settings.max_files_per_scan + _MULTIPART_OVERHEAD
                )
                if declared.isdigit() and int(declared) > limit:
                    response = error_response(
                        413, "file_too_large", "Request body exceeds the allowed upload size."
                    )
                    return response
            try:
                response = await call_next(request)
            except Exception:
                logger.exception("unhandled error", extra={"event": "unhandled_error"})
                response = error_response(500, "internal_error", "An internal error occurred.")
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            logger.info(
                "request",
                extra={
                    "event": "request",
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code if response is not None else None,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            request_id_ctx.reset(token)

    @app.exception_handler(SentinelError)
    async def handle_sentinel_error(_: Request, exc: SentinelError):
        if exc.status_code >= 500:
            logger.error("application error: %s", exc.message)
        return error_response(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError):
        details = [
            f"{'.'.join(str(p) for p in err.get('loc', ()))}: {err.get('msg', 'invalid')}"
            for err in exc.errors()
        ]
        return error_response(422, "validation_error", "Request validation failed.", details)

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(_: Request, exc: StarletteHTTPException):
        codes = {404: "not_found", 405: "method_not_allowed"}
        return error_response(
            exc.status_code, codes.get(exc.status_code, "http_error"), str(exc.detail)
        )

    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(rules.router)
    app.include_router(dashboard.router)
    return app
