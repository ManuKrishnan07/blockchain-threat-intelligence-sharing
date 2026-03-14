import logging
import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# ── Configure root logger ──────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)

logger = logging.getLogger("dtisp")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every request with method, path, status code, and duration.
    Attaches a unique request-id to each request for traceability.
    """
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start      = time.perf_counter()

        # Attach request_id so route handlers can log with it
        request.state.request_id = request_id

        logger.info(
            f"[{request_id}] → {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )

        response = await call_next(request)

        duration_ms = (time.perf_counter() - start) * 1000
        logger.info(
            f"[{request_id}] ← {response.status_code} "
            f"({duration_ms:.1f}ms)"
        )

        response.headers["X-Request-ID"] = request_id
        return response