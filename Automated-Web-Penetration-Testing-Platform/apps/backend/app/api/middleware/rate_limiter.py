"""Simple token-bucket rate limiter keyed by client IP. In-memory; replace with
Redis backed sliding window for multi-instance deployments."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "anon"
        now = time.monotonic()
        bucket = self._hits[client]
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Slow down."},
            )
        bucket.append(now)
        return await call_next(request)
