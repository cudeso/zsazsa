"""Lightweight in-process rate limiter for JSON endpoints.

Uses an in-memory sliding window keyed by endpoint scope + client IP.
This is intentionally simple and does not require extra dependencies.
"""

import time
from collections import deque
from functools import wraps
from threading import Lock

from flask import jsonify, request

_WINDOWS: dict[str, deque] = {}
_LOCK = Lock()


def _client_ip() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def rate_limited(scope: str, limit: int, window_s: int):
    """Decorator that returns HTTP 429 when a client exceeds the limit."""

    def _decorator(func):
        @wraps(func)
        def _wrapped(*args, **kwargs):
            now = time.time()
            key = f"{scope}:{_client_ip()}"
            cutoff = now - window_s

            with _LOCK:
                bucket = _WINDOWS.get(key)
                if bucket is not None:
                    while bucket and bucket[0] <= cutoff:
                        bucket.popleft()
                    if not bucket:
                        del _WINDOWS[key]
                        bucket = None
                if bucket is None:
                    bucket = deque()
                    _WINDOWS[key] = bucket
                if len(bucket) >= limit:
                    retry_after = max(1, int(window_s - (now - bucket[0])))
                    return (
                        jsonify({
                            "ok": False,
                            "error": "Too many requests. Please retry shortly.",
                        }),
                        429,
                        {"Retry-After": str(retry_after)},
                    )
                bucket.append(now)

            return func(*args, **kwargs)

        return _wrapped

    return _decorator
