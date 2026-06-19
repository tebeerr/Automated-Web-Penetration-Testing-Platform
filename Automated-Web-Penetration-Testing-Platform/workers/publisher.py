"""Helpers to push scan progress into Redis pub/sub from the worker side."""

from __future__ import annotations

import json

import redis

from app.config import settings

_client: redis.Redis | None = None


def _client_singleton() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _client


def publish_scan_progress(scan_id: str, payload: dict) -> None:
    """Publish a progress frame to the channel watched by the API WebSocket relay."""
    channel = f"scan:{scan_id}"
    _client_singleton().publish(channel, json.dumps(payload))
