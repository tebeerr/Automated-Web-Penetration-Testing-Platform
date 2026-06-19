"""Per-scan WebSocket fan-out. Worker publishes progress to Redis pub/sub on
channel `scan:{scan_id}`; this module relays each frame to subscribed sockets."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings

log = logging.getLogger(__name__)

ws_router = APIRouter()


class ScanProgressManager:
    """Holds active sockets per scan_id."""

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.setdefault(scan_id, set()).add(ws)

    async def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        async with self._lock:
            if scan_id in self._connections:
                self._connections[scan_id].discard(ws)
                if not self._connections[scan_id]:
                    self._connections.pop(scan_id, None)

    async def broadcast(self, scan_id: str, payload: dict | str) -> None:
        message = payload if isinstance(payload, str) else json.dumps(payload)
        async with self._lock:
            targets = list(self._connections.get(scan_id, ()))
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(scan_id, ws)


manager = ScanProgressManager()


async def redis_pubsub_relay() -> None:
    """Background task: subscribe to `scan:*` and broadcast to local sockets."""
    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    try:
        await pubsub.psubscribe("scan:*")
        async for msg in pubsub.listen():
            if msg.get("type") != "pmessage":
                continue
            channel = msg.get("channel", "")
            if not channel.startswith("scan:"):
                continue
            scan_id = channel.split(":", 1)[1]
            await manager.broadcast(scan_id, msg.get("data", ""))
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Redis pub/sub relay crashed; retrying.")
    finally:
        with contextlib.suppress(Exception):
            await pubsub.close()
        with contextlib.suppress(Exception):
            await redis.close()


@ws_router.websocket("/ws/scan/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str) -> None:
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Client may send keepalives; ignore content.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(scan_id, websocket)
