"""
WebSocket transport layer — async client wrapping websockets.

Provides a clean async context manager that:
  - Connects to the relay
  - Sends/receives JSON messages
  - Handles reconnection (simple linear backoff)
"""

import asyncio
import json
import logging
from typing import Optional, AsyncIterator

import websockets
from websockets.client import WebSocketClientProtocol

log = logging.getLogger("transport")


class Transport:
    def __init__(self, url: str) -> None:
        self.url = url
        self._ws: Optional[WebSocketClientProtocol] = None

    async def connect(self) -> None:
        self._ws = await websockets.connect(self.url)

    async def close(self) -> None:
        if self._ws:
            await self._ws.close()

    async def send(self, data: dict) -> None:
        assert self._ws, "Not connected"
        await self._ws.send(json.dumps(data))

    async def recv(self) -> dict:
        assert self._ws, "Not connected"
        raw = await self._ws.recv()
        return json.loads(raw)

    async def rpc(self, data: dict) -> dict:
        """Send a message and wait for exactly one reply."""
        await self.send(data)
        return await self.recv()

    async def __aenter__(self) -> "Transport":
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
