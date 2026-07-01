"""
Channel Relay Server — never sees plaintext.

Responsibilities:
  - Store & serve public key bundles (X3DH prekey bundles)
  - Route encrypted message blobs between connected clients
  - Queue messages for offline users (in-memory; cleared on delivery)

The server sees only:
  - Usernames (for routing)
  - Encrypted blobs (ciphertext + header, already encrypted by client)
  - Public keys (these are public by design)

WebSocket message format (JSON):
  All messages have a "type" field.

Client → Server:
  {"type": "register",   "bundle": {...}}           # upload public key bundle
  {"type": "get_bundle", "username": "bob"}         # fetch Bob's bundle
  {"type": "send",       "to": "bob", "payload": {...}}  # deliver encrypted message
  {"type": "fetch"}                                  # get queued messages

Server → Client:
  {"type": "ok",   ...}
  {"type": "error","msg": "..."}
  {"type": "bundle","bundle": {...}}
  {"type": "messages","messages": [...]}
  {"type": "deliver","from": "alice","payload": {...}}
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import websockets
from websockets.server import WebSocketServerProtocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("relay")


class RelayServer:
    def __init__(self) -> None:
        # username → public bundle dict
        self.bundles: Dict[str, dict] = {}
        # username → list of queued message dicts (for offline users)
        self.queues: Dict[str, List[dict]] = {}
        # username → active WebSocket (for live delivery)
        self.connections: Dict[str, WebSocketServerProtocol] = {}

    async def handler(self, ws: WebSocketServerProtocol) -> None:
        peer = ws.remote_address
        username: Optional[str] = None
        log.info(f"Connection from {peer}")

        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await self._send(ws, {"type": "error", "msg": "invalid JSON"})
                    continue

                mtype = msg.get("type")

                if mtype == "register":
                    username = await self._handle_register(ws, msg)

                elif mtype == "get_bundle":
                    await self._handle_get_bundle(ws, msg)

                elif mtype == "send":
                    await self._handle_send(ws, msg, username)

                elif mtype == "fetch":
                    await self._handle_fetch(ws, username)

                else:
                    await self._send(ws, {"type": "error", "msg": f"unknown type: {mtype}"})

        except websockets.exceptions.ConnectionClosedOK:
            pass
        except websockets.exceptions.ConnectionClosedError as e:
            log.warning(f"Connection error from {peer}: {e}")
        finally:
            if username and self.connections.get(username) is ws:
                del self.connections[username]
                log.info(f"Disconnected: {username}")

    async def _handle_register(
        self, ws: WebSocketServerProtocol, msg: dict
    ) -> Optional[str]:
        bundle = msg.get("bundle")
        if not bundle or "username" not in bundle:
            await self._send(ws, {"type": "error", "msg": "missing bundle.username"})
            return None

        username = bundle["username"]
        self.bundles[username] = bundle
        self.connections[username] = ws
        if username not in self.queues:
            self.queues[username] = []

        log.info(f"Registered: {username}  opks={len(bundle.get('opks', []))}")
        await self._send(ws, {"type": "ok", "msg": f"registered as {username}"})
        return username

    async def _handle_get_bundle(
        self, ws: WebSocketServerProtocol, msg: dict
    ) -> None:
        target = msg.get("username")
        if not target:
            await self._send(ws, {"type": "error", "msg": "missing username"})
            return

        bundle = self.bundles.get(target)
        if bundle is None:
            await self._send(ws, {"type": "error", "msg": f"user not found: {target}"})
            return

        # Serve one OPK and remove it (one-time use)
        bundle_copy = dict(bundle)
        opks = list(bundle_copy.get("opks", []))
        if opks:
            bundle_copy["opks"] = [opks[0]]
            bundle["opks"] = opks[1:]   # consume from server store
        else:
            bundle_copy["opks"] = []

        log.info(f"Bundle served: {target} → {ws.remote_address}  "
                 f"opks_remaining={len(bundle.get('opks', []))}")
        await self._send(ws, {"type": "bundle", "bundle": bundle_copy})

    async def _handle_send(
        self,
        ws: WebSocketServerProtocol,
        msg: dict,
        sender: Optional[str],
    ) -> None:
        if not sender:
            await self._send(ws, {"type": "error", "msg": "not registered"})
            return

        to = msg.get("to")
        payload = msg.get("payload")
        if not to or payload is None:
            await self._send(ws, {"type": "error", "msg": "missing to/payload"})
            return

        envelope = {
            "from": sender,
            "payload": payload,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

        # Live delivery if recipient is connected
        recipient_ws = self.connections.get(to)
        if recipient_ws is not None:
            try:
                await self._send(recipient_ws, {"type": "deliver", **envelope})
                log.info(f"Delivered live: {sender} → {to}")
                await self._send(ws, {"type": "ok", "msg": "delivered"})
                return
            except Exception:
                pass  # fall through to queue

        # Queue for offline delivery
        if to not in self.queues:
            self.queues[to] = []
        self.queues[to].append(envelope)
        log.info(f"Queued: {sender} → {to}  (offline)")
        await self._send(ws, {"type": "ok", "msg": "queued"})

    async def _handle_fetch(
        self, ws: WebSocketServerProtocol, username: Optional[str]
    ) -> None:
        if not username:
            await self._send(ws, {"type": "error", "msg": "not registered"})
            return
        messages = self.queues.pop(username, [])
        self.queues[username] = []   # reset
        await self._send(ws, {"type": "messages", "messages": messages})
        if messages:
            log.info(f"Flushed {len(messages)} queued msg(s) → {username}")

    @staticmethod
    async def _send(ws: WebSocketServerProtocol, data: dict) -> None:
        await ws.send(json.dumps(data))

    def list_users(self) -> List[str]:
        return list(self.bundles.keys())


async def main(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = RelayServer()
    log.info(f"Channel relay starting on ws://{host}:{port}")
    log.info("This server NEVER decrypts message content.")
    async with websockets.serve(server.handler, host, port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Channel relay server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    asyncio.run(main(args.host, args.port))
