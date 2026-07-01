#!/usr/bin/env python3
"""
channel — Secure CLI messenger (Signal-style E2E encryption)

Commands:
  channel register <username>            Register and upload key bundle
  channel chat <peer>                    Open interactive chat with <peer>
  channel send <peer> <message>          Send a single message
  channel fetch                          Fetch queued messages
  channel sessions                       List open sessions
  channel whoami                         Show your username

Identity is stored at ~/.channel/<username>/identity.json
Sessions are stored at ~/.channel/<username>/store.db
"""

import asyncio
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

# ── path setup (allow running as script or installed package) ────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.crypto.keys import LocalIdentity, b64_to_pub_x25519, pub_to_b64
from client.crypto.x3dh import x3dh_send, x3dh_receive
from client.crypto.double_ratchet import (
    RatchetState, encrypt_message, decrypt_message,
)
from client.store import SessionStore
from client.transport import Transport


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_SERVER = "ws://127.0.0.1:8765"
IDENTITY_DIR   = Path.home() / ".channel"


# ─── ANSI colours ────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BLUE    = "\033[94m"
    GREY    = "\033[90m"
    MAGENTA = "\033[95m"


def _banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}\
  ██████╗██╗  ██╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██╗
 ██╔════╝██║  ██║██╔══██╗████╗  ██║████╗  ██║██╔════╝██║
 ██║     ███████║███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
 ██║     ██╔══██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
 ╚██████╗██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗███████╗
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.RESET}{C.DIM}  Signal-style E2E encryption  ·  X3DH + Double Ratchet{C.RESET}
""")


# ─── Identity helpers ─────────────────────────────────────────────────────────

def _identity_path(username: str) -> Path:
    return IDENTITY_DIR / username / "identity.json"


def _load_identity(username: Optional[str] = None) -> LocalIdentity:
    if username:
        path = _identity_path(username)
    else:
        dirs = (
            [d for d in IDENTITY_DIR.iterdir() if d.is_dir()]
            if IDENTITY_DIR.exists() else []
        )
        if len(dirs) == 1:
            path = dirs[0] / "identity.json"
        elif not dirs:
            _die("No identity found. Run:  channel register <username>")
        else:
            names = [d.name for d in dirs]
            _die(f"Multiple identities: {names}. Pass --user <username>")

    if not path.exists():
        _die(f"Identity not found at {path}. Run:  channel register <username>")
    return LocalIdentity.load(path)


def _die(msg: str) -> None:
    click.echo(f"{C.RED}✗ {msg}{C.RESET}", err=True)
    sys.exit(1)


def _ok(msg: str) -> None:
    click.echo(f"{C.GREEN}✓{C.RESET} {msg}")


def _info(msg: str) -> None:
    click.echo(f"{C.CYAN}·{C.RESET} {msg}")


# ─── Crypto wire helpers ──────────────────────────────────────────────────────

def _encrypt_for_wire(state: RatchetState, plaintext: str):
    """Returns (header_dict, ciphertext_b64, new_state)."""
    hdr, ct_bytes, state = encrypt_message(state, plaintext.encode("utf-8"))
    return hdr, base64.b64encode(ct_bytes).decode(), state


def _decrypt_from_wire(state: RatchetState, hdr: dict, ct_b64: str):
    """Returns (plaintext_str, new_state)."""
    ct = base64.b64decode(ct_b64)
    pt_bytes, state = decrypt_message(state, hdr, ct)
    return pt_bytes.decode("utf-8"), state


# ─── Session establishment ────────────────────────────────────────────────────

async def _ensure_session_sender(
    transport: Transport,
    local: LocalIdentity,
    store: SessionStore,
    peer: str,
) -> RatchetState:
    """
    Load existing ratchet session for `peer`, or perform X3DH to create one.
    Attaches `_x3dh_header` attribute if this is a brand-new session.
    """
    state = store.load_session(peer)
    if state:
        return state

    # Fetch peer's bundle from relay
    resp = await transport.rpc({"type": "get_bundle", "username": peer})
    if resp["type"] == "error":
        _die(f"Could not get bundle for '{peer}': {resp['msg']}")

    bundle = resp["bundle"]

    # X3DH → shared secret + header Alice must attach to first message
    sk, x3dh_header = x3dh_send(local, bundle)

    # Initialise sender-side Double Ratchet using Bob's SPK as the first remote key
    remote_spk_pub = b64_to_pub_x25519(bundle["spk_pub"])
    state = RatchetState.init_sender(sk, remote_spk_pub)

    # Tag the new state so the caller knows to attach the X3DH header
    state._x3dh_header = x3dh_header  # type: ignore[attr-defined]

    store.save_session(peer, state, is_initiator=True)
    return state


def _establish_receiver_session(
    local: LocalIdentity,
    store: SessionStore,
    sender: str,
    x3dh_header: dict,
) -> RatchetState:
    """
    Synchronous X3DH responder path — safe to call inside or outside a loop.
    Derives shared secret, initialises Bob's ratchet, persists state.
    """
    sk, used_opk = x3dh_receive(local, x3dh_header)
    if used_opk is not None:
        local.save(_identity_path(local.username))   # persist OPK consumption
    state = RatchetState.init_receiver(sk, local.spk_priv, local.spk_pub)
    store.save_session(sender, state, is_initiator=False)
    return state


# ─── Message processing ───────────────────────────────────────────────────────

def _fmt_ts(ts_str: str) -> str:
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%H:%M")
    except Exception:
        return "??:??"


def _fmt_msg(sender: str, text: str, ts: str, is_self: bool) -> str:
    time = f"{C.GREY}[{_fmt_ts(ts)}]{C.RESET}"
    name = (
        f"{C.BLUE}{C.BOLD}you{C.RESET}"
        if is_self
        else f"{C.GREEN}{C.BOLD}{sender}{C.RESET}"
    )
    return f"{time} {name}: {text}"


def _process_envelope(
    local: LocalIdentity,
    store: SessionStore,
    sender: str,
    payload: dict,
    ts: str,
) -> None:
    """
    Decrypt and print one incoming message envelope.
    Handles X3DH initiation transparently.
    Pure synchronous — safe to call from anywhere.
    """
    x3dh_hdr = payload.get("x3dh_header")
    hdr       = payload["header"]
    ct_b64    = payload["ciphertext"]

    # First message ever from this sender?
    if x3dh_hdr and not store.has_session(sender):
        try:
            state = _establish_receiver_session(local, store, sender, x3dh_hdr)
        except Exception as exc:
            click.echo(f"{C.RED}✗ X3DH failed from {sender}: {exc}{C.RESET}")
            return
    else:
        state = store.load_session(sender)
        if state is None:
            click.echo(
                f"{C.RED}✗ No session with {sender}. "
                f"Dropping message (X3DH header missing?).{C.RESET}"
            )
            return

    try:
        text, state = _decrypt_from_wire(state, hdr, ct_b64)
        store.save_session(sender, state)
        click.echo(_fmt_msg(sender, text, ts, is_self=False))
    except Exception as exc:
        click.echo(f"{C.RED}✗ Decrypt failed from {sender}: {exc}{C.RESET}")


# ─── CLI root ─────────────────────────────────────────────────────────────────

@click.group()
@click.option(
    "--server", default=DEFAULT_SERVER, envvar="CHANNEL_SERVER",
    show_default=True, help="Relay server WebSocket URL",
)
@click.option("--user", default=None, envvar="CHANNEL_USER", help="Username (auto-detected if only one exists, or set CHANNEL_USER)")
@click.pass_context
def cli(ctx, server: str, user: Optional[str]) -> None:
    """Channel — end-to-end encrypted CLI messenger."""
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["user"]   = user


# ─── register ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("username")
@click.option("--opks", default=10, show_default=True,
              help="Number of one-time prekeys to generate")
@click.pass_context
def register(ctx, username: str, opks: int) -> None:
    """Generate identity keys and register with the relay server."""
    _banner()
    server = ctx.obj["server"]
    path   = _identity_path(username)

    if path.exists():
        if not click.confirm(
            f"{C.YELLOW}Identity for '{username}' already exists. Overwrite?{C.RESET}"
        ):
            return

    _info(f"Generating identity for {C.BOLD}{username}{C.RESET} …")
    identity = LocalIdentity.generate(username, num_opks=opks)
    identity.save(path)
    _ok(f"Identity saved → {path}")
    _info("Connecting to relay …")
    asyncio.run(_do_register(server, identity))


async def _do_register(server: str, identity: LocalIdentity) -> None:
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": identity.public_bundle()})
    if resp["type"] == "ok":
        _ok(resp["msg"])
        _ok(f"Uploaded {len(identity.opks)} one-time prekeys")
    else:
        _die(f"Registration failed: {resp.get('msg')}")


# ─── whoami ───────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def whoami(ctx) -> None:
    """Show your identity info."""
    identity = _load_identity(ctx.obj["user"])
    click.echo(f"Username  : {C.BOLD}{identity.username}{C.RESET}")
    click.echo(f"IK pub    : {C.DIM}{pub_to_b64(identity.ik_pub)[:32]}…{C.RESET}")
    click.echo(f"Sign pub  : {C.DIM}{pub_to_b64(identity.ik_sign_pub)[:32]}…{C.RESET}")
    click.echo(f"OPKs left : {len(identity.opks)}")


# ─── sessions ─────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def sessions(ctx) -> None:
    """List peers you have open sessions with."""
    identity = _load_identity(ctx.obj["user"])
    store    = SessionStore(identity.username)
    peers    = store.list_sessions()
    store.close()

    if not peers:
        click.echo(f"{C.DIM}No open sessions.{C.RESET}")
    else:
        click.echo(f"{C.BOLD}Open sessions:{C.RESET}")
        for p in peers:
            click.echo(f"  {C.CYAN}·{C.RESET} {p}")


# ─── send ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("peer")
@click.argument("message")
@click.pass_context
def send(ctx, peer: str, message: str) -> None:
    """Send a single encrypted message to PEER."""
    identity = _load_identity(ctx.obj["user"])
    asyncio.run(_do_send(ctx.obj["server"], identity, peer, message))


async def _do_send(
    server: str, local: LocalIdentity, peer: str, plaintext: str
) -> None:
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": local.public_bundle()})
        if resp["type"] != "ok":
            _die(f"Server auth failed: {resp}")

        store = SessionStore(local.username)
        state = await _ensure_session_sender(t, local, store, peer)
        x3dh_hdr = getattr(state, "_x3dh_header", None)

        hdr, ct_b64, state = _encrypt_for_wire(state, plaintext)
        store.save_session(peer, state)

        payload: dict = {"header": hdr, "ciphertext": ct_b64}
        if x3dh_hdr:
            payload["x3dh_header"] = x3dh_hdr

        resp = await t.rpc({"type": "send", "to": peer, "payload": payload})
        store.close()

    if resp["type"] == "ok":
        _ok(f"Message {'delivered' if resp['msg'] == 'delivered' else 'queued'} → {peer}")
    else:
        _die(f"Send failed: {resp}")


# ─── fetch ────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def fetch(ctx) -> None:
    """Fetch and decrypt queued messages."""
    identity = _load_identity(ctx.obj["user"])
    asyncio.run(_do_fetch(ctx.obj["server"], identity))


async def _do_fetch(server: str, local: LocalIdentity) -> None:
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": local.public_bundle()})
        if resp["type"] != "ok":
            _die("Server auth failed")
        resp = await t.rpc({"type": "fetch"})

    messages = resp.get("messages", [])
    if not messages:
        _info("No queued messages.")
        return

    store = SessionStore(local.username)
    for env in messages:
        _process_envelope(local, store, env["from"], env["payload"], env.get("ts", ""))
    store.close()


# ─── chat (interactive) ───────────────────────────────────────────────────────

@cli.command()
@click.argument("peer")
@click.pass_context
def chat(ctx, peer: str) -> None:
    """Open an interactive real-time chat session with PEER."""
    identity = _load_identity(ctx.obj["user"])
    _banner()
    click.echo(
        f"  {C.BOLD}Chatting with {C.GREEN}{peer}{C.RESET}  "
        f"{C.DIM}(/quit to exit){C.RESET}\n"
    )
    asyncio.run(_do_chat(ctx.obj["server"], identity, peer))


async def _do_chat(server: str, local: LocalIdentity, peer: str) -> None:
    """
    Interactive full-duplex chat.

    Uses a single dispatcher task as the ONLY coroutine calling recv().
    All frames are routed via asyncio.Queue to avoid concurrent recv() calls,
    which the websockets library forbids.

      ack_q   ← server replies to our sends (ok / queued)
      inbox_q ← pushed 'deliver' messages from other users
    """
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": local.public_bundle()})
        if resp["type"] != "ok":
            _die("Server auth failed")

        store = SessionStore(local.username)

        # Drain any queued messages first (safe: no tasks running yet)
        resp = await t.rpc({"type": "fetch"})
        for env in resp.get("messages", []):
            if env["from"] == peer:
                _process_envelope(
                    local, store, env["from"], env["payload"], env.get("ts", "")
                )

        ack_q:   asyncio.Queue = asyncio.Queue()
        inbox_q: asyncio.Queue = asyncio.Queue()
        stop = asyncio.Event()

        async def _dispatcher() -> None:
            """
            The ONE coroutine allowed to call recv().
            Routes every incoming frame to the correct queue.
            """
            while not stop.is_set():
                try:
                    frame = await asyncio.wait_for(t.recv(), timeout=1.0)
                    if frame.get("type") == "deliver":
                        await inbox_q.put(frame)
                    else:
                        await ack_q.put(frame)
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

        async def _printer() -> None:
            """Print incoming messages as they arrive in inbox_q."""
            while not stop.is_set():
                try:
                    frame = await asyncio.wait_for(inbox_q.get(), timeout=0.5)
                    print(f"\r{' ' * 80}\r", end="", flush=True)
                    _process_envelope(
                        local, store,
                        frame["from"], frame["payload"], frame.get("ts", ""),
                    )
                    print(f"{C.CYAN}you › {C.RESET}", end="", flush=True)
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

        dispatcher = asyncio.create_task(_dispatcher())
        printer    = asyncio.create_task(_printer())
        loop       = asyncio.get_event_loop()

        try:
            while True:
                print(f"{C.CYAN}you › {C.RESET}", end="", flush=True)
                line = await loop.run_in_executor(None, sys.stdin.readline)

                if not line:
                    break
                text = line.rstrip("\n")
                if not text:
                    continue
                if text.lower() in ("/quit", "/q", "/exit"):
                    break

                try:
                    state = await _ensure_session_sender(t, local, store, peer)
                    x3dh_hdr = getattr(state, "_x3dh_header", None)

                    hdr, ct_b64, state = _encrypt_for_wire(state, text)
                    store.save_session(peer, state)

                    payload: dict = {"header": hdr, "ciphertext": ct_b64}
                    if x3dh_hdr:
                        payload["x3dh_header"] = x3dh_hdr

                    # Only send — dispatcher handles the ack via ack_q
                    await t.send({"type": "send", "to": peer, "payload": payload})
                    try:
                        await asyncio.wait_for(ack_q.get(), timeout=3.0)
                    except asyncio.TimeoutError:
                        pass

                    now = datetime.now(timezone.utc).isoformat()
                    print(
                        f"\033[1A\r{' ' * 80}\r"
                        f"{_fmt_msg(local.username, text, now, is_self=True)}"
                    )
                except Exception as exc:
                    print(f"\n{C.RED}✗ Send error: {exc}{C.RESET}")

        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            dispatcher.cancel()
            printer.cancel()
            store.close()

    click.echo(f"\n{C.DIM}Session ended.{C.RESET}")


if __name__ == "__main__":
    cli(obj={})
