#!/usr/bin/env python3
"""
channel — Secure CLI messenger (Signal-style E2E encryption)

Commands:
  channel register <username>
  channel chat <peer>
  channel send <peer> <message>
  channel fetch
  channel sessions
  channel whoami
"""

import asyncio
import base64
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.crypto.keys import LocalIdentity, b64_to_pub_x25519, pub_to_b64
from client.crypto.x3dh import x3dh_send, x3dh_receive
from client.crypto.double_ratchet import RatchetState, encrypt_message, decrypt_message
from client.store import SessionStore
from client.transport import Transport

DEFAULT_SERVER = "ws://127.0.0.1:8765"
IDENTITY_DIR   = Path.home() / ".channel"


class C:
    RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM    = "\033[2m"
    GREEN   = "\033[92m"; CYAN    = "\033[96m"; YELLOW = "\033[93m"
    RED     = "\033[91m"; BLUE    = "\033[94m"; GREY   = "\033[90m"
    MAGENTA = "\033[95m"; WHITE   = "\033[97m"; BG_DARK = "\033[40m"


def _banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}  ███████╗███╗   ██╗ ██████╗ ██████╗ ██╗     ██╗  ██╗██╗  ██╗██╗
  ██╔════╝████╗  ██║██╔═████╗██╔══██╗██║     ██║  ██║╚██╗██╔╝██║
  ███████╗██╔██╗ ██║██║██╔██║██████╔╝██║     ███████║ ╚███╔╝ ██║
  ╚════██║██║╚██╗██║████╔╝██║██╔══██╗██║     ╚════██║ ██╔██╗ ╚═╝
  ███████║██║ ╚████║╚██████╔╝██║  ██║███████╗     ██║██╔╝ ██╗██╗
  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═╝╚═╝  ╚═╝╚═╝{C.RESET}
{C.GREY}  ┌─────────────────────────────────────────────────────────┐
  │  {C.CYAN}Protocol{C.GREY}  X3DH + Double Ratchet   {C.CYAN}Cipher{C.GREY}  AES-256-GCM  │
  │  {C.CYAN}Keys{C.GREY}     X25519 · Ed25519        {C.CYAN}KDF{C.GREY}    HKDF-SHA256  │
  └─────────────────────────────────────────────────────────┘{C.RESET}
""")


# ─── Identity ─────────────────────────────────────────────────────────────────

def _identity_path(username: str) -> Path:
    return IDENTITY_DIR / username / "identity.json"


def _load_identity(username: Optional[str] = None) -> LocalIdentity:
    if username:
        path = _identity_path(username)
    else:
        dirs = [d for d in IDENTITY_DIR.iterdir() if d.is_dir()] if IDENTITY_DIR.exists() else []
        if len(dirs) == 1:
            path = dirs[0] / "identity.json"
        elif not dirs:
            _die("No identity found. Run: channel register <username>")
        else:
            _die(f"Multiple identities: {[d.name for d in dirs]}. Pass --user <name>")
    if not path.exists():
        _die(f"Identity not found. Run: channel register <username>")
    return LocalIdentity.load(path)


def _die(msg: str) -> None:
    click.echo(f"{C.RED}✗ {msg}{C.RESET}", err=True)
    raise SystemExit(1)

def _ok(msg: str)   -> None: click.echo(f"  {C.GREEN}✓{C.RESET}  {msg}")
def _info(msg: str) -> None: click.echo(f"  {C.CYAN}»{C.RESET}  {msg}")
def _warn(msg: str) -> None: click.echo(f"  {C.YELLOW}!{C.RESET}  {msg}")


# ─── Crypto helpers ───────────────────────────────────────────────────────────

def _encrypt_for_wire(state: RatchetState, plaintext: str):
    hdr, ct, state = encrypt_message(state, plaintext.encode())
    return hdr, base64.b64encode(ct).decode(), state


def _decrypt_from_wire(state: RatchetState, hdr: dict, ct_b64: str):
    pt, state = decrypt_message(state, hdr, base64.b64decode(ct_b64))
    return pt.decode(), state


# ─── Session helpers ──────────────────────────────────────────────────────────

async def _x3dh_initiate(
    transport: Transport, local: LocalIdentity, store: SessionStore, peer: str
) -> tuple[RatchetState, dict]:
    """
    Fetch peer bundle, run X3DH, init sender ratchet, save session.
    Returns (state, x3dh_header_to_attach_to_first_message).
    Caller must ensure NO dispatcher is running (this calls transport.recv internally).
    """
    resp = await transport.rpc({"type": "get_bundle", "username": peer})
    if resp["type"] == "error":
        raise RuntimeError(f"User '{peer}' not found on relay. Are they registered?")
    bundle = resp["bundle"]
    sk, x3dh_hdr = x3dh_send(local, bundle)
    remote_spk = b64_to_pub_x25519(bundle["spk_pub"])
    state = RatchetState.init_sender(sk, remote_spk)
    store.save_session(peer, state, is_initiator=True)
    return state, x3dh_hdr


def _x3dh_respond(
    local: LocalIdentity, store: SessionStore, sender: str, x3dh_hdr: dict
) -> RatchetState:
    """Receive X3DH header, derive shared secret, init receiver ratchet."""
    sk, used_opk = x3dh_receive(local, x3dh_hdr)
    if used_opk is not None:
        local.save(_identity_path(local.username))
    state = RatchetState.init_receiver(sk, local.spk_priv, local.spk_pub)
    store.save_session(sender, state, is_initiator=False)
    return state


# ─── Message display ──────────────────────────────────────────────────────────

def _fmt_ts(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%H:%M")
    except Exception:
        return "--:--"

def _fmt_msg(sender: str, text: str, ts: str, me: bool) -> str:
    t = f"{C.GREY}[{_fmt_ts(ts)}]{C.RESET}"
    n = f"{C.BLUE}{C.BOLD}you{C.RESET}" if me else f"{C.GREEN}{C.BOLD}{sender}{C.RESET}"
    return f"{t} {n}: {text}"


def _process_envelope(local, store, sender, payload, ts):
    """Decrypt and print one incoming message envelope."""
    x3dh_hdr = payload.get("x3dh_header")
    hdr, ct_b64 = payload["header"], payload["ciphertext"]

    if x3dh_hdr:
        # Sender did X3DH — always establish from their header (authoritative)
        try:
            state = _x3dh_respond(local, store, sender, x3dh_hdr)
        except Exception as e:
            click.echo(f"{C.RED}✗ X3DH failed from {sender}: {e}{C.RESET}")
            return
    else:
        state = store.load_session(sender)
        if state is None:
            click.echo(f"{C.RED}✗ No session with {sender} — message dropped.{C.RESET}")
            return

    try:
        text, state = _decrypt_from_wire(state, hdr, ct_b64)
        store.save_session(sender, state)
        click.echo(_fmt_msg(sender, text, ts, me=False))
    except Exception as e:
        click.echo(f"{C.RED}✗ Decrypt failed from {sender}: {e}{C.RESET}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

@click.group()
@click.option("--server", default=DEFAULT_SERVER, envvar="CHANNEL_SERVER", show_default=True)
@click.option("--user",   default=None,           envvar="CHANNEL_USER")
@click.pass_context
def cli(ctx, server, user):
    """Channel — end-to-end encrypted CLI messenger."""
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["user"]   = user


@cli.command()
@click.argument("username")
@click.option("--opks", default=10, show_default=True)
@click.pass_context
def register(ctx, username, opks):
    """Generate keys and register with the relay."""
    _banner()
    path = _identity_path(username)
    if path.exists():
        if not click.confirm(f"{C.YELLOW}Overwrite existing identity for '{username}'?{C.RESET}"):
            return
    _info(f"Generating identity for {C.BOLD}{C.CYAN}{username}{C.RESET} …")
    identity = LocalIdentity.generate(username, num_opks=opks)
    identity.save(path)
    _ok(f"Identity saved  {C.DIM}{path}{C.RESET}")
    _info(f"Uploading key bundle to relay …")
    asyncio.run(_do_register(ctx.obj["server"], identity))


async def _do_register(server, identity):
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": identity.public_bundle()})
    if resp["type"] == "ok":
        _ok(f"Registered as {C.BOLD}{C.CYAN}{identity.username}{C.RESET}")
        _ok(f"Uploaded {C.BOLD}{len(identity.opks)}{C.RESET} one-time prekeys  {C.DIM}(forward secrecy){C.RESET}")
        _divider()
    else:
        _die(f"Registration failed: {resp.get('msg')}")


@cli.command()
@click.pass_context
def whoami(ctx):
    """Show identity info."""
    i = _load_identity(ctx.obj["user"])
    _divider()
    click.echo(f"  {C.BOLD}Username {C.RESET}  {C.CYAN}{i.username}{C.RESET}")
    click.echo(f"  {C.BOLD}IK pub   {C.RESET}  {C.DIM}{pub_to_b64(i.ik_pub)[:40]}…{C.RESET}")
    click.echo(f"  {C.BOLD}Sign pub {C.RESET}  {C.DIM}{pub_to_b64(i.ik_sign_pub)[:40]}…{C.RESET}")
    click.echo(f"  {C.BOLD}OPKs     {C.RESET}  {len(i.opks)} remaining")
    _divider()


@cli.command()
@click.pass_context
def sessions(ctx):
    """List open sessions."""
    i = _load_identity(ctx.obj["user"])
    s = SessionStore(i.username)
    peers = s.list_sessions(); s.close()
    if not peers:
        click.echo(f"{C.DIM}No open sessions.{C.RESET}")
    else:
        click.echo(f"{C.BOLD}Open sessions:{C.RESET}")
        for p in peers: click.echo(f"  {C.CYAN}·{C.RESET} {p}")


@cli.command()
@click.argument("peer")
@click.argument("message")
@click.pass_context
def send(ctx, peer, message):
    """Send a single encrypted message."""
    asyncio.run(_do_send(ctx.obj["server"], _load_identity(ctx.obj["user"]), peer, message))


async def _do_send(server, local, peer, plaintext):
    async with Transport(server) as t:
        await t.rpc({"type": "register", "bundle": local.public_bundle()})
        store = SessionStore(local.username)
        x3dh_hdr = None
        if not store.has_session(peer):
            _, x3dh_hdr = await _x3dh_initiate(t, local, store, peer)
        state = store.load_session(peer)
        hdr, ct_b64, state = _encrypt_for_wire(state, plaintext)
        store.save_session(peer, state)
        payload = {"header": hdr, "ciphertext": ct_b64}
        if x3dh_hdr:
            payload["x3dh_header"] = x3dh_hdr
        resp = await t.rpc({"type": "send", "to": peer, "payload": payload})
        store.close()
    _ok(f"Message {'delivered' if resp.get('msg') == 'delivered' else 'queued'} → {peer}") \
        if resp["type"] == "ok" else _die(f"Send failed: {resp}")


@cli.command()
@click.pass_context
def fetch(ctx):
    """Fetch and decrypt queued messages."""
    asyncio.run(_do_fetch(ctx.obj["server"], _load_identity(ctx.obj["user"])))


async def _do_fetch(server, local):
    async with Transport(server) as t:
        await t.rpc({"type": "register", "bundle": local.public_bundle()})
        resp = await t.rpc({"type": "fetch"})
    messages = resp.get("messages", [])
    if not messages:
        return _info("No queued messages.")
    store = SessionStore(local.username)
    for env in messages:
        _process_envelope(local, store, env["from"], env["payload"], env.get("ts", ""))
    store.close()


@cli.command()
@click.argument("peer")
@click.pass_context
def chat(ctx, peer):
    """Open interactive chat with PEER."""
    identity = _load_identity(ctx.obj["user"])
    _banner()
    click.echo(
        f"  {C.GREY}┌──────────────────────────────────────────┐{C.RESET}\n"
        f"  {C.GREY}│{C.RESET}  Chatting with {C.GREEN}{C.BOLD}{peer}{C.RESET}          "
        f"{C.DIM}/quit to exit{C.RESET}  {C.GREY}│{C.RESET}\n"
        f"  {C.GREY}│{C.RESET}  {C.DIM}End-to-end encrypted · relay sees nothing{C.RESET}  {C.GREY}│{C.RESET}\n"
        f"  {C.GREY}└──────────────────────────────────────────┘{C.RESET}\n"
    )
    asyncio.run(_do_chat(ctx.obj["server"], identity, peer))


async def _do_chat(server: str, local: LocalIdentity, peer: str) -> None:
    """
    Full-duplex interactive chat.

    Design:
    ─ ONE dispatcher task owns all recv() calls (websockets forbids concurrent recv)
    ─ Frames routed via asyncio.Queue: ack_q (server acks) / inbox_q (incoming msgs)
    ─ Session established LAZILY on first send:
        · dispatcher is cancelled before X3DH rpc() call
        · restarted immediately after
      This avoids BOTH the concurrent-recv crash AND the "user not found" error
      that happened when we tried to fetch a bundle before the peer had registered.
    """
    async with Transport(server) as t:

        # ── Sequential setup (no background tasks yet) ────────────────────────
        resp = await t.rpc({"type": "register", "bundle": local.public_bundle()})
        if resp["type"] != "ok":
            _die("Server auth failed")

        store = SessionStore(local.username)

        # Flush offline messages
        resp = await t.rpc({"type": "fetch"})
        for env in resp.get("messages", []):
            if env["from"] == peer:
                _process_envelope(local, store, env["from"], env["payload"], env.get("ts", ""))

        ack_q:   asyncio.Queue = asyncio.Queue()
        inbox_q: asyncio.Queue = asyncio.Queue()
        chat_stop = asyncio.Event()

        def _make_dispatcher():
            async def _dispatcher():
                while not chat_stop.is_set():
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
            return asyncio.create_task(_dispatcher())

        async def _printer():
            while not chat_stop.is_set():
                try:
                    frame = await asyncio.wait_for(inbox_q.get(), timeout=0.5)
                    # Clear current prompt line
                    sys.stdout.write(f"\r{' ' * 80}\r")
                    sys.stdout.flush()
                    try:
                        _process_envelope(
                            local, store,
                            frame["from"], frame["payload"], frame.get("ts", ""),
                        )
                    except Exception as exc:
                        sys.stdout.write(f"{C.RED}✗ Display error: {exc}{C.RESET}\n")
                    sys.stdout.flush()
                    # Reprint prompt
                    sys.stdout.write(f"{C.CYAN}you › {C.RESET}")
                    sys.stdout.flush()
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass  # keep running — never let printer die

        # X3DH state — populated only when user sends first message
        pending_x3dh: Optional[dict] = None

        dispatcher = _make_dispatcher()
        printer    = asyncio.create_task(_printer())
        loop       = asyncio.get_event_loop()

        try:
            while True:
                print(f"{C.CYAN}you › {C.RESET}", end="", flush=True)
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line: break
                text = line.rstrip("\n")
                if not text: continue
                if text.lower() in ("/quit", "/q", "/exit"): break

                try:
                    # ── Lazy X3DH: only on very first send, no session yet ────
                    if not store.has_session(peer) and pending_x3dh is None:
                        # Stop dispatcher so we can safely call rpc (recv)
                        dispatcher.cancel()
                        try:
                            await dispatcher
                        except asyncio.CancelledError:
                            pass

                        try:
                            _, pending_x3dh = await _x3dh_initiate(t, local, store, peer)
                        except Exception as exc:
                            print(f"\n{C.RED}✗ {exc}{C.RESET}")
                            # Restart dispatcher and let user try again
                            dispatcher = _make_dispatcher()
                            continue

                        # Restart dispatcher
                        dispatcher = _make_dispatcher()

                    state = store.load_session(peer)
                    if state is None:
                        print(f"\n{C.RED}✗ No session — try sending again{C.RESET}")
                        continue

                    hdr, ct_b64, state = _encrypt_for_wire(state, text)
                    store.save_session(peer, state)

                    payload: dict = {"header": hdr, "ciphertext": ct_b64}
                    if pending_x3dh:
                        payload["x3dh_header"] = pending_x3dh
                        pending_x3dh = None

                    await t.send({"type": "send", "to": peer, "payload": payload})
                    try:
                        await asyncio.wait_for(ack_q.get(), timeout=3.0)
                    except asyncio.TimeoutError:
                        pass

                    now = datetime.now(timezone.utc).isoformat()
                    print(f"\033[1A\r{' ' * 80}\r{_fmt_msg(local.username, text, now, me=True)}")

                except Exception as exc:
                    print(f"\n{C.RED}✗ Send error: {exc}{C.RESET}")

        except KeyboardInterrupt:
            pass
        finally:
            chat_stop.set()
            dispatcher.cancel()
            printer.cancel()
            store.close()

    click.echo(f"\n{C.DIM}Session ended.{C.RESET}")


if __name__ == "__main__":
    cli(obj={})
