#!/usr/bin/env python3
"""
channel — Secure CLI messenger (Signal-style E2E encryption)

Commands:
  channel register [USERNAME]        (prompts if not given)
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
CONFIG_FILE    = IDENTITY_DIR / "config.json"


# ─── ANSI colour helpers ──────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM     = "\033[2m"
    GREEN   = "\033[92m"; CYAN    = "\033[96m"; YELLOW  = "\033[93m"
    RED     = "\033[91m"; BLUE    = "\033[94m"; GREY    = "\033[90m"
    MAGENTA = "\033[95m"; WHITE   = "\033[97m"; BG_DARK = "\033[40m"
    PURPLE  = "\033[35m"


def _strip_ansi(s: str) -> str:
    """Return the printable length of a string, ignoring ANSI escapes."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _visible_len(s: str) -> int:
    return len(_strip_ansi(s))


def _padded(label: str, value: str, total_label_width: int = 10) -> str:
    """Print a key-value row with aligned columns."""
    pad = " " * (total_label_width - _visible_len(label))
    return f"  {C.BOLD}{label}{C.RESET}{pad}{value}"


# ─── Banner ───────────────────────────────────────────────────────────────────

def _banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}  ██████╗██╗  ██╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██╗
 ██╔════╝██║  ██║██╔══██╗████╗  ██║████╗  ██║██╔════╝██║
 ██║     ███████║███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
 ██║     ██╔══██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
 ╚██████╗██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗███████╗
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝{C.RESET}
{C.GREY}  ┌────────────────────────────────────────────────────────────┐
  │  {C.CYAN}Protocol{C.GREY}  X3DH + Double Ratchet    {C.CYAN}Cipher{C.GREY}  AES-256-GCM   │
  │  {C.CYAN}Keys{C.GREY}     X25519 · Ed25519         {C.CYAN}KDF{C.GREY}    HKDF-SHA256   │
  └────────────────────────────────────────────────────────────┘{C.RESET}
""")


# ─── Box helpers ──────────────────────────────────────────────────────────────

def _box(lines: list[str], colour: str = C.GREY) -> None:
    """
    Print a neat box whose width fits the longest line.
    Lines may contain ANSI codes — width is measured on printable chars.
    """
    inner_width = max(_visible_len(l) for l in lines) + 2  # 1-space padding each side
    top    = f"  {colour}┌{'─' * inner_width}┐{C.RESET}"
    bottom = f"  {colour}└{'─' * inner_width}┘{C.RESET}"
    print(top)
    for line in lines:
        vis = _visible_len(line)
        right_pad = " " * (inner_width - vis - 1)
        print(f"  {colour}│{C.RESET} {line}{right_pad} {colour}│{C.RESET}")
    print(bottom)


def _divider(width: int = 57) -> None:
    click.echo(f"  {C.GREY}{'─' * width}{C.RESET}")


# ─── Message helpers ──────────────────────────────────────────────────────────

def _die(msg: str) -> None:
    click.echo(f"\n  {C.RED}✗  {msg}{C.RESET}\n", err=True)
    raise SystemExit(1)

def _ok(msg: str)   -> None: click.echo(f"  {C.GREEN}✓{C.RESET}  {msg}")
def _info(msg: str) -> None: click.echo(f"  {C.CYAN}»{C.RESET}  {msg}")
def _warn(msg: str) -> None: click.echo(f"  {C.YELLOW}⚠{C.RESET}  {msg}")


# ─── Identity helpers ─────────────────────────────────────────────────────────

def _identity_path(username: str) -> Path:
    return IDENTITY_DIR / username / "identity.json"


def _list_identities() -> list[str]:
    if not IDENTITY_DIR.exists():
        return []
    return [d.name for d in sorted(IDENTITY_DIR.iterdir()) if d.is_dir()
            and (d / "identity.json").exists()]


def _read_active_user() -> Optional[str]:
    """Return the last-active username saved in ~/.channel/config.json, or None."""
    try:
        import json as _json
        return _json.loads(CONFIG_FILE.read_text()).get("active_user")
    except Exception:
        return None


def _write_active_user(username: str) -> None:
    """Persist the given username as the active user in ~/.channel/config.json."""
    import json as _json
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    try:
        existing = _json.loads(CONFIG_FILE.read_text())
    except Exception:
        pass
    existing["active_user"] = username
    CONFIG_FILE.write_text(_json.dumps(existing, indent=2))


def _load_identity(username: Optional[str] = None) -> LocalIdentity:
    # Explicit flag / env var always wins
    if username:
        path = _identity_path(username)
        if not path.exists():
            _die(f"No identity for '{username}'.  Run: channel register {username}")
        return LocalIdentity.load(path)

    # Try the saved active user next (set automatically after register)
    saved = _read_active_user()
    if saved:
        path = _identity_path(saved)
        if path.exists():
            return LocalIdentity.load(path)

    # Fall back to auto-discover
    names = _list_identities()
    if len(names) == 1:
        return LocalIdentity.load(_identity_path(names[0]))
    elif not names:
        _die("No identity found.  Run: channel register <username>")
    else:
        _die(
            f"Multiple identities found: {names}\n"
            f"     Pass --user <name> or set CHANNEL_USER=<name>"
        )


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
        raise RuntimeError(f"User '{peer}' not found on relay — are they registered?")
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
    if me:
        n = f"{C.BLUE}{C.BOLD}you{C.RESET}"
    else:
        n = f"{C.GREEN}{C.BOLD}{sender}{C.RESET}"
    return f"{t} {n}: {text}"


def _process_envelope(local, store, sender, payload, ts):
    """Decrypt and print one incoming message envelope."""
    x3dh_hdr = payload.get("x3dh_header")
    hdr, ct_b64 = payload["header"], payload["ciphertext"]

    if x3dh_hdr:
        try:
            state = _x3dh_respond(local, store, sender, x3dh_hdr)
        except Exception as e:
            click.echo(f"  {C.RED}✗  X3DH failed from {sender}: {e}{C.RESET}")
            return
    else:
        state = store.load_session(sender)
        if state is None:
            click.echo(f"  {C.RED}✗  No session with {sender} — message dropped.{C.RESET}")
            return

    try:
        text, state = _decrypt_from_wire(state, hdr, ct_b64)
        store.save_session(sender, state)
        click.echo(_fmt_msg(sender, text, ts, me=False))
    except Exception as e:
        click.echo(f"  {C.RED}✗  Decrypt failed from {sender}: {e}{C.RESET}")


# ─── CLI group ────────────────────────────────────────────────────────────────

@click.group()
@click.option("--server", default=DEFAULT_SERVER, envvar="CHANNEL_SERVER", show_default=True,
              help="Relay server WebSocket URL.")
@click.option("--user",   default=None,           envvar="CHANNEL_USER",
              help="Local username to use (required when multiple identities exist).")
@click.pass_context
def cli(ctx, server, user):
    """Channel — end-to-end encrypted CLI messenger."""
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["user"]   = user


# ─── register ─────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("username", required=False, default=None)
@click.option("--opks", default=10, show_default=True,
              help="Number of one-time prekeys to generate.")
@click.pass_context
def register(ctx, username: Optional[str], opks: int):
    """Generate keys and register with the relay.

    USERNAME is optional — you will be prompted if not provided.
    """
    _banner()

    # ── Interactive username prompt ────────────────────────────────────────────
    if not username:
        existing = _list_identities()
        if existing:
            _info(f"Existing identities: {C.CYAN}{', '.join(existing)}{C.RESET}")
        print()
        while True:
            username = click.prompt(
                f"  {C.BOLD}Choose a username{C.RESET}", prompt_suffix=" › "
            ).strip()
            if not username:
                _warn("Username cannot be empty.")
                continue
            if " " in username:
                _warn("Username cannot contain spaces.")
                continue
            if len(username) > 32:
                _warn("Username must be 32 characters or fewer.")
                continue
            break
        print()

    # ── Confirm overwrite if identity already exists ───────────────────────────
    path = _identity_path(username)
    if path.exists():
        _warn(f"An identity for '{username}' already exists locally.")
        if not click.confirm(f"  {C.YELLOW}Overwrite?{C.RESET}", default=False):
            _info("Cancelled.")
            return
        print()

    # ── Generate & save ───────────────────────────────────────────────────────
    _info(f"Generating identity for {C.BOLD}{C.CYAN}{username}{C.RESET} …")
    identity = LocalIdentity.generate(username, num_opks=opks)
    identity.save(path)
    _ok(f"Keys saved  {C.DIM}{path}{C.RESET}")

    # ── Persist as active user ────────────────────────────────────────────────
    _write_active_user(username)
    _ok(f"Active user set to {C.CYAN}{C.BOLD}{username}{C.RESET}")

    # ── Upload ────────────────────────────────────────────────────────────────
    _info("Uploading key bundle to relay …")
    asyncio.run(_do_register(ctx.obj["server"], identity))


async def _do_register(server: str, identity) -> None:
    async with Transport(server) as t:
        resp = await t.rpc({"type": "register", "bundle": identity.public_bundle()})
    print()
    if resp["type"] == "ok":
        _box([
            f"{C.GREEN}{C.BOLD}Registration successful!{C.RESET}",
            "",
            f"{C.BOLD}Username{C.RESET}  {C.CYAN}{identity.username}{C.RESET}",
            f"{C.BOLD}OPKs{C.RESET}      {len(identity.opks)} one-time prekeys uploaded  {C.DIM}(forward secrecy){C.RESET}",
            "",
            f"{C.DIM}Active user is now set to {C.RESET}{C.CYAN}{C.BOLD}{identity.username}{C.RESET}{C.DIM} automatically.{C.RESET}",
            f"{C.DIM}To switch users later:{C.RESET}",
            f"  {C.CYAN}channel --user <name> chat <peer>{C.RESET}",
            f"  {C.CYAN}channel register <other-name>{C.RESET}  {C.DIM}(switches active user){C.RESET}",
            "",
            f"{C.DIM}Start a chat:{C.RESET}",
            f"  {C.CYAN}channel chat <peer>{C.RESET}",
        ])
    else:
        _die(f"Registration failed: {resp.get('msg')}")
    print()


# ─── whoami ───────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def whoami(ctx):
    """Show your identity info."""
    i = _load_identity(ctx.obj["user"])
    print()
    _box([
        f"{C.CYAN}{C.BOLD}Identity: {i.username}{C.RESET}",
        "",
        f"{C.BOLD}IK pub{C.RESET}   {C.DIM}{pub_to_b64(i.ik_pub)[:44]}…{C.RESET}",
        f"{C.BOLD}Sign pub{C.RESET} {C.DIM}{pub_to_b64(i.ik_sign_pub)[:44]}…{C.RESET}",
        f"{C.BOLD}OPKs{C.RESET}     {C.YELLOW}{len(i.opks)}{C.RESET} remaining",
    ])
    print()


# ─── sessions ─────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def sessions(ctx):
    """List open E2E sessions."""
    i = _load_identity(ctx.obj["user"])
    s = SessionStore(i.username)
    peers = s.list_sessions()
    s.close()
    print()
    if not peers:
        _box([
            f"{C.DIM}No open sessions yet.{C.RESET}",
            f"{C.DIM}Start one with:  channel chat <peer>{C.RESET}",
        ])
    else:
        lines = [f"{C.CYAN}{C.BOLD}Open sessions for {i.username}{C.RESET}", ""]
        for idx, p in enumerate(peers, 1):
            lines.append(f"  {C.GREY}{idx}.{C.RESET}  {C.GREEN}{p}{C.RESET}")
        _box(lines)
    print()


# ─── send ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("peer")
@click.argument("message")
@click.pass_context
def send(ctx, peer, message):
    """Send a single encrypted message to PEER."""
    asyncio.run(_do_send(ctx.obj["server"], _load_identity(ctx.obj["user"]), peer, message))


async def _do_send(server: str, local, peer: str, plaintext: str) -> None:
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
    status = "delivered" if resp.get("msg") == "delivered" else "queued"
    if resp["type"] == "ok":
        _ok(f"Message {C.GREEN}{status}{C.RESET} → {C.CYAN}{peer}{C.RESET}")
    else:
        _die(f"Send failed: {resp}")


# ─── fetch ────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def fetch(ctx):
    """Fetch and decrypt queued messages."""
    asyncio.run(_do_fetch(ctx.obj["server"], _load_identity(ctx.obj["user"])))


async def _do_fetch(server: str, local) -> None:
    async with Transport(server) as t:
        await t.rpc({"type": "register", "bundle": local.public_bundle()})
        resp = await t.rpc({"type": "fetch"})
    messages = resp.get("messages", [])
    if not messages:
        return _info("No queued messages.")
    _info(f"Decrypting {len(messages)} message(s) …")
    _divider()
    store = SessionStore(local.username)
    for env in messages:
        _process_envelope(local, store, env["from"], env["payload"], env.get("ts", ""))
    store.close()
    _divider()


# ─── chat ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("peer")
@click.pass_context
def chat(ctx, peer):
    """Open interactive end-to-end encrypted chat with PEER."""
    identity = _load_identity(ctx.obj["user"])
    _banner()

    # Dynamic-width chat header
    me = identity.username
    subtitle = "End-to-end encrypted · relay sees nothing"
    hint     = "/quit to exit"
    title    = f"  {me}  →  {peer}  "
    # Measure visible widths and pick the widest
    widest = max(_visible_len(title), _visible_len(subtitle) + 4, _visible_len(hint) + 4)

    def _pad_centre(text: str, width: int) -> str:
        vis = _visible_len(text)
        left  = (width - vis) // 2
        right = width - vis - left
        return " " * left + text + " " * right

    title_col    = f"{C.CYAN}{C.BOLD}{me}{C.RESET}  →  {C.GREEN}{C.BOLD}{peer}{C.RESET}"
    subtitle_col = f"{C.DIM}{subtitle}{C.RESET}"
    hint_col     = f"{C.DIM}{hint}{C.RESET}"

    _box([
        _pad_centre(title_col,    widest),
        _pad_centre(subtitle_col, widest),
        "",
        _pad_centre(hint_col,     widest),
    ])
    print()

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
    me = local.username

    async with Transport(server) as t:

        # ── Sequential setup (no background tasks yet) ────────────────────────
        resp = await t.rpc({"type": "register", "bundle": local.public_bundle()})
        if resp["type"] != "ok":
            _die("Server auth failed")

        store = SessionStore(me)

        # Flush offline messages from this peer
        resp = await t.rpc({"type": "fetch"})
        offline = [e for e in resp.get("messages", []) if e["from"] == peer]
        if offline:
            _info(f"{len(offline)} offline message(s) from {C.CYAN}{peer}{C.RESET}:")
            for env in offline:
                _process_envelope(local, store, env["from"], env["payload"], env.get("ts", ""))
            _divider()

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

        prompt_str = f"{C.CYAN}{me} › {C.RESET}"

        async def _printer():
            while not chat_stop.is_set():
                try:
                    frame = await asyncio.wait_for(inbox_q.get(), timeout=0.5)
                    # Clear current prompt line before printing
                    sys.stdout.write(f"\r{' ' * 80}\r")
                    sys.stdout.flush()
                    try:
                        _process_envelope(
                            local, store,
                            frame["from"], frame["payload"], frame.get("ts", ""),
                        )
                    except Exception as exc:
                        sys.stdout.write(f"  {C.RED}✗  Display error: {exc}{C.RESET}\n")
                    sys.stdout.flush()
                    # Reprint prompt
                    sys.stdout.write(prompt_str)
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
                print(prompt_str, end="", flush=True)
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                text = line.rstrip("\n")
                if not text:
                    continue
                if text.lower() in ("/quit", "/q", "/exit"):
                    break

                # ── Special commands ──────────────────────────────────────────
                if text.lower() == "/whoami":
                    print(f"\r{' ' * 80}\r  {C.CYAN}You are:{C.RESET} {C.BOLD}{me}{C.RESET}")
                    continue
                if text.lower() == "/help":
                    print(
                        f"\r{' ' * 80}\r"
                        f"  {C.GREY}Commands:{C.RESET}\n"
                        f"  {C.CYAN}/quit{C.RESET}    — exit chat\n"
                        f"  {C.CYAN}/whoami{C.RESET}  — show your username\n"
                        f"  {C.CYAN}/help{C.RESET}    — this message\n"
                    )
                    continue

                try:
                    # ── Lazy X3DH: only on very first send ───────────────────
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
                            print(f"\n  {C.RED}✗  {exc}{C.RESET}")
                            # Restart dispatcher and let user try again
                            dispatcher = _make_dispatcher()
                            continue

                        # Restart dispatcher
                        dispatcher = _make_dispatcher()

                    state = store.load_session(peer)
                    if state is None:
                        print(f"\n  {C.RED}✗  No session — try sending again{C.RESET}")
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
                    # Overwrite the input line with the formatted sent message
                    print(f"\033[1A\r{' ' * 80}\r{_fmt_msg(me, text, now, me=True)}")

                except Exception as exc:
                    print(f"\n  {C.RED}✗  Send error: {exc}{C.RESET}")

        except KeyboardInterrupt:
            pass
        finally:
            chat_stop.set()
            dispatcher.cancel()
            printer.cancel()
            store.close()

    print()
    _box([
        f"{C.DIM}Session ended.{C.RESET}",
        f"{C.DIM}Your messages are gone from this relay — E2E by design.{C.RESET}",
    ])
    print()


if __name__ == "__main__":
    cli(obj={})
