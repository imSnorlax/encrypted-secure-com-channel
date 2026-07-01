"""
Double Ratchet Algorithm — Signal spec.

Reference: https://signal.org/docs/specifications/doubleratchet/

State machine with two interlocked ratchets:
  1. Symmetric-key ratchet  — advances every message (sending & receiving chains)
  2. DH ratchet             — advances every round-trip (new DH key pair per send)

Message encryption:  AES-256-GCM (AEAD)
Header encryption:   AES-256-GCM with a separate header key ratchet
KDF chain:           HKDF-SHA256
"""

import os
import json
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .keys import (
    b64_to_pub_x25519, b64_to_priv_x25519,
    pub_to_b64, priv_x25519_to_b64,
)


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_SKIP = 1000          # max skipped messages to cache keys for
_INFO_RK  = b"Channel_DR_RootKey_v1"
_INFO_MSG = b"Channel_DR_MsgKey_v1"


# ─── KDF primitives ──────────────────────────────────────────────────────────

def _kdf_rk(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    Root KDF: derive new root key + chain key from a DH output.
    Returns (new_root_key, chain_key), each 32 bytes.
    """
    out = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=root_key,
        info=_INFO_RK,
    ).derive(dh_out)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    Chain KDF: HMAC-SHA256-based ratchet step.
    Returns (new_chain_key, message_key), each 32 bytes.

    Uses constant input bytes per the Signal spec to separate the two outputs.
    """
    def _hmac(key: bytes, msg: bytes) -> bytes:
        h = HMAC(key, SHA256(), backend=default_backend())
        h.update(msg)
        return h.finalize()

    new_ck  = _hmac(chain_key, b"\x02")
    msg_key = _hmac(chain_key, b"\x01")
    return new_ck, msg_key


# ─── AEAD helpers ────────────────────────────────────────────────────────────

def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext+tag."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def _decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Input is nonce || ciphertext+tag."""
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def _raw_pub(key: X25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# ─── Ratchet state ────────────────────────────────────────────────────────────

@dataclass
class RatchetState:
    """
    Full Double Ratchet state for one session.
    Persisted to disk after every send/receive.
    """
    # DH ratchet
    dh_self_priv: X25519PrivateKey
    dh_self_pub:  X25519PublicKey
    dh_remote_pub: Optional[X25519PublicKey]

    # Chain keys  (None until first ratchet step)
    root_key:   bytes
    send_ck:    Optional[bytes]
    recv_ck:    Optional[bytes]

    # Message counters
    send_n: int = 0          # messages sent in current send chain
    recv_n: int = 0          # messages received in current recv chain
    prev_send_n: int = 0     # send_n before last DH ratchet step

    # Out-of-order message key cache: {(dh_pub_b64, msg_n): msg_key}
    skipped: Dict[Tuple[str, int], bytes] = field(default_factory=dict)

    @classmethod
    def init_sender(
        cls,
        sk: bytes,
        remote_pub: X25519PublicKey,
    ) -> "RatchetState":
        """Alice initialises after X3DH."""
        dh_self_priv = X25519PrivateKey.generate()
        dh_out = dh_self_priv.exchange(remote_pub)
        rk, send_ck = _kdf_rk(sk, dh_out)
        return cls(
            dh_self_priv=dh_self_priv,
            dh_self_pub=dh_self_priv.public_key(),
            dh_remote_pub=remote_pub,
            root_key=rk,
            send_ck=send_ck,
            recv_ck=None,
        )

    @classmethod
    def init_receiver(
        cls,
        sk: bytes,
        local_spk_priv: X25519PrivateKey,
        local_spk_pub:  X25519PublicKey,
    ) -> "RatchetState":
        """Bob initialises after X3DH (uses SPK as initial DH ratchet key)."""
        return cls(
            dh_self_priv=local_spk_priv,
            dh_self_pub=local_spk_pub,
            dh_remote_pub=None,
            root_key=sk,
            send_ck=None,
            recv_ck=None,
        )

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        def _skipped_serial(skipped: dict) -> list:
            return [
                {"dh_pub": k[0], "n": k[1], "key": base64.b64encode(v).decode()}
                for k, v in skipped.items()
            ]

        return {
            "dh_self_priv": priv_x25519_to_b64(self.dh_self_priv),
            "dh_self_pub":  pub_to_b64(self.dh_self_pub),
            "dh_remote_pub": pub_to_b64(self.dh_remote_pub) if self.dh_remote_pub else None,
            "root_key":  base64.b64encode(self.root_key).decode(),
            "send_ck":   base64.b64encode(self.send_ck).decode() if self.send_ck else None,
            "recv_ck":   base64.b64encode(self.recv_ck).decode() if self.recv_ck else None,
            "send_n":    self.send_n,
            "recv_n":    self.recv_n,
            "prev_send_n": self.prev_send_n,
            "skipped":   _skipped_serial(self.skipped),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetState":
        dh_self_priv = b64_to_priv_x25519(d["dh_self_priv"])
        skipped = {
            (e["dh_pub"], e["n"]): base64.b64decode(e["key"])
            for e in d.get("skipped", [])
        }
        return cls(
            dh_self_priv=dh_self_priv,
            dh_self_pub=dh_self_priv.public_key(),
            dh_remote_pub=(
                b64_to_pub_x25519(d["dh_remote_pub"])
                if d["dh_remote_pub"] else None
            ),
            root_key=base64.b64decode(d["root_key"]),
            send_ck=(base64.b64decode(d["send_ck"]) if d["send_ck"] else None),
            recv_ck=(base64.b64decode(d["recv_ck"]) if d["recv_ck"] else None),
            send_n=d["send_n"],
            recv_n=d["recv_n"],
            prev_send_n=d["prev_send_n"],
            skipped=skipped,
        )


# ─── Ratchet operations ──────────────────────────────────────────────────────

def encrypt_message(state: RatchetState, plaintext: bytes) -> Tuple[dict, bytes, RatchetState]:
    """
    Encrypt a message, advancing the symmetric-key ratchet.

    Returns (header, ciphertext, updated_state).
    header + ciphertext must be sent alongside each other.
    """
    assert state.send_ck is not None, "Sender chain not initialised"

    state.send_ck, msg_key = _kdf_ck(state.send_ck)

    header = {
        "dh_pub": pub_to_b64(state.dh_self_pub),
        "pn":     state.prev_send_n,
        "n":      state.send_n,
    }
    state.send_n += 1

    # AAD = canonical JSON of header (protects header integrity)
    aad = json.dumps(header, sort_keys=True).encode()
    ciphertext = _encrypt(msg_key, plaintext, aad)

    return header, ciphertext, state


def decrypt_message(
    state: RatchetState,
    header: dict,
    ciphertext: bytes,
) -> Tuple[bytes, RatchetState]:
    """
    Decrypt a message, advancing ratchet state as needed.
    Handles out-of-order delivery via skipped-key cache.
    """
    aad = json.dumps(header, sort_keys=True).encode()

    # 1. Check skipped-key cache first
    key = (header["dh_pub"], header["n"])
    if key in state.skipped:
        msg_key = state.skipped.pop(key)
        plaintext = _decrypt(msg_key, ciphertext, aad)
        return plaintext, state

    incoming_dh = b64_to_pub_x25519(header["dh_pub"])

    # 2. If DH ratchet key has changed → perform DH ratchet step
    current_remote_b64 = (
        pub_to_b64(state.dh_remote_pub) if state.dh_remote_pub else None
    )
    if current_remote_b64 != header["dh_pub"]:
        # Skip remaining messages in the current recv chain
        state = _skip_message_keys(state, header["pn"])
        state = _dh_ratchet(state, incoming_dh)

    # 3. Skip ahead in the new recv chain if messages arrived out of order
    state = _skip_message_keys(state, header["n"])

    # 4. Advance recv chain to decrypt this message
    assert state.recv_ck is not None, "Receive chain not ready"
    state.recv_ck, msg_key = _kdf_ck(state.recv_ck)
    state.recv_n += 1

    plaintext = _decrypt(msg_key, ciphertext, aad)
    return plaintext, state


def _skip_message_keys(state: RatchetState, until: int) -> RatchetState:
    """Cache keys for messages we haven't received yet (out-of-order)."""
    if state.recv_ck is None:
        return state
    if until - state.recv_n > MAX_SKIP:
        raise ValueError(f"Too many skipped messages: {until - state.recv_n}")
    while state.recv_n < until:
        state.recv_ck, mk = _kdf_ck(state.recv_ck)
        state.skipped[(pub_to_b64(state.dh_remote_pub), state.recv_n)] = mk
        state.recv_n += 1
    return state


def _dh_ratchet(state: RatchetState, remote_pub: X25519PublicKey) -> RatchetState:
    """Perform a DH ratchet step: new recv chain then new send chain."""
    state.prev_send_n = state.send_n
    state.send_n = 0
    state.recv_n = 0
    state.dh_remote_pub = remote_pub

    # Derive new recv chain
    dh_recv = state.dh_self_priv.exchange(remote_pub)
    state.root_key, state.recv_ck = _kdf_rk(state.root_key, dh_recv)

    # Generate new DH key pair and derive new send chain
    state.dh_self_priv = X25519PrivateKey.generate()
    state.dh_self_pub = state.dh_self_priv.public_key()
    dh_send = state.dh_self_priv.exchange(remote_pub)
    state.root_key, state.send_ck = _kdf_rk(state.root_key, dh_send)

    return state
