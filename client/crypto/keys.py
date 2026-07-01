"""
Key generation and management for the Channel secure messaging protocol.

Uses:
  - X25519  for Diffie-Hellman key exchange (X3DH + Double Ratchet DH steps)
  - Ed25519 for signing (signed prekey in X3DH bundle)
"""

import os
import json
import base64
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization


# ─── Serialisation helpers ───────────────────────────────────────────────────

def pub_to_b64(key: X25519PublicKey | Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def priv_x25519_to_b64(key: X25519PrivateKey) -> str:
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def priv_ed25519_to_b64(key: Ed25519PrivateKey) -> str:
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def b64_to_pub_x25519(s: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(base64.b64decode(s))


def b64_to_pub_ed25519(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(s))


def b64_to_priv_x25519(s: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(base64.b64decode(s))


def b64_to_priv_ed25519(s: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(s))


# ─── Key bundle structures ────────────────────────────────────────────────────

@dataclass
class OPK:
    """One-time prekey pair."""
    opk_id: int
    private: X25519PrivateKey
    public: X25519PublicKey

    @classmethod
    def generate(cls, opk_id: int) -> "OPK":
        priv = X25519PrivateKey.generate()
        return cls(opk_id=opk_id, private=priv, public=priv.public_key())


@dataclass
class LocalIdentity:
    """
    Full local identity: contains all private keys.
    Stored encrypted on disk; never leaves the device.
    """
    username: str

    # Identity key (X25519) — used in X3DH DH steps
    ik_priv: X25519PrivateKey
    ik_pub: X25519PublicKey

    # Signing identity key (Ed25519) — signs the SPK
    ik_sign_priv: Ed25519PrivateKey
    ik_sign_pub: Ed25519PublicKey

    # Signed prekey (X25519)
    spk_priv: X25519PrivateKey
    spk_pub: X25519PublicKey
    spk_sig: bytes       # Ed25519 signature over spk_pub raw bytes
    spk_id: int

    # One-time prekeys
    opks: List[OPK] = field(default_factory=list)

    @classmethod
    def generate(cls, username: str, num_opks: int = 10) -> "LocalIdentity":
        ik_priv = X25519PrivateKey.generate()
        ik_sign_priv = Ed25519PrivateKey.generate()
        spk_priv = X25519PrivateKey.generate()
        spk_pub = spk_priv.public_key()
        spk_raw = spk_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        spk_sig = ik_sign_priv.sign(spk_raw)
        opks = [OPK.generate(i) for i in range(num_opks)]
        return cls(
            username=username,
            ik_priv=ik_priv,
            ik_pub=ik_priv.public_key(),
            ik_sign_priv=ik_sign_priv,
            ik_sign_pub=ik_sign_priv.public_key(),
            spk_priv=spk_priv,
            spk_pub=spk_pub,
            spk_sig=spk_sig,
            spk_id=0,
            opks=opks,
        )

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "ik_priv": priv_x25519_to_b64(self.ik_priv),
            "ik_pub": pub_to_b64(self.ik_pub),
            "ik_sign_priv": priv_ed25519_to_b64(self.ik_sign_priv),
            "ik_sign_pub": pub_to_b64(self.ik_sign_pub),
            "spk_priv": priv_x25519_to_b64(self.spk_priv),
            "spk_pub": pub_to_b64(self.spk_pub),
            "spk_sig": base64.b64encode(self.spk_sig).decode(),
            "spk_id": self.spk_id,
            "opks": [
                {
                    "id": o.opk_id,
                    "private": priv_x25519_to_b64(o.private),
                    "public": pub_to_b64(o.public),
                }
                for o in self.opks
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LocalIdentity":
        opks = [
            OPK(
                opk_id=o["id"],
                private=b64_to_priv_x25519(o["private"]),
                public=b64_to_pub_x25519(o["public"]),
            )
            for o in d["opks"]
        ]
        ik_priv = b64_to_priv_x25519(d["ik_priv"])
        ik_sign_priv = b64_to_priv_ed25519(d["ik_sign_priv"])
        spk_priv = b64_to_priv_x25519(d["spk_priv"])
        return cls(
            username=d["username"],
            ik_priv=ik_priv,
            ik_pub=ik_priv.public_key(),
            ik_sign_priv=ik_sign_priv,
            ik_sign_pub=ik_sign_priv.public_key(),
            spk_priv=spk_priv,
            spk_pub=spk_priv.public_key(),
            spk_sig=base64.b64decode(d["spk_sig"]),
            spk_id=d["spk_id"],
            opks=opks,
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        path.chmod(0o600)  # owner read/write only

    @classmethod
    def load(cls, path: Path) -> "LocalIdentity":
        return cls.from_dict(json.loads(path.read_text()))

    def public_bundle(self) -> dict:
        """
        The data published to the relay server so others can initiate X3DH.
        Contains only public keys + signature.
        """
        return {
            "username": self.username,
            "ik_pub": pub_to_b64(self.ik_pub),
            "ik_sign_pub": pub_to_b64(self.ik_sign_pub),
            "spk_pub": pub_to_b64(self.spk_pub),
            "spk_sig": base64.b64encode(self.spk_sig).decode(),
            "spk_id": self.spk_id,
            "opks": [
                {"id": o.opk_id, "pub": pub_to_b64(o.public)}
                for o in self.opks
            ],
        }

    def pop_opk(self, opk_id: int) -> Optional[OPK]:
        """Find and remove a one-time prekey by id."""
        for i, o in enumerate(self.opks):
            if o.opk_id == opk_id:
                return self.opks.pop(i)
        return None
