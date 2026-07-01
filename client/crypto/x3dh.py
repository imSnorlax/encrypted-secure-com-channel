"""
X3DH (Extended Triple Diffie-Hellman) key agreement — Signal spec.

Reference: https://signal.org/docs/specifications/x3dh/

Alice (initiator) computes master secret using Bob's published bundle.
Bob (responder) computes the same master secret from Alice's initial message.

DH computations:
  DH1 = DH(IK_A,  SPK_B)
  DH2 = DH(EK_A,  IK_B)
  DH3 = DH(EK_A,  SPK_B)
  DH4 = DH(EK_A,  OPK_B)   ← if OPK was present

  SK = KDF(DH1 || DH2 || DH3 [|| DH4])

The SK is then used to initialise the Double Ratchet.
"""

import os
import base64
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from .keys import (
    LocalIdentity, OPK,
    pub_to_b64, b64_to_pub_x25519, b64_to_pub_ed25519, b64_to_priv_x25519,
    priv_x25519_to_b64,
)


# ─── Constants ────────────────────────────────────────────────────────────────

# 32 × 0xFF bytes prepended to DH output before KDF (Signal spec §2.2)
_F = b"\xff" * 32
_INFO = b"Channel_X3DH_v1"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _raw_pub(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _dh(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    return priv.exchange(pub)


def _kdf(*dh_outputs: bytes) -> bytes:
    """HKDF-SHA256 over the concatenation of DH outputs, prepended by F."""
    material = _F + b"".join(dh_outputs)
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=_INFO,
    ).derive(material)


def _verify_spk(
    ik_sign_pub: Ed25519PublicKey, spk_pub_raw: bytes, spk_sig: bytes
) -> None:
    """Raise InvalidSignature if the SPK signature is bad."""
    ik_sign_pub.verify(spk_sig, spk_pub_raw)


# ─── Initiator (Alice) ────────────────────────────────────────────────────────

def x3dh_send(
    local: LocalIdentity,
    remote_bundle: dict,
) -> Tuple[bytes, dict]:
    """
    Alice initiates a session with Bob.

    Args:
        local:         Alice's full local identity.
        remote_bundle: Bob's public key bundle from the relay.

    Returns:
        (session_key, initial_message_header)
        session_key       — 32-byte shared secret, feeds into Double Ratchet init
        initial_message_header — extra fields Alice must attach to her first message
                                 so Bob can reconstruct the shared secret.
    """
    # Parse Bob's bundle
    ik_b = b64_to_pub_x25519(remote_bundle["ik_pub"])
    ik_sign_b = b64_to_pub_ed25519(remote_bundle["ik_sign_pub"])
    spk_b = b64_to_pub_x25519(remote_bundle["spk_pub"])
    spk_sig = base64.b64decode(remote_bundle["spk_sig"])
    spk_id = remote_bundle["spk_id"]

    # Verify SPK signature — abort if Bob's bundle was tampered with
    _verify_spk(ik_sign_b, _raw_pub(spk_b), spk_sig)

    # Choose OPK if available
    opk_b: Optional[X25519PublicKey] = None
    opk_id: Optional[int] = None
    if remote_bundle.get("opks"):
        opk_entry = remote_bundle["opks"][0]   # relay provides one
        opk_b = b64_to_pub_x25519(opk_entry["pub"])
        opk_id = opk_entry["id"]

    # Generate ephemeral key
    ek_priv = X25519PrivateKey.generate()
    ek_pub = ek_priv.public_key()

    # Four DH computations
    dh1 = _dh(local.ik_priv, spk_b)
    dh2 = _dh(ek_priv, ik_b)
    dh3 = _dh(ek_priv, spk_b)

    dh_inputs = [dh1, dh2, dh3]
    if opk_b is not None:
        dh_inputs.append(_dh(ek_priv, opk_b))

    sk = _kdf(*dh_inputs)

    header = {
        "ik_pub":   pub_to_b64(local.ik_pub),
        "ek_pub":   pub_to_b64(ek_pub),
        "spk_id":   spk_id,
        "opk_id":   opk_id,
    }
    return sk, header


# ─── Responder (Bob) ──────────────────────────────────────────────────────────

def x3dh_receive(
    local: LocalIdentity,
    header: dict,
) -> Tuple[bytes, Optional[OPK]]:
    """
    Bob reconstructs the shared secret from Alice's initial message header.

    Args:
        local:  Bob's full local identity.
        header: The x3dh_header field from Alice's first message.

    Returns:
        (session_key, used_opk_or_None)
        The caller must remove the used OPK from Bob's local store.
    """
    ik_a = b64_to_pub_x25519(header["ik_pub"])
    ek_a = b64_to_pub_x25519(header["ek_pub"])
    opk_id: Optional[int] = header.get("opk_id")

    # Recover OPK private key
    opk: Optional[OPK] = None
    if opk_id is not None:
        opk = local.pop_opk(opk_id)
        if opk is None:
            raise ValueError(f"OPK id={opk_id} not found — already consumed?")

    # Mirror Alice's four DH steps
    dh1 = _dh(local.spk_priv, ik_a)
    dh2 = _dh(local.ik_priv, ek_a)
    dh3 = _dh(local.spk_priv, ek_a)

    dh_inputs = [dh1, dh2, dh3]
    if opk is not None:
        dh_inputs.append(_dh(opk.private, ek_a))

    sk = _kdf(*dh_inputs)
    return sk, opk
