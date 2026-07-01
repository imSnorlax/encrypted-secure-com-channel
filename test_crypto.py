"""
Crypto test suite — run this before anything else.
Validates X3DH key agreement and Double Ratchet correctness.

Usage:
    python test_crypto.py
"""

import sys
import os

# Allow running from the project root
sys.path.insert(0, os.path.dirname(__file__))

from client.crypto.keys import LocalIdentity
from client.crypto.x3dh import x3dh_send, x3dh_receive
from client.crypto.double_ratchet import (
    RatchetState, encrypt_message, decrypt_message
)


PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

_failures = []


def check(label: str, condition: bool) -> None:
    if condition:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  {label}  ← FAILED")
        _failures.append(label)


# ─── Key generation ──────────────────────────────────────────────────────────

def test_key_generation():
    print("\n[1] Key generation & serialisation")
    alice = LocalIdentity.generate("alice", num_opks=5)
    check("Identity generated", alice.username == "alice")
    check("Has 5 OPKs", len(alice.opks) == 5)

    d = alice.to_dict()
    alice2 = LocalIdentity.from_dict(d)
    check("Round-trip serialise/deserialise", alice2.username == "alice")
    check("OPKs preserved", len(alice2.opks) == 5)

    bundle = alice.public_bundle()
    check("Public bundle has required fields",
          all(k in bundle for k in ["ik_pub", "ik_sign_pub", "spk_pub", "spk_sig", "opks"]))


# ─── X3DH ────────────────────────────────────────────────────────────────────

def test_x3dh_with_opk():
    print("\n[2] X3DH with one-time prekey")
    alice = LocalIdentity.generate("alice", num_opks=3)
    bob   = LocalIdentity.generate("bob",   num_opks=3)

    bob_bundle = bob.public_bundle()
    sk_alice, header = x3dh_send(alice, bob_bundle)
    sk_bob, used_opk = x3dh_receive(bob, header)

    check("Shared secrets match", sk_alice == sk_bob)
    check("Key length is 32 bytes", len(sk_alice) == 32)
    check("OPK was consumed", used_opk is not None)
    check("Bob has 2 OPKs remaining", len(bob.opks) == 2)

    return sk_alice, alice, bob


def test_x3dh_without_opk():
    print("\n[3] X3DH without one-time prekey")
    alice = LocalIdentity.generate("alice", num_opks=0)
    bob   = LocalIdentity.generate("bob",   num_opks=0)

    bob_bundle = bob.public_bundle()
    # Bundle has no OPKs
    check("Bundle has empty OPKs", len(bob_bundle["opks"]) == 0)

    sk_alice, header = x3dh_send(alice, bob_bundle)
    sk_bob, used_opk = x3dh_receive(bob, header)

    check("Shared secrets match (no OPK)", sk_alice == sk_bob)
    check("OPK not used", used_opk is None)


def test_x3dh_tampered_bundle():
    print("\n[4] X3DH rejects tampered SPK signature")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")

    bundle = bob.public_bundle()
    # Replace SPK with a fresh one (signature no longer valid)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from client.crypto.keys import pub_to_b64
    fake_spk = X25519PrivateKey.generate().public_key()
    bundle["spk_pub"] = pub_to_b64(fake_spk)

    raised = False
    try:
        x3dh_send(alice, bundle)
    except Exception:
        raised = True
    check("Tampered bundle rejected", raised)


# ─── Double Ratchet ──────────────────────────────────────────────────────────

def _init_ratchet_pair(sk: bytes, alice: LocalIdentity, bob: LocalIdentity):
    """Initialise Alice→sender, Bob→receiver ratchet pair."""
    alice_state = RatchetState.init_sender(sk, bob.spk_pub)
    bob_state   = RatchetState.init_receiver(sk, bob.spk_priv, bob.spk_pub)
    return alice_state, bob_state


def test_ratchet_basic():
    print("\n[5] Double Ratchet: basic send/receive")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    bob_bundle = bob.public_bundle()
    sk, header = x3dh_send(alice, bob_bundle)
    x3dh_receive(bob, header)

    alice_s, bob_s = _init_ratchet_pair(sk, alice, bob)

    msg = b"Hello, Bob! This is a secret."
    hdr, ct, alice_s = encrypt_message(alice_s, msg)
    pt, bob_s = decrypt_message(bob_s, hdr, ct)
    check("Basic encrypt/decrypt", pt == msg)

    # Bob replies
    reply = b"Hey Alice, got it!"
    hdr2, ct2, bob_s = encrypt_message(bob_s, reply)
    pt2, alice_s = decrypt_message(alice_s, hdr2, ct2)
    check("Reply decrypt (DH ratchet stepped)", pt2 == reply)


def test_ratchet_multi_messages():
    print("\n[6] Double Ratchet: multiple messages, both directions")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    sk, header = x3dh_send(alice, bob.public_bundle())
    x3dh_receive(bob, header)
    alice_s, bob_s = _init_ratchet_pair(sk, alice, bob)

    # Alice sends 5 messages
    messages = [f"Message {i} from Alice".encode() for i in range(5)]
    ciphertexts = []
    for m in messages:
        hdr, ct, alice_s = encrypt_message(alice_s, m)
        ciphertexts.append((hdr, ct))

    for i, (hdr, ct) in enumerate(ciphertexts):
        pt, bob_s = decrypt_message(bob_s, hdr, ct)
        check(f"  Alice→Bob msg {i}", pt == messages[i])

    # Bob sends 5 messages
    b_messages = [f"Reply {i} from Bob".encode() for i in range(5)]
    b_cts = []
    for m in b_messages:
        hdr, ct, bob_s = encrypt_message(bob_s, m)
        b_cts.append((hdr, ct))

    for i, (hdr, ct) in enumerate(b_cts):
        pt, alice_s = decrypt_message(alice_s, hdr, ct)
        check(f"  Bob→Alice msg {i}", pt == b_messages[i])


def test_ratchet_out_of_order():
    print("\n[7] Double Ratchet: out-of-order delivery")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    sk, header = x3dh_send(alice, bob.public_bundle())
    x3dh_receive(bob, header)
    alice_s, bob_s = _init_ratchet_pair(sk, alice, bob)

    # Alice sends 4 messages
    pkts = []
    for i in range(4):
        hdr, ct, alice_s = encrypt_message(alice_s, f"msg{i}".encode())
        pkts.append((hdr, ct, f"msg{i}".encode()))

    # Bob receives in reverse order: 3, 2, 1, 0
    for i in reversed(range(4)):
        hdr, ct, expected = pkts[i]
        pt, bob_s = decrypt_message(bob_s, hdr, ct)
        check(f"  Out-of-order msg {i}", pt == expected)


def test_ratchet_wrong_key():
    print("\n[8] Double Ratchet: ciphertext tamper detection")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    sk, header = x3dh_send(alice, bob.public_bundle())
    x3dh_receive(bob, header)
    alice_s, bob_s = _init_ratchet_pair(sk, alice, bob)

    hdr, ct, alice_s = encrypt_message(alice_s, b"secret")
    # Flip a byte in the ciphertext
    ct_bad = bytes([ct[0] ^ 0xFF]) + ct[1:]
    raised = False
    try:
        decrypt_message(bob_s, hdr, ct_bad)
    except Exception:
        raised = True
    check("Tampered ciphertext rejected (AEAD)", raised)


def test_ratchet_serialisation():
    print("\n[9] Ratchet state serialisation (persistence)")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    sk, header = x3dh_send(alice, bob.public_bundle())
    x3dh_receive(bob, header)
    alice_s, bob_s = _init_ratchet_pair(sk, alice, bob)

    hdr, ct, alice_s = encrypt_message(alice_s, b"persist test")

    # Serialise and restore Bob's state
    import json
    bob_dict = bob_s.to_dict()
    bob_s2 = RatchetState.from_dict(bob_dict)

    pt, _ = decrypt_message(bob_s2, hdr, ct)
    check("Decrypt after state round-trip", pt == b"persist test")


def test_different_sessions_isolated():
    print("\n[10] Independent sessions don't share keys")
    alice = LocalIdentity.generate("alice")
    bob   = LocalIdentity.generate("bob")
    carol = LocalIdentity.generate("carol")

    sk_ab, h_ab = x3dh_send(alice, bob.public_bundle())
    sk_ac, h_ac = x3dh_send(alice, carol.public_bundle())
    x3dh_receive(bob, h_ab)
    x3dh_receive(carol, h_ac)

    check("Alice-Bob ≠ Alice-Carol session keys", sk_ab != sk_ac)

    a_b_s, b_s = _init_ratchet_pair(sk_ab, alice, bob)
    a_c_s, c_s = _init_ratchet_pair(sk_ac, alice, carol)

    hdr1, ct1, a_b_s = encrypt_message(a_b_s, b"for bob only")
    hdr2, ct2, a_c_s = encrypt_message(a_c_s, b"for carol only")

    pt_b, _ = decrypt_message(b_s, hdr1, ct1)
    pt_c, _ = decrypt_message(c_s, hdr2, ct2)

    check("Bob decrypts his message", pt_b == b"for bob only")
    check("Carol decrypts her message", pt_c == b"for carol only")

    # Neither can decrypt the other's message
    raised_b = False
    try:
        decrypt_message(b_s, hdr2, ct2)
    except Exception:
        raised_b = True
    check("Bob cannot decrypt Carol's message", raised_b)


# ─── Runner ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Channel — Crypto Test Suite")
    print("=" * 60)

    test_key_generation()
    test_x3dh_with_opk()
    test_x3dh_without_opk()
    test_x3dh_tampered_bundle()
    test_ratchet_basic()
    test_ratchet_multi_messages()
    test_ratchet_out_of_order()
    test_ratchet_wrong_key()
    test_ratchet_serialisation()
    test_different_sessions_isolated()

    print("\n" + "=" * 60)
    if _failures:
        print(f"  RESULT: {len(_failures)} FAILED — {_failures}")
        sys.exit(1)
    else:
        print(f"  RESULT: ALL TESTS PASSED ✓")
    print("=" * 60)
