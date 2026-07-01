# Channel

> **Signal-style end-to-end encrypted CLI messenger**  
> X3DH key agreement · Double Ratchet · AES-256-GCM · Ed25519 signatures

Built as a clean, auditable implementation of the protocols powering Signal — zero dependencies on Signal's own libraries.

---

## Crypto Stack

| Layer | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 (ECDH) | X3DH DH steps + Double Ratchet DH ratchet |
| Signing | Ed25519 | Signed prekey (SPK) verification |
| AEAD | AES-256-GCM | Message encryption + integrity |
| KDF | HKDF-SHA256 | Root key, chain key, message key derivation |
| Protocol | X3DH + Double Ratchet | Full Signal-spec session establishment |

### Why these choices?
- **X25519**: No weak-curve risk, fast, constant-time in OpenSSL/libsodium
- **Ed25519**: Deterministic signatures, no k-reuse vulnerability (unlike ECDSA)
- **AES-256-GCM**: Hardware-accelerated on modern CPUs, authenticated
- **HKDF not bare SHA**: Proper domain separation between root/chain/message keys
- **OPKs (one-time prekeys)**: Provide forward secrecy even if long-term keys are compromised

### What the relay server sees
```
✗ Message content   (AES-256-GCM encrypted)
✗ Conversation keys  (never transmitted)
✓ Usernames          (for routing only)
✓ Public key bundles (public by design)
✓ Ciphertext blobs   (meaningless without keys)
```

---

## Project Structure

```
channel/
├── channel.py               # CLI entry point
├── test_crypto.py           # Crypto test suite (run this first!)
├── requirements.txt
├── server/
│   └── relay.py             # WebSocket relay — routes ciphertext only
└── client/
    ├── cli.py               # CLI commands
    ├── store.py             # SQLite ratchet state persistence
    ├── transport.py         # WebSocket client wrapper
    └── crypto/
        ├── keys.py          # Key generation & serialisation
        ├── x3dh.py          # Extended Triple DH
        └── double_ratchet.py # Double Ratchet state machine
```

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run crypto tests first (validates all protocol logic)
python test_crypto.py
```

---

## Usage

### Terminal 1 — Start the relay server
```bash
python server/relay.py
# Relay starts on ws://127.0.0.1:8765
```

### Terminal 2 — Alice registers and chats
```bash
python channel.py register alice
python channel.py chat bob
```

### Terminal 3 — Bob registers and chats
```bash
python channel.py register bob
python channel.py chat alice
```

### Other commands
```bash
# Send a single message (non-interactive)
python channel.py send bob "hey"

# Fetch queued messages (when recipient was offline)
python channel.py fetch

# Show your identity info
python channel.py whoami

# List open sessions
python channel.py sessions

# Use a remote server
python channel.py --server ws://192.168.1.5:8765 chat bob
# or set env var:
CHANNEL_SERVER=ws://192.168.1.5:8765 python channel.py chat bob
```

---

## How It Works

### Session Initiation (X3DH)

When Alice messages Bob for the first time:

```
Alice fetches Bob's public bundle from relay:
  { IK_B, IK_sign_B, SPK_B, sig(SPK_B), [OPK_B] }

Alice verifies: Ed25519.verify(IK_sign_B, SPK_B, sig)

Alice computes 4 DH outputs:
  DH1 = X25519(IK_A_priv,  SPK_B_pub)
  DH2 = X25519(EK_A_priv,  IK_B_pub)
  DH3 = X25519(EK_A_priv,  SPK_B_pub)
  DH4 = X25519(EK_A_priv,  OPK_B_pub)

SK = HKDF(F || DH1 || DH2 || DH3 || DH4)

Alice sends to relay → Bob:
  { IK_A_pub, EK_A_pub, spk_id, opk_id, [DR header], ciphertext }

Bob reconstructs SK with the mirror DH steps.
```

### Ongoing Messaging (Double Ratchet)

Every message:
1. **Symmetric ratchet** — HMAC-SHA256 chain advances, derives new message key
2. **DH ratchet** — on each reply, new X25519 key pair generated, new root derived

This gives:
- **Forward secrecy**: Old message keys deleted after use
- **Break-in recovery**: Compromise of current keys doesn't expose future messages
- **Out-of-order delivery**: Skipped keys cached (up to 1000)

---

## Security Properties

| Property | Status |
|---|---|
| End-to-end encryption | ✅ Relay never sees plaintext |
| Forward secrecy | ✅ Per-message key deletion |
| Future secrecy (break-in recovery) | ✅ DH ratchet on each reply |
| Authentication | ✅ SPK signed by Ed25519 identity key |
| Replay protection | ✅ GCM nonces + message counters |
| Out-of-order delivery | ✅ Skipped-key cache (MAX_SKIP=1000) |
| OPK deniability | ✅ One-time prekeys consumed immediately |

---

## Running Tests

```bash
python test_crypto.py
```

The suite covers:
- Key generation & round-trip serialisation
- X3DH with and without OPKs
- X3DH tampered bundle rejection
- Double Ratchet: basic, multi-message, bidirectional
- Out-of-order message delivery
- Ciphertext tamper detection (AEAD)
- Ratchet state persistence
- Session isolation between different peers

---

## LinkedIn Demo Script

```bash
# Window 1
python server/relay.py

# Window 2 (Alice)
python channel.py register alice
python channel.py chat bob

# Window 3 (Bob)  
python channel.py register bob
python channel.py chat alice
```

Key things to highlight:
1. `test_crypto.py` passing — protocol correctness
2. Server logs show only `"from": "alice"` + opaque blobs — zero plaintext
3. `channel.py whoami` shows Ed25519 fingerprint — verifiable identity
4. Messages survive if recipient is offline (`fetch` command)

---

*Implemented against the Signal protocol specifications:*  
*[signal.org/docs/specifications/x3dh](https://signal.org/docs/specifications/x3dh/)*  
*[signal.org/docs/specifications/doubleratchet](https://signal.org/docs/specifications/doubleratchet/)*
