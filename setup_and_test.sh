#!/usr/bin/env bash
# ─── Channel — Setup & Test Script ───────────────────────────────────────────
# Run this from the project root:  bash setup_and_test.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[92m'
CYAN='\033[96m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "\n${CYAN}${BOLD}Channel — Setup & Test${RESET}\n"

# ── 1. Install dependencies ──────────────────────────────────────────────────
echo -e "${CYAN}[1/3] Installing Python dependencies…${RESET}"
pip install -q cryptography websockets click aiofiles
echo -e "${GREEN}✓ Dependencies installed${RESET}\n"

# ── 2. Run crypto test suite ─────────────────────────────────────────────────
echo -e "${CYAN}[2/3] Running crypto test suite…${RESET}"
python test_crypto.py
echo ""

# ── 3. Quick import smoke-test ───────────────────────────────────────────────
echo -e "${CYAN}[3/3] Import smoke-test (relay + CLI)…${RESET}"
python -c "
import sys
sys.path.insert(0, '.')
from server.relay import RelayServer
from client.cli import cli
from client.store import SessionStore
from client.transport import Transport
print('  All modules import cleanly.')
"
echo -e "${GREEN}✓ Smoke-test passed${RESET}\n"

echo -e "${BOLD}${GREEN}═══════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  All checks passed. Ready to demo!${RESET}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════${RESET}"
echo ""
echo -e "${CYAN}Quick start:${RESET}"
echo "  Terminal 1:  python server/relay.py"
echo "  Terminal 2:  python channel.py register alice"
echo "               python channel.py chat bob"
echo "  Terminal 3:  python channel.py register bob"
echo "               python channel.py chat alice"
echo ""
