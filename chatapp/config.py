"""Static configuration and runtime path resolution.

No secrets are stored here. All key material lives under the per-user
runtime base directory with 0700 permissions and is never committed.
"""
from __future__ import annotations

import os
from pathlib import Path

# --- Wire protocol -------------------------------------------------------
# Every encrypted cell is padded to exactly this many plaintext bytes
# before ratchet encryption, so ciphertext length is constant.
CELL_PLAINTEXT_SIZE = 1024

# 1-byte cell type prefix inside the padded plaintext.
CELL_TYPE_DATA = 0x01      # carries a real chat message
CELL_TYPE_PADDING = 0x02   # dummy traffic, discarded by receiver
CELL_TYPE_CONTROL = 0x03   # handshake / control frames

# Length prefix (4 bytes, big-endian) frames each cell on the TCP stream.
LENGTH_PREFIX_BYTES = 4

# --- Adaptive padding (WTF-PAD-style) ------------------------------------
# Inter-cell delay is drawn from an exponential distribution clamped to
# this range (milliseconds).
PADDING_MIN_DELAY_MS = 200
PADDING_MAX_DELAY_MS = 2000
PADDING_MEAN_DELAY_MS = 700

# --- Tor ports (loopback only) -------------------------------------------
DEFAULT_APP_PORT = 12345          # receiver app listener (onion -> here)
DEFAULT_RECEIVER_SOCKS = 0        # 0 = disabled unless needed
DEFAULT_SENDER_SOCKS = 9050
DEFAULT_CONTROL_PORT = 9051
ONION_VIRTUAL_PORT = 80

TOR_BOOTSTRAP_TIMEOUT_S = 180


def runtime_base() -> Path:
    """Return the per-user runtime base (~/.zt-chat), creating it 0700."""
    base = Path(os.environ.get("ZT_CHAT_HOME", Path.home() / ".zt-chat"))
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def _subdir(name: str) -> Path:
    d = runtime_base() / name
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def tor_data_dir() -> Path:
    return _subdir("runtime")


def onion_auth_dir() -> Path:
    return _subdir("onion_auth")


def hidden_service_dir() -> Path:
    return _subdir("hidden_service")


def state_dir() -> Path:
    return _subdir("state")


def config_template_dir() -> Path:
    # config/ lives next to the package root.
    return Path(__file__).resolve().parent.parent / "config"
