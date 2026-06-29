"""Interactive chat session: wires crypto + padding + transport together.

Protocol over the established stream (all cells fixed-size, ratchet-
encrypted once the channel is up):

  1. Sender -> Receiver: CONTROL 'PREKEY_REQ' (plaintext, pre-ratchet)
  2. Receiver -> Sender: CONTROL prekey bundle (plaintext, pre-ratchet)
  3. Sender verifies fingerprint, runs X3DH, sends initial handshake.
  4. Both run the padding scheduler and exchange DATA/PADDING cells.

The handshake frames (steps 1-3) are sent as raw length-prefixed frames;
after the ratchet is live, every frame is an encrypted fixed-size cell.
"""
from __future__ import annotations

import sys
import threading

from . import config, padding
from .crypto import SecureChannel, verify_fingerprint
from .transport import CellStream

PREKEY_REQ = b"PREKEY_REQ"


class ChatSession:
    def __init__(self, stream: CellStream, channel: SecureChannel):
        self._stream = stream
        self._channel = channel
        self._scheduler = padding.PaddingScheduler(self._send_cell)
        self._stop = threading.Event()

    # --- cell I/O ------------------------------------------------------
    def _send_cell(self, cell_type: int, payload: bytes) -> None:
        plaintext = padding.pad_plaintext(payload, cell_type)
        ciphertext = self._channel.encrypt(plaintext)
        self._stream.send_ciphertext(ciphertext)

    def _recv_loop(self) -> None:
        import time
        while not self._stop.is_set():
            ct = self._stream.recv_ciphertext()
            if ct is None:
                sys.stdout.write("\r\033[K\n\033[1;31m[!] Peer disconnected. Session ended.\033[0m\n")
                sys.stdout.flush()
                self._stop.set()
                break
            try:
                pt = self._channel.decrypt(ct)
                cell_type, payload = padding.unpad_plaintext(pt)
                if cell_type == config.CELL_TYPE_DATA:
                    timestamp = time.strftime("%H:%M:%S")
                    msg_text = payload.decode(errors="replace")
                    # Clear line, print timestamped peer message, then restore colored prompt
                    sys.stdout.write(f"\r\033[K\033[90m[{timestamp}]\033[0m \033[1;32mpeer>\033[0m {msg_text}\n")
                    sys.stdout.write("\033[1;34myou>\033[0m ")
                    sys.stdout.flush()
                # PADDING cells are silently discarded.
            except Exception as e:
                sys.stdout.write(f"\r\033[K\033[1;31m[-] Decryption error: {e}\033[0m\n")
                sys.stdout.write("\033[1;34myou>\033[0m ")
                sys.stdout.flush()

    # --- run -----------------------------------------------------------
    def run(self) -> None:
        print("\n\033[1;32m┌────────────────────────────────────────────────────────┐\033[0m")
        print("\033[1;32m│            SECURE DOUBLE RATChET SESSION ACTIVE        │\033[0m")
        print("\033[1;32m├────────────────────────────────────────────────────────┤\033[0m")
        print("\033[1;32m│  * All traffic padded to constant 1024-byte cells.     │\033[0m")
        print("\033[1;32m│  * Adaptive cover traffic padding scheduler running.  │\033[0m")
        print("\033[1;32m│  * Type /quit or /exit to cleanly close.               │\033[0m")
        print("\033[1;32m└────────────────────────────────────────────────────────┘\033[0m\n")

        self._scheduler.start()
        rx = threading.Thread(target=self._recv_loop, daemon=True)
        rx.start()
        try:
            while not self._stop.is_set():
                try:
                    line = input("\033[1;34myou>\033[0m ")
                except (EOFError, KeyboardInterrupt):
                    break
                if self._stop.is_set():
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped in ("/quit", "/exit"):
                    break
                self._scheduler.enqueue(line.encode())
        finally:
            self._stop.set()
            self._scheduler.stop()
            self._stream.close()
            self._channel.wipe()

