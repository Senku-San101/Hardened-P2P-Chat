"""Entrypoint: choose sender or receiver, set up Tor + crypto, then chat."""
from __future__ import annotations

import socket
import struct
import sys
import time

from . import config
from .crypto import SecureChannel
from .oob import OOBBundle, print_oob
from .session import ChatSession, PREKEY_REQ
from .tor import TorManager, generate_client_auth_keypair
from .transport import CellStream, connect_via_socks, listen_loopback

# --- Cyberpunk Terminal Colorized Banner ---
RAW_BANNER = r''' .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. 
/ .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \
\ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
 \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / 
 / /\  M""MMMMM""MM                         dP                                  dP   / /\ 
/ /\ \ M  MMMMM  MM                         88                                  88  / /\ \
\ \/ / M         `M .d8888b. 88d888b. .d888b88 .d8888b. 88d888b. .d8888b. .d888b88  \ \/ /
 \/ /  M  MMMMM  MM 88'  `88 88'  `88 88'  `88 88ooood8 88'  `88 88ooood8 88'  `88   \/ / 
 / /\  M  MMMMM  MM 88.  .88 88       88.  .88 88.  ... 88    88 88.  ... 88.  .88   / /\ 
/ /\ \ M  MMMMM  MM `88888P8 dP       `88888P8 `88888P' dP    dP `88888P' `88888P8  / /\ \
\ \/ / MMMMMMMMMMMM                                                                 \ \/ /
 \/ /                                                                                \/ / 
 / /\  MM"""""""`YM d8888b. MM"""""""`YM    MM'""""'YMM dP                  dP       / /\ 
/ /\ \ MM  mmmmm  M     `88 MM  mmmmm  M    M' .mmm. `M 88                  88      / /\ \
\ \/ / M'        .M .aaadP' M'        .M    M  MMMMMooM 88d888b. .d8888b. d8888P    \ \/ /
 \/ /  MM  MMMMMMMM 88'     MM  MMMMMMMM    M  MMMMMMMM 88'  `88 88'  `88   88       \/ / 
 / /\  MM  MMMMMMMM 88.     MM  MMMMMMMM    M. `MMM' .M 88    88 88.  .88   88       / /\ 
/ /\ \ MM  MMMMMMMM Y88888P MM  MMMMMMMM    MM.     .dM dP    dP `88888P8   dP      / /\ \
\ \/ / MMMMMMMMMMMM         MMMMMMMMMMMM    MMMMMMMMMMM                             \ \/ /
 \/ /                                                                                \/ / 
 / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ 
/ /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \
\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
 `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--' '''


def print_colored_banner() -> None:
    cyan = "\033[36m"
    green = "\033[92m"
    reset = "\033[0m"
    
    banner_lines = RAW_BANNER.strip("\n").splitlines()
    for i, line in enumerate(banner_lines):
        if i in range(4, 20):
            # Middle lines with borders
            border_left = line[:7]
            center = line[7:74]
            border_right = line[74:]
            print(f"{cyan}{border_left}{green}{center}{cyan}{border_right}{reset}")
        else:
            # Border-only lines (top, bottom)
            print(f"{cyan}{line}{reset}")


# --- UX Logging Helpers ---
def log_info(msg: str) -> None:
    print(f"\033[1;34m[*]\033[0m {msg}")

def log_success(msg: str) -> None:
    print(f"\033[1;32m[+]\033[0m {msg}")

def log_warn(msg: str) -> None:
    print(f"\033[1;33m[!]\033[0m \033[1;33m{msg}\033[0m")

def log_error(msg: str) -> None:
    print(f"\033[1;31m[-]\033[0m \033[1;31m{msg}\033[0m")


def _raw_send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _raw_recv(stream: CellStream) -> bytes:
    data = stream.recv_ciphertext()
    if data is None:
        raise ConnectionError("peer closed during handshake")
    return data


def run_receiver() -> None:
    print("\n\033[1;35m┌────────────────────────────────────────────────────────┐\033[0m")
    print("\033[1;35m│                 ROLE SELECTED: RECEIVER                │\033[0m")
    print("\033[1;35m└────────────────────────────────────────────────────────┘\033[0m\n")

    tor = TorManager("receiver")
    channel = SecureChannel.create()

    priv_b32, pub_b32 = generate_client_auth_keypair()
    torrc = tor.render_receiver_torrc(pub_b32)
    
    log_info("Launching Tor (Snowflake) and publishing onion service...")
    log_info("This may take up to 1-2 minutes for Tor to fully bootstrap. Please wait...")
    tor.launch(torrc)

    onion = tor.onion_address()
    if not onion:
        log_error("Failed to obtain onion address.")
        tor.shutdown()
        return

    bundle = OOBBundle(
        onion_address=onion,
        client_auth_privkey=priv_b32,
        identity_fingerprint=channel.identity_fingerprint(),
    )
    print_oob(bundle)

    log_info(f"Listening on 127.0.0.1:{tor.app_port} ...")
    srv = listen_loopback(tor.app_port)
    try:
        log_info("Waiting for sender to connect...")
        conn, _ = srv.accept()
        log_success("Incoming SOCKS SOCKS5 TCP connection established!")
        stream = CellStream(conn)
        
        # Handshake (pre-ratchet, raw frames).
        log_info("Performing cryptographic pre-key handshake...")
        req = _raw_recv(stream)
        if req != PREKEY_REQ:
            log_error("Unexpected handshake format received.")
            return
        _raw_send(conn, channel.public_prekey_bundle())
        initial = _raw_recv(stream)
        channel.start_responder(initial)
        log_success("X3DH + Double Ratchet secure channel established successfully!")
        ChatSession(stream, channel).run()
    except KeyboardInterrupt:
        log_warn("Receiver session interrupted.")
    finally:
        srv.close()
        log_info("Stopping onion service and shutting down Tor cleanly...")
        tor.shutdown()
        log_success("Shutdown complete.")


def run_sender() -> None:
    print("\n\033[1;34m┌────────────────────────────────────────────────────────┐\033[0m")
    print("\033[1;34m│                  ROLE SELECTED: SENDER                 │\033[0m")
    print("\033[1;34m└────────────────────────────────────────────────────────┘\033[0m\n")

    try:
        raw = input("\033[1;34mPaste OOB bundle (onion:auth_privkey:fingerprint):\033[0m ").strip()
        if not raw:
            log_error("No OOB bundle provided.")
            return
        bundle = OOBBundle.decode(raw)
    except Exception as e:
        log_error(f"Invalid OOB bundle format: {e}")
        return

    tor = TorManager("sender")
    channel = SecureChannel.create()
    tor.install_client_auth(bundle.onion_address, bundle.client_auth_privkey)
    
    log_info("Launching Tor (Snowflake)...")
    tor.launch(tor.render_sender_torrc())

    log_info(f"Connecting to onion service {bundle.onion_address} via SOCKS SOCKS5 proxy...")
    retries = 15
    delay_s = 10
    stream = None
    for attempt in range(1, retries + 1):
        try:
            stream = connect_via_socks(
                bundle.onion_address, config.ONION_VIRTUAL_PORT,
                tor.socks_port)
            log_success("Connected successfully to the onion service!")
            break
        except (ConnectionError, TimeoutError, socket.error) as e:
            if attempt == retries:
                log_error(f"Connection failed after {retries} attempts.")
                tor.shutdown()
                raise e
            log_warn(f"Onion service not yet reachable. (Tor takes 1-2 minutes to publish descriptor.)")
            print(f"    Retrying in {delay_s}s... [Attempt {attempt}/{retries}]")
            time.sleep(delay_s)

    try:
        log_info("Initiating secure end-to-end handshake...")
        _raw_send(stream._sock, PREKEY_REQ)  # noqa: SLF001 handshake
        peer_bundle = _raw_recv(stream)
        initial = channel.start_initiator(
            peer_bundle, bundle.identity_fingerprint)
        _raw_send(stream._sock, initial)  # noqa: SLF001 handshake
        log_success("X3DH + Double Ratchet secure channel established successfully!")
        ChatSession(stream, channel).run()
    except KeyboardInterrupt:
        log_warn("Sender session interrupted.")
    finally:
        log_info("Shutting down Tor cleanly...")
        tor.shutdown()
        log_success("Shutdown complete.")


def main() -> None:
    print_colored_banner()
    print("\n\033[1;36m┌────────────────────────────────────────────────────────┐\033[0m")
    print("\033[1;36m│          ZERO-TRUST E2E P2P CHAT OVER TOR              │\033[0m")
    print("\033[1;36m└────────────────────────────────────────────────────────┘\033[0m\n")
    print("  \033[1;35m[r]\033[0m \033[1mRECEIVER\033[0m  (Creates onion service, displays connection details)")
    print("  \033[1;34m[s]\033[0m \033[1mSENDER\033[0m    (Connects to receiver using connection details)")
    print("  \033[1;31m[q]\033[0m \033[1mQUIT\033[0m      (Exit the application)")
    print()
    
    try:
        role = input("\033[1;36mSelect role [r/s/q]:\033[0m ").strip().lower()
        if role.startswith("r"):
            run_receiver()
        elif role.startswith("s"):
            run_sender()
        elif role.startswith("q") or role in ("exit", "quit"):
            log_success("Goodbye!")
            sys.exit(0)
        else:
            log_error("Unknown option selected.")
            sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\n\033[1;33m[!] Session interrupted by user. Goodbye!\033[0m")
        sys.exit(0)


if __name__ == "__main__":
    main()
