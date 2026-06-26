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


def _raw_send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _raw_recv(stream: CellStream) -> bytes:
    data = stream.recv_ciphertext()
    if data is None:
        raise ConnectionError("peer closed during handshake")
    return data


def run_receiver() -> None:
    print("[*] Role: RECEIVER")
    tor = TorManager("receiver")
    channel = SecureChannel.create()

    priv_b32, pub_b32 = generate_client_auth_keypair()
    torrc = tor.render_receiver_torrc(pub_b32)
    print("[*] Launching Tor (Snowflake) and publishing onion service...")
    tor.launch(torrc)

    onion = tor.onion_address()
    if not onion:
        print("[!] Failed to obtain onion address.", file=sys.stderr)
        tor.shutdown()
        return

    bundle = OOBBundle(
        onion_address=onion,
        client_auth_privkey=priv_b32,
        identity_fingerprint=channel.identity_fingerprint(),
    )
    print_oob(bundle)

    print(f"[*] Listening on 127.0.0.1:{tor.app_port} ...")
    srv = listen_loopback(tor.app_port)
    try:
        conn, _ = srv.accept()
        stream = CellStream(conn)
        # Handshake (pre-ratchet, raw frames).
        req = _raw_recv(stream)
        if req != PREKEY_REQ:
            print("[!] Unexpected handshake.", file=sys.stderr)
            return
        _raw_send(conn, channel.public_prekey_bundle())
        initial = _raw_recv(stream)
        channel.start_responder(initial)
        print("[*] Secure channel established. Type /quit to exit.")
        ChatSession(stream, channel).run()
    finally:
        srv.close()
        tor.shutdown()


def run_sender() -> None:
    print("[*] Role: SENDER")
    raw = input("Paste OOB bundle (onion:auth_privkey:fingerprint): ")
    bundle = OOBBundle.decode(raw)

    tor = TorManager("sender")
    channel = SecureChannel.create()
    tor.install_client_auth(bundle.onion_address, bundle.client_auth_privkey)
    print("[*] Launching Tor (Snowflake)...")
    tor.launch(tor.render_sender_torrc())

    print("[*] Connecting to onion service...")
    retries = 15
    delay_s = 10
    stream = None
    for attempt in range(1, retries + 1):
        try:
            stream = connect_via_socks(
                bundle.onion_address, config.ONION_VIRTUAL_PORT,
                tor.socks_port)
            print("[*] Connected successfully!")
            break
        except (ConnectionError, TimeoutError) as e:
            if attempt == retries:
                print(f"[-] Connection failed after {retries} attempts.")
                raise e
            print(f"[*] Onion service not yet reachable. (This is normal and takes up to 1-2 minutes for Tor to publish the descriptor.)")
            print(f"    Retrying in {delay_s}s... [Attempt {attempt}/{retries}]")
            time.sleep(delay_s)

    try:
        _raw_send(stream._sock, PREKEY_REQ)  # noqa: SLF001 handshake
        peer_bundle = _raw_recv(stream)
        initial = channel.start_initiator(
            peer_bundle, bundle.identity_fingerprint)
        _raw_send(stream._sock, initial)  # noqa: SLF001 handshake
        print("[*] Secure channel established. Type /quit to exit.")
        ChatSession(stream, channel).run()
    finally:
        tor.shutdown()


def main() -> None:
    print("Zero-Trust P2P Chat over Tor")
    print("  [r] receiver (creates onion service, shows OOB data)")
    print("  [s] sender   (connects using OOB data)")
    role = input("Choose role [r/s]: ").strip().lower()
    if role.startswith("r"):
        run_receiver()
    elif role.startswith("s"):
        run_sender()
    else:
        print("Unknown role.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrupted]")

