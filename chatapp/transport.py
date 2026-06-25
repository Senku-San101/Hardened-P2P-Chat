"""Stream transport: length-prefixed encrypted cells.

Sender connects to the onion service through Tor's SOCKS5 port.
Receiver listens on a loopback port that the onion service forwards to.

Each frame on the wire is: [4-byte big-endian length][ciphertext].
The ciphertext is the Double Ratchet output over a fixed-size plaintext
cell, so frame lengths are uniform in steady state.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional

from . import config


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class CellStream:
    """Frames ciphertext cells over a connected socket."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    def send_ciphertext(self, ciphertext: bytes) -> None:
        frame = struct.pack(">I", len(ciphertext)) + ciphertext
        self._sock.sendall(frame)

    def recv_ciphertext(self) -> Optional[bytes]:
        header = _recv_exact(self._sock, config.LENGTH_PREFIX_BYTES)
        if header is None:
            return None
        (length,) = struct.unpack(">I", header)
        if length == 0 or length > (1 << 20):
            raise ValueError("implausible frame length")
        return _recv_exact(self._sock, length)

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


def connect_via_socks(onion_host: str, virtual_port: int,
                      socks_port: int) -> CellStream:
    """Open a SOCKS5 connection through Tor to onion_host:virtual_port.

    Uses SOCKS5 with a hostname target so Tor resolves the .onion itself.
    """
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=60)
    # SOCKS5 greeting: no auth.
    sock.sendall(b"\x05\x01\x00")
    resp = _recv_exact(sock, 2)
    if resp != b"\x05\x00":
        sock.close()
        raise ConnectionError("SOCKS5 handshake failed")
    host = onion_host.encode("ascii")
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(
        ">H", virtual_port)
    sock.sendall(req)
    reply = _recv_exact(sock, 4)
    if reply is None or reply[1] != 0x00:
        sock.close()
        raise ConnectionError(
            "SOCKS5 connect refused (auth/onion unreachable). "
            "Check client-auth key and that the onion is published.")
    # Drain bound address per address type.
    atyp = reply[3]
    if atyp == 0x01:
        _recv_exact(sock, 4 + 2)
    elif atyp == 0x03:
        ln = _recv_exact(sock, 1)
        _recv_exact(sock, ln[0] + 2)
    elif atyp == 0x04:
        _recv_exact(sock, 16 + 2)
    return CellStream(sock)


def listen_loopback(app_port: int) -> socket.socket:
    """Listen on 127.0.0.1:app_port for the onion-forwarded connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", app_port))
    srv.listen(1)
    return srv
