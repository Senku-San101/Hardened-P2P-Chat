"""Tor process management via stem.

Responsibilities:
  * render a torrc from the templates in config/
  * launch tor (Snowflake PT) and wait for bootstrap
  * (receiver) create a v3 onion service with client authorization,
    return the onion address and the client's x25519 PRIVATE key that the
    sender must install
  * (sender) install a received client-auth private key into
    ClientOnionAuthDir before launch
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional

from nacl.public import PrivateKey

from . import config


def _b32_nopad(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _read_bridge_lines() -> str:
    path = config.config_template_dir() / "bridges.snowflake.default"
    lines = []
    if path.exists():
        for ln in path.read_text().splitlines():
            s = ln.strip()
            if s and not s.startswith("#"):
                lines.append(s)
    return "\n".join(lines)


def generate_client_auth_keypair() -> tuple[str, str]:
    """Return (priv_b32, pub_b32) x25519 keys for v3 onion client auth."""
    sk = PrivateKey.generate()
    return _b32_nopad(bytes(sk)), _b32_nopad(bytes(sk.public_key))


def _render(template_name: str, subs: dict[str, str]) -> str:
    tpl = (config.config_template_dir() / template_name).read_text()
    for k, v in subs.items():
        tpl = tpl.replace("{{" + k + "}}", v)
    return tpl


def find_free_port(preferred_port: int) -> int:
    """Check if the preferred port is free; if not, find any available loopback port."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", preferred_port))
            return preferred_port
    except OSError:
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TorManager:
    def __init__(self, role: str) -> None:
        self.role = role
        self._process = None
        self._controller = None
        self.control_port = config.DEFAULT_CONTROL_PORT
        self.socks_port = config.DEFAULT_SENDER_SOCKS
        self.app_port = config.DEFAULT_APP_PORT

    @property
    def data_dir(self) -> Path:
        d = config.runtime_base() / f"runtime_{self.role}"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        return d

    @property
    def onion_auth_dir(self) -> Path:
        d = config.runtime_base() / f"onion_auth_{self.role}"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        return d

    @property
    def hidden_service_dir(self) -> Path:
        d = config.runtime_base() / f"hidden_service_{self.role}"
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        return d

    # --- receiver ------------------------------------------------------
    def render_receiver_torrc(self, client_pub_b32: str) -> str:
        self.control_port = find_free_port(config.DEFAULT_CONTROL_PORT)
        self.socks_port = config.DEFAULT_RECEIVER_SOCKS
        self.app_port = find_free_port(config.DEFAULT_APP_PORT)

        hs_dir = self.hidden_service_dir
        # Install the authorized client public key.
        auth_clients = hs_dir / "authorized_clients"
        auth_clients.mkdir(mode=0o700, parents=True, exist_ok=True)
        (auth_clients / "sender.auth").write_text(
            f"descriptor:x25519:{client_pub_b32}\n"
        )
        os.chmod(auth_clients / "sender.auth", 0o600)
        return _render("torrc_receiver.template", {
            "SOCKS_PORT": str(self.socks_port),
            "DATA_DIR": str(self.data_dir),
            "CONTROL_PORT": str(self.control_port),
            "BRIDGE_LINES": _read_bridge_lines(),
            "HS_DIR": str(hs_dir),
            "APP_PORT": str(self.app_port),
        })

    # --- sender --------------------------------------------------------
    def install_client_auth(self, onion_address: str, priv_b32: str) -> None:
        """Write <onion-host>.auth_private for the sender's Tor."""
        host = onion_address[:-len(".onion")] if onion_address.endswith(
            ".onion") else onion_address
        auth_dir = self.onion_auth_dir
        f = auth_dir / f"{host}.auth_private"
        f.write_text(f"{host}:descriptor:x25519:{priv_b32}\n")
        os.chmod(f, 0o600)

    def render_sender_torrc(self) -> str:
        self.control_port = find_free_port(config.DEFAULT_CONTROL_PORT)
        self.socks_port = find_free_port(config.DEFAULT_SENDER_SOCKS)
        return _render("torrc_sender.template", {
            "SOCKS_PORT": str(self.socks_port),
            "DATA_DIR": str(self.data_dir),
            "CONTROL_PORT": str(self.control_port),
            "BRIDGE_LINES": _read_bridge_lines(),
            "ONION_AUTH_DIR": str(self.onion_auth_dir),
        })

    # --- lifecycle -----------------------------------------------------
    def launch(self, torrc_text: str) -> None:
        import stem.process
        from stem.control import Controller

        torrc_path = self.data_dir / "torrc"
        torrc_path.write_text(torrc_text)
        os.chmod(torrc_path, 0o600)

        def _bootstrap(line: str) -> None:
            if "Bootstrapped" in line:
                # Color '[tor]' grey, status text cyan
                print(f"\033[90m[tor]\033[0m \033[36m{line}\033[0m")


        self._process = stem.process.launch_tor(
            torrc_path=str(torrc_path),
            init_msg_handler=_bootstrap,
            timeout=config.TOR_BOOTSTRAP_TIMEOUT_S,
            take_ownership=True,
        )
        self._controller = Controller.from_port(
            port=self.control_port)
        self._controller.authenticate()

    def onion_address(self) -> Optional[str]:
        hostname = self.hidden_service_dir / "hostname"
        if hostname.exists():
            return hostname.read_text().strip()
        return None

    def shutdown(self) -> None:
        try:
            if self._controller:
                self._controller.close()
        finally:
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=10)
