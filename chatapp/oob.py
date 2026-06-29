"""Out-of-band (OOB) parameter exchange.

The receiver displays three items that must be shared through a trusted
side channel (in person, encrypted call, dead drop):

  1. onion address           (56 base32 chars + .onion)
  2. client-auth private key  (x25519, base32 - this is what the SENDER
     installs into ClientOnionAuthDir; the receiver keeps only the public
     half in authorized_clients/)
  3. identity key fingerprint (sha-256 of the X3DH identity public key,
     64 hex chars)

We transmit the client-auth *private* key OOB because in this two-party
model the sender is the authorized client; the receiver never retains it.
"""
from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

try:
    import qrcode
except Exception:  # qrcode optional
    qrcode = None


@dataclass
class OOBBundle:
    onion_address: str        # e.g. abcd...xyz.onion
    client_auth_privkey: str  # base32 x25519 private key (no padding)
    identity_fingerprint: str # 64 hex chars

    def encode(self) -> str:
        """Single-line transport form, ':' separated."""
        return ":".join(
            [self.onion_address, self.client_auth_privkey, self.identity_fingerprint]
        )

    @classmethod
    def decode(cls, blob: str) -> "OOBBundle":
        blob = blob.strip()
        parts = blob.split(":")
        if len(parts) != 3:
            raise ValueError(
                "OOB bundle must have 3 colon-separated fields: "
                "onion:auth_privkey:fingerprint"
            )
        onion, auth, fp = parts
        if not onion.endswith(".onion") or len(onion) != 62:
            raise ValueError("Invalid v3 onion address.")
        if len(fp) != 64 or not all(c in "0123456789abcdef" for c in fp.lower()):
            raise ValueError("Fingerprint must be 64 hex chars.")
        return cls(onion_address=onion, client_auth_privkey=auth,
                   identity_fingerprint=fp.lower())


def fingerprint_identity_key(identity_pub_bytes: bytes) -> str:
    """sha-256 hex fingerprint of an identity public key."""
    return hashlib.sha256(identity_pub_bytes).hexdigest()


def render_qr(text: str) -> str:
    """Return an ASCII QR code for terminal display, or '' if unavailable."""
    if qrcode is None:
        return ""
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


def print_oob(bundle: OOBBundle) -> None:
    cyan = "\033[36m"
    yellow = "\033[33m"
    magenta = "\033[35m"
    green = "\033[32m"
    reset = "\033[0m"
    bold = "\033[1m"

    # Box for connection details
    print(f"\n{yellow}┌{'─' * 88}┐{reset}")
    print(f"{yellow}│{' ' * 16}{bold}SHARE SENSITIVE CONNECTION DATA VIA TRUSTED CHANNEL ONLY{reset}{' ' * 16}{yellow}│{reset}")
    print(f"{yellow}└{'─' * 88}┘{reset}")
    
    print(f"{cyan}┌{'─' * 88}┐{reset}")
    print(f"{cyan}│{bold}  1. Onion Address :{reset} {green}{bundle.onion_address:<67}{reset}{cyan}│{reset}")
    print(f"{cyan}│{bold}  2. SOCKS Auth Key:{reset} {green}{bundle.client_auth_privkey:<67}{reset}{cyan}│{reset}")
    print(f"{cyan}│{bold}  3. Fingerprint   :{reset} {magenta}{bundle.identity_fingerprint:<67}{reset}{cyan}│{reset}")
    print(f"{cyan}└{'─' * 88}┘{reset}")
    
    # Print the compact bundle cleanly for perfect copy-pasting without borders
    print(f"\n{bold}COMPACT BUNDLE (Single-line for easy copy/paste):{reset}")
    print(f"\033[44m\033[97m {bundle.encode()} \033[0m\n")

    qr = render_qr(bundle.encode())
    if qr:
        print(f"{yellow}┌{'─' * 88}┐{reset}")
        print(f"{yellow}│  SCAN QR CODE (Secure connection details):                                             │{reset}")
        print(f"{yellow}└{'─' * 88}┘{reset}")
        for qr_line in qr.splitlines():
            if qr_line.strip():
                print(f"  {qr_line}")
        print(f"{yellow}┌{'─' * 88}┐{reset}")


