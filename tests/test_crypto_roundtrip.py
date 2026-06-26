"""Offline self-test: full X3DH -> Double Ratchet -> padding round-trip.

Runs WITHOUT Tor or any network. Validates the crypto wiring against the
installed X3DH / DoubleRatchet versions.

Run:
    ./.venv/bin/python -m tests.test_crypto_roundtrip
"""
from __future__ import annotations

import sys

from chatapp.crypto import SecureChannel, IdentityFingerprintMismatch
from chatapp.padding import pad_plaintext, unpad_plaintext
from chatapp import config


def _ok(msg: str) -> None:
    print(f"  \033[1;32mPASS\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[1;31mFAIL\033[0m {msg}")


def main() -> int:
    failures = 0

    # Roles: receiver = responder, sender = initiator.
    receiver = SecureChannel.create()
    sender = SecureChannel.create()

    # OOB: sender learns receiver's identity fingerprint.
    recv_fp = receiver.identity_fingerprint()

    # Handshake.
    bundle = receiver.public_prekey_bundle()
    initial = sender.start_initiator(bundle, recv_fp)
    receiver.start_responder(initial)
    _ok("X3DH handshake completed and ratchets seeded")

    # Fingerprint tamper test.
    try:
        SecureChannel.create().start_initiator(bundle, "00" * 32)
        _fail("fingerprint mismatch was NOT detected")
        failures += 1
    except IdentityFingerprintMismatch:
        _ok("fingerprint mismatch correctly rejected")

    # Bidirectional message exchange through fixed-size cells.
    samples = [b"hello", b"", b"x" * 500, "unicode \u2713 \U0001f512".encode()]
    for i, msg in enumerate(samples):
        # sender -> receiver
        cell = pad_plaintext(msg, config.CELL_TYPE_DATA)
        ct = sender.encrypt(cell)
        pt = receiver.decrypt(ct)
        ctype, payload = unpad_plaintext(pt)
        if ctype == config.CELL_TYPE_DATA and payload == msg:
            _ok(f"sender->receiver msg #{i} round-tripped ({len(msg)} bytes)")
        else:
            _fail(f"sender->receiver msg #{i} mismatch")
            failures += 1

        # receiver -> sender (exercises the DH ratchet step)
        cell = pad_plaintext(msg[::-1], config.CELL_TYPE_DATA)
        ct = receiver.encrypt(cell)
        pt = sender.decrypt(ct)
        ctype, payload = unpad_plaintext(pt)
        if ctype == config.CELL_TYPE_DATA and payload == msg[::-1]:
            _ok(f"receiver->sender msg #{i} round-tripped")
        else:
            _fail(f"receiver->sender msg #{i} mismatch")
            failures += 1

    # Ciphertext length uniformity (padding effectiveness).
    lengths = set()
    for n in range(5):
        ct = sender.encrypt(pad_plaintext(b"a" * n, config.CELL_TYPE_DATA))
        receiver.decrypt(ct)
        lengths.add(len(ct))
    if len(lengths) == 1:
        _ok(f"ciphertext length constant ({lengths.pop()} bytes)")
    else:
        _fail(f"ciphertext length varies: {sorted(lengths)}")
        failures += 1

    print()
    if failures:
        print(f"\033[1;31m{failures} check(s) failed.\033[0m")
        return 1
    print("\033[1;32mAll crypto self-tests passed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
