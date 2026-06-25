"""End-to-end encryption: X3DH key agreement + Double Ratchet messaging.

Bound to the maintained pure-Python `X3DH` and `DoubleRatchet` libraries
(by Tim Henkes / the python-omemo project). Those libraries are
asyncio-based and expose abstract base classes that an application must
subclass to pin concrete cryptographic choices. We pin:

  * Curve25519 / XEdDSA identity & prekeys
  * HKDF-SHA-256 for the X3DH and root-chain KDFs
  * AES-256-GCM AEAD for Double Ratchet message encryption

All key material stays in memory; `wipe()` is a best-effort zeroization.

The rest of the app is synchronous, so async library calls are driven
through a private event loop via `_run()`.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

from nacl import utils as nacl_utils

from doubleratchet import DoubleRatchet as DR
from doubleratchet import EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve25519 as dhr25519,
    kdf_hkdf,
    kdf_separate_hmacs,
)
import x3dh

# --- shared cryptographic parameters -------------------------------------
INFO_X3DH = b"zt-chat-x3dh-v1"
INFO_ROOT = b"zt-chat-dr-root-v1"
INFO_AEAD = b"zt-chat-dr-aead-v1"
DR_AD = b"zt-chat-associated-data-v1"


# --- Double Ratchet concrete configuration -------------------------------
class _RootKDF(kdf_hkdf.KDF):
    @staticmethod
    def _get_hash_function() -> Any:
        return kdf_hkdf.HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return INFO_ROOT


class _MsgKDF(kdf_separate_hmacs.KDF):
    @staticmethod
    def _get_hash_function() -> Any:
        return kdf_separate_hmacs.HashFunction.SHA_256


class _AEAD(aead_aes_hmac.AEAD):
    @staticmethod
    def _get_hash_function() -> Any:
        return aead_aes_hmac.HashFunction.SHA_256

    @staticmethod
    def _get_info() -> bytes:
        return INFO_AEAD


class _DHRatchet(dhr25519.DiffieHellmanRatchet):
    pass


_DR_KWARGS = dict(
    diffie_hellman_ratchet_class=_DHRatchet,
    root_chain_kdf=_RootKDF,
    message_chain_kdf=_MsgKDF,
    message_chain_constant=b"\x01\x02",
    dos_protection_threshold=100,
    aead=_AEAD,
)


# --- X3DH concrete configuration -----------------------------------------
class _X3DHState(x3dh.BaseState):
    @staticmethod
    def _encode_public_key(key_format: Any, pub: bytes) -> bytes:
        # Domain-separated wire encoding of a public key.
        return b"\x01" + pub


@dataclass
class IdentityFingerprintMismatch(Exception):
    expected: str
    actual: str

    def __str__(self) -> str:  # pragma: no cover
        return (
            "Identity fingerprint mismatch! Possible MITM.\n"
            f"  expected (OOB): {self.expected}\n"
            f"  received      : {self.actual}"
        )


def fingerprint(identity_pub_bytes: bytes) -> str:
    return hashlib.sha256(identity_pub_bytes).hexdigest()


def verify_fingerprint(expected_hex: str, identity_pub_bytes: bytes) -> None:
    actual = fingerprint(identity_pub_bytes)
    if not nacl_utils.bytes_eq(
        bytes.fromhex(expected_hex), bytes.fromhex(actual)
    ):
        raise IdentityFingerprintMismatch(expected=expected_hex, actual=actual)


def _run(coro: Any) -> Any:
    """Drive an async library call from synchronous code."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():  # pragma: no cover - defensive
            raise RuntimeError("unexpected running loop")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class SecureChannel:
    """X3DH + Double Ratchet wrapper for one peer."""

    def __init__(self) -> None:
        self._state: Optional[_X3DHState] = None
        self._ratchet: Optional[DR] = None
        self._identity_pub: Optional[bytes] = None

    # --- identity / lifecycle -----------------------------------------
    @classmethod
    def create(cls) -> "SecureChannel":
        ch = cls()
        # identity_key_format=Curve25519, sign prekeys, 100 one-time prekeys.
        ch._state = _X3DHState.create(
            identity_key_format=x3dh.IdentityKeyFormat.CURVE_25519,
            hash_function=x3dh.HashFunction.SHA_256,
            info=INFO_X3DH,
        )
        ch._identity_pub = ch._state.bundle.identity_key
        return ch

    @property
    def identity_public(self) -> bytes:
        assert self._identity_pub is not None
        return self._identity_pub

    def identity_fingerprint(self) -> str:
        return fingerprint(self.identity_public)

    # --- responder (receiver) -----------------------------------------
    def public_prekey_bundle(self) -> bytes:
        assert self._state is not None
        b = self._state.bundle
        payload = {
            "identity_key": b.identity_key.hex(),
            "signed_pre_key": b.signed_pre_key.hex(),
            "signed_pre_key_sig": b.signed_pre_key_sig.hex(),
            "pre_keys": [pk.hex() for pk in b.pre_keys],
        }
        return json.dumps(payload, separators=(",", ":")).encode()

    def start_responder(self, initial_msg: bytes) -> None:
        assert self._state is not None
        env = json.loads(initial_msg.decode())
        header = x3dh.Header(
            identity_key=bytes.fromhex(env["ik"]),
            ephemeral_key=bytes.fromhex(env["ek"]),
            signed_pre_key=bytes.fromhex(env["spk"]),
            pre_key=bytes.fromhex(env["pk"]) if env.get("pk") else None,
        )
        shared_secret, associated_data, _ = _run(
            self._state.get_shared_secret_passive(header)
        )
        self._ratchet = _run(DR.create_from_shared_secret(
            shared_secret=shared_secret,
            recipient_ratchet_pub=bytes.fromhex(env["dh"]),
            associated_data=associated_data or DR_AD,
            **_DR_KWARGS,
        ))
        # Decrypt the piggy-backed first ciphertext to advance the ratchet.
        if env.get("ct"):
            self._decrypt_wire(bytes.fromhex(env["ct"]))

    # --- initiator (sender) -------------------------------------------
    def start_initiator(self, peer_bundle: bytes, expected_fp: str) -> bytes:
        assert self._state is not None
        d = json.loads(peer_bundle.decode())
        peer_ik = bytes.fromhex(d["identity_key"])
        verify_fingerprint(expected_fp, peer_ik)
        remote_bundle = x3dh.Bundle(
            identity_key=peer_ik,
            signed_pre_key=bytes.fromhex(d["signed_pre_key"]),
            signed_pre_key_sig=bytes.fromhex(d["signed_pre_key_sig"]),
            pre_keys=[bytes.fromhex(pk) for pk in d["pre_keys"]],
        )
        shared_secret, associated_data, header = _run(
            self._state.get_shared_secret_active(remote_bundle)
        )
        ratchet, enc = _run(DR.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=remote_bundle.signed_pre_key,
            message=b"\x00",  # ratchet warm-up, ignored by app layer
            associated_data=associated_data or DR_AD,
            **_DR_KWARGS,
        ))
        self._ratchet = ratchet
        envelope = {
            "ik": header.identity_key.hex(),
            "ek": header.ephemeral_key.hex(),
            "spk": header.signed_pre_key.hex(),
            "pk": header.pre_key.hex() if header.pre_key else "",
            "dh": enc.header.ratchet_pub.hex(),
            "ct": self._encode_wire(enc).hex(),
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    # --- message encoding ---------------------------------------------
    @staticmethod
    def _encode_wire(enc: EncryptedMessage) -> bytes:
        h = enc.header
        obj = {
            "dh": h.ratchet_pub.hex(),
            "pn": h.previous_sending_chain_length,
            "n": h.sending_chain_length,
            "ct": enc.ciphertext.hex(),
        }
        return json.dumps(obj, separators=(",", ":")).encode()

    @staticmethod
    def _decode_wire(blob: bytes) -> EncryptedMessage:
        obj = json.loads(blob.decode())
        header = Header(
            ratchet_pub=bytes.fromhex(obj["dh"]),
            previous_sending_chain_length=obj["pn"],
            sending_chain_length=obj["n"],
        )
        return EncryptedMessage(header=header,
                                ciphertext=bytes.fromhex(obj["ct"]))

    def _decrypt_wire(self, blob: bytes) -> bytes:
        assert self._ratchet is not None
        enc = self._decode_wire(blob)
        pt, _ = _run(self._ratchet.decrypt_message(enc, DR_AD))
        return pt

    # --- messaging -----------------------------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        if self._ratchet is None:
            raise RuntimeError("channel not established")
        enc = _run(self._ratchet.encrypt_message(plaintext, DR_AD))
        return self._encode_wire(enc)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._ratchet is None:
            raise RuntimeError("channel not established")
        return self._decrypt_wire(ciphertext)

    # --- teardown ------------------------------------------------------
    def wipe(self) -> None:
        self._state = None
        self._ratchet = None
        self._identity_pub = None
