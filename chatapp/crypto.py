"""End-to-end encryption: X3DH key agreement + Double Ratchet messaging.

Bound to the pure-Python `X3DH` and `DoubleRatchet` libraries
(by Tim Henkes / the python-omemo project), pinned to **1.3.0**.
These are asyncio-based and expose abstract base classes that an
application must subclass to pin concrete cryptographic choices. We pin:

  * Curve25519 / XEdDSA identity & prekeys
  * HKDF-SHA-256 for the X3DH and Double Ratchet root chain
  * HMAC-SHA-256 message chain
  * AES-256-CBC + HMAC-SHA-256 AEAD for message encryption

All key material stays in memory; `wipe()` drops references.

The rest of the app is synchronous, so async library calls are driven
through a private event loop via `_run()`.

API reference (X3DH/DoubleRatchet 1.3.0):
  * BaseState.create(identity_key_format, hash_function, info,
                     identity_key_pair=None)  -> no prekey count here
  * BaseState.generate_pre_keys(num_pre_keys)
  * get_shared_secret_active(bundle)  -> (ss, ad, x3dh.Header)
  * get_shared_secret_passive(header) -> (ss, ad, SignedPreKeyPair)
  * DR.encrypt_initial_message(... , shared_secret, recipient_ratchet_pub,
                               message, associated_data) -> (dr, EncryptedMessage)
  * DR.decrypt_initial_message(... , shared_secret, own_ratchet_priv,
                               message, associated_data) -> (dr, plaintext)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
from dataclasses import dataclass
from typing import Any, Optional

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
NUM_PRE_KEYS = 100
MAX_SKIPPED = 100


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


def _encode_dr_header(header: Header) -> bytes:
    return b"|".join([
        header.ratchet_pub,
        str(header.previous_sending_chain_length).encode(),
        str(header.sending_chain_length).encode(),
    ])


class _DoubleRatchet(DR):
    """Concrete Double Ratchet binding our associated-data construction.

    The header is authenticated by mixing it into the AEAD associated data,
    so an attacker cannot tamper with ratchet_pub or chain counters.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return associated_data + b"||" + _encode_dr_header(header)


# Config kwargs shared by encrypt_initial_message / decrypt_initial_message.
_DR_CONFIG = dict(
    diffie_hellman_ratchet_class=_DHRatchet,
    root_chain_kdf=_RootKDF,
    message_chain_kdf=_MsgKDF,
    message_chain_constant=b"\x01\x02",
    dos_protection_threshold=10,
    max_num_skipped_message_keys=MAX_SKIPPED,
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
    if not hmac.compare_digest(
        bytes.fromhex(expected_hex), bytes.fromhex(actual)
    ):
        raise IdentityFingerprintMismatch(expected=expected_hex, actual=actual)


def _run(result: Any) -> Any:
    """Drive an async library call from synchronous code.

    Tolerates non-awaitables: in X3DH/DoubleRatchet 1.3.0 most methods are
    coroutines, but a few (e.g. generate_pre_keys) are synchronous. If the
    argument is not awaitable we return it unchanged.
    """
    if not inspect.isawaitable(result):
        return result
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():  # pragma: no cover - defensive
            raise RuntimeError("unexpected running loop")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(result)


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
        state = _X3DHState.create(
            identity_key_format=x3dh.IdentityKeyFormat.CURVE_25519,
            hash_function=x3dh.HashFunction.SHA_256,
            info=INFO_X3DH,
        )
        # generate_pre_keys is synchronous in 1.3.0.
        state.generate_pre_keys(NUM_PRE_KEYS)
        ch._state = state
        ch._identity_pub = state.bundle.identity_key
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
            "pre_keys": sorted(pk.hex() for pk in b.pre_keys),
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
        shared_secret, associated_data, spk_pair = _run(
            self._state.get_shared_secret_passive(header)
        )
        enc = self._decode_wire(bytes.fromhex(env["ct"]))
        # The responder's own ratchet private key is its signed-prekey priv,
        # because the initiator targeted recipient_ratchet_pub = signed_pre_key.
        self._ratchet, _plain = _run(_DoubleRatchet.decrypt_initial_message(
            shared_secret=shared_secret,
            own_ratchet_priv=spk_pair.priv,
            message=enc,
            associated_data=associated_data or DR_AD,
            **_DR_CONFIG,
        ))

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
            pre_keys=frozenset(bytes.fromhex(pk) for pk in d["pre_keys"]),
        )
        shared_secret, associated_data, header = _run(
            self._state.get_shared_secret_active(remote_bundle)
        )
        self._ratchet, enc = _run(_DoubleRatchet.encrypt_initial_message(
            shared_secret=shared_secret,
            recipient_ratchet_pub=remote_bundle.signed_pre_key,
            message=b"\x00",  # ratchet warm-up, ignored by app layer
            associated_data=associated_data or DR_AD,
            **_DR_CONFIG,
        ))
        envelope = {
            "ik": header.identity_key.hex(),
            "ek": header.ephemeral_key.hex(),
            "spk": header.signed_pre_key.hex(),
            "pk": header.pre_key.hex() if header.pre_key else "",
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

    # --- messaging -----------------------------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        if self._ratchet is None:
            raise RuntimeError("channel not established")
        enc = _run(self._ratchet.encrypt_message(plaintext, DR_AD))
        return self._encode_wire(enc)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._ratchet is None:
            raise RuntimeError("channel not established")
        enc = self._decode_wire(ciphertext)
        return _run(self._ratchet.decrypt_message(enc, DR_AD))

    # --- teardown ------------------------------------------------------
    def wipe(self) -> None:
        self._state = None
        self._ratchet = None
        self._identity_pub = None
