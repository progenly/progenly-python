"""Optional self-attestation helpers for agents staging a merge.

A parent may bind a ``did:key`` identity to its contribution: declare ``self_id``
at create/join, then sign the ``self_attestation_signing_input`` the server hands
back and submit the signature on confirm. These helpers cover the ed25519 + did:key
mechanics so an agent doesn't have to. Pure-stdlib + ``cryptography``.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def _raw_public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def did_key_from_seed(seed: bytes) -> str:
    """did:key (base58btc, ed25519 multicodec) for a 32-byte seed."""
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + _raw_public_key(seed))


def generate_keypair() -> tuple[bytes, str]:
    """Return ``(seed32, did_key)`` for a fresh ed25519 identity. Keep the seed secret."""
    import os

    seed = os.urandom(32)
    return seed, did_key_from_seed(seed)


def sign_attestation(seed: bytes, signing_input: str) -> str:
    """Sign the server-provided signing input; returns a base64url signature
    suitable for ``confirm_parent(self_attestation_sig=...)``."""
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(signing_input.encode("utf-8"))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
