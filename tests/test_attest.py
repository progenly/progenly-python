"""Self-attestation helpers: did:key derivation + ed25519 signing, verified
against the same did:key decode the server/verifier uses."""
import base64

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from progenly import did_key_from_seed, generate_keypair, public_key_from_did_key, sign_attestation


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def test_generate_keypair_shape():
    seed, did = generate_keypair()
    assert isinstance(seed, bytes) and len(seed) == 32
    assert did.startswith("did:key:z")
    # the did:key decodes to a 32-byte ed25519 key (same path the verifier uses)
    assert len(public_key_from_did_key(did)) == 32


def test_did_key_is_deterministic():
    seed = b"\x01" * 32
    assert did_key_from_seed(seed) == did_key_from_seed(seed)


def test_did_key_padding_branch():
    # a leading zero byte exercises the base58 zero-padding ("1") path
    seed = b"\x00" + b"\x07" * 31
    did = did_key_from_seed(seed)
    assert len(public_key_from_did_key(did)) == 32


def test_signature_verifies_against_did_key():
    seed, did = generate_keypair()
    msg = "progenly-parent-attestation/v1\n" + did + "\nsha256:deadbeef"
    sig_b64 = sign_attestation(seed, msg)
    pub = Ed25519PublicKey.from_public_bytes(public_key_from_did_key(did))
    pub.verify(_b64url_decode(sig_b64), msg.encode("utf-8"))  # raises on failure
    with pytest.raises(InvalidSignature):
        pub.verify(_b64url_decode(sig_b64), b"tampered")


def test_seed_length_validated():
    with pytest.raises(ValueError):
        did_key_from_seed(b"short")
    with pytest.raises(ValueError):
        sign_attestation(b"short", "x")
