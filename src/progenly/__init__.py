"""Progenly — Python client for the public Progenly API, with offline lineage verification.

    from progenly import Progenly
    p = Progenly()
    print(p.verify(birth_id="...").ok)   # verified locally — no trust in the server
    for birth in p.iter_births():
        print(birth["child_name"])
"""
from .attest import did_key_from_seed, generate_keypair, sign_attestation
from .client import MergeIntent, Progenly, ProgenlyError
from .verify import (
    CONTINUITY_GENESIS,
    VerifyResult,
    canonicalize,
    public_key_from_did_key,
    verify_continuity,
    verify_envelope,
)

__version__ = "0.4.1"
__all__ = [
    "Progenly",
    "MergeIntent",
    "ProgenlyError",
    "VerifyResult",
    "verify_envelope",
    "verify_continuity",
    "CONTINUITY_GENESIS",
    "canonicalize",
    "public_key_from_did_key",
    "generate_keypair",
    "did_key_from_seed",
    "sign_attestation",
    "__version__",
]
