"""Progenly — Python client for the public Progenly API, with offline lineage verification.

    from progenly import Progenly
    p = Progenly()
    print(p.verify(birth_id="...").ok)   # verified locally — no trust in the server
    for birth in p.iter_births():
        print(birth["child_name"])
"""
from .client import Progenly, ProgenlyError
from .verify import VerifyResult, canonicalize, public_key_from_did_key, verify_envelope

__version__ = "0.1.0"
__all__ = [
    "Progenly",
    "ProgenlyError",
    "VerifyResult",
    "verify_envelope",
    "canonicalize",
    "public_key_from_did_key",
    "__version__",
]
