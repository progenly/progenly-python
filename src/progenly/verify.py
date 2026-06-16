"""Offline verification of Progenly birth certificates (attestation-envelope v0.1.1).

Byte-compatible with the server's verifier and the colony-sdk reference: structural
checks -> ed25519 peel-and-verify of each sigchain entry over JCS(envelope with
sigchain[0..i-1]) -> validity window -> did:key issuer binding. No network, no trust
in the server: the only dependency is `cryptography` for the ed25519 check.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"
_REQUIRED = ("issuer", "subject", "witnessed_claim", "evidence", "validity", "sigchain")


@dataclass
class VerifyResult:
    """The verdict. ``ok`` = signatures + validity; ``issuer_bound`` = did:key binding."""

    ok: bool
    issuer_bound: bool
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def canonicalize(value: object) -> bytes:
    """RFC 8785 (JCS) for this float-free profile: recursively key-sorted, compact, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError(f"invalid base58 character: {ch!r}")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def public_key_from_did_key(did: str) -> bytes:
    """Extract the raw 32-byte ed25519 public key from a base58btc did:key."""
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise ValueError("not a base58btc did:key")
    decoded = _b58decode(did[len(prefix):])
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError("did:key multicodec is not ed25519")
    pub = decoded[2:]
    if len(pub) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return pub


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _parse_ts(s: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def verify_envelope(envelope: object, now: _dt.datetime | None = None) -> VerifyResult:
    """Verify a certificate envelope offline. Returns a :class:`VerifyResult`."""
    reasons: list[str] = []
    notes: list[str] = []

    if not isinstance(envelope, dict):
        return VerifyResult(False, False, ["envelope is not an object"], [])
    if envelope.get("envelope_version") != "0.1":
        reasons.append('unsupported envelope_version (expected "0.1")')
    for f in _REQUIRED:
        if f not in envelope:
            reasons.append(f"missing required field: {f}")
    ev = envelope.get("evidence")
    if not isinstance(ev, list) or not ev:
        reasons.append("evidence must be a non-empty list")
    chain = envelope.get("sigchain")
    if not isinstance(chain, list) or not chain:
        reasons.append("sigchain must be a non-empty list")
    if reasons:
        return VerifyResult(False, False, reasons, notes)

    assert isinstance(chain, list) and chain  # validated above; narrows type
    sig_ok = _verify_sigchain(envelope, chain, reasons, notes)
    val_ok = _verify_validity(envelope["validity"], now or _dt.datetime.now(_dt.timezone.utc), reasons, notes)
    issuer_bound = _issuer_binding(chain[0], envelope["issuer"], notes)
    return VerifyResult(sig_ok and val_ok, issuer_bound, reasons, notes)


def _verify_sigchain(envelope: dict, chain: list, reasons: list[str], notes: list[str]) -> bool:
    ok = True
    first = chain[0]
    if isinstance(first, dict) and first.get("role") not in (None, "issuer"):
        reasons.append("sigchain[0].role must be 'issuer' or unset")
        ok = False
    for i, entry in enumerate(chain):
        if not isinstance(entry, dict) or entry.get("alg") != "ed25519":
            reasons.append(f"sigchain[{i}]: unsupported or missing alg (v0.1 = ed25519 only)")
            ok = False
            continue
        stripped = dict(envelope)
        stripped["sigchain"] = chain[:i]
        message = canonicalize(stripped)
        try:
            pub = public_key_from_did_key(str(entry.get("key_id", "")))
        except Exception:
            reasons.append(f"sigchain[{i}]: key_id not a resolvable ed25519 did:key")
            ok = False
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(_b64url_decode(str(entry.get("sig", ""))), message)
        except (InvalidSignature, ValueError):
            reasons.append(f"sigchain[{i}]: signature does not verify")
            ok = False
            continue
        notes.append(f"sigchain[{i}] verified against {str(entry.get('key_id', ''))[:24]}…")
    return ok


def _verify_validity(validity: object, now: _dt.datetime, reasons: list[str], notes: list[str]) -> bool:
    if not isinstance(validity, dict):
        reasons.append("validity is not an object")
        return False
    model = validity.get("validity_model")
    if model == "perpetual":
        notes.append("validity: perpetual")
        return True
    if model == "revocation_checked":
        notes.append("validity: revocation_checked — not confirmed offline")
        return True
    if model == "time_bounded":
        try:
            nb, na = _parse_ts(validity.get("not_before", "")), _parse_ts(validity.get("not_after", ""))
        except (ValueError, TypeError):
            reasons.append("validity: unparseable not_before/not_after")
            return False
        if now < nb:
            reasons.append("validity: not yet valid")
            return False
        if now > na:
            reasons.append("validity: expired")
            return False
        notes.append("validity: time_bounded, within window")
        return True
    reasons.append("validity: unknown validity_model")
    return False


def _issuer_binding(sig0: object, issuer: object, notes: list[str]) -> bool:
    if not isinstance(issuer, dict):
        notes.append("issuer-binding: issuer is not an object")
        return False
    if issuer.get("id_scheme") == "did:key":
        if isinstance(sig0, dict) and sig0.get("key_id") == issuer.get("id"):
            notes.append("issuer-binding OK: did:key key_id == issuer.id")
            return True
        notes.append("issuer-binding UNVERIFIED: did:key issuer but key_id != issuer.id")
        return False
    notes.append("issuer-binding UNBINDABLE: non-did:key issuer scheme in v0.1")
    return False
