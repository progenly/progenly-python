"""Offline verification of Progenly birth certificates (attestation-envelope v0.1.1).

Byte-compatible with the server's verifier and the colony-sdk reference: structural
checks -> ed25519 peel-and-verify of each sigchain entry over JCS(envelope with
sigchain[0..i-1]) -> validity window -> did:key issuer binding. No network, no trust
in the server: the only dependency is `cryptography` for the ed25519 check.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: The continuity chain's genesis prev_hash (links the first event to nothing).
CONTINUITY_GENESIS = "sha256:" + "0" * 64

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


def _continuity_entry_hash(event: dict) -> str:
    """Recompute an event's entry_hash: ``sha256:`` + sha256(JCS{occurred_at,
    prev_hash, ref_hash, seq, type}). Byte-compatible with the server."""
    canonical = canonicalize(
        {
            "occurred_at": event["occurred_at"],
            "prev_hash": event["prev_hash"],
            "ref_hash": event["ref_hash"],
            "seq": event["seq"],
            "type": event["type"],
        }
    )
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def verify_continuity(data: object) -> VerifyResult:
    """Verify a continuity-of-subject chain offline (from :meth:`Progenly.continuity`).

    Re-derives the hash-linked chain without trusting the server's verdict:
    contiguous ``seq``, each ``prev_hash`` links the prior ``entry_hash`` (first =
    genesis), each ``entry_hash`` recomputes, and the signed ``head`` matches the
    last entry and verifies (ed25519) against its ``issuer`` did:key.

    ``ok`` = chain integrity + head signature; ``issuer_bound`` = the head signature
    verified against a resolvable did:key issuer.
    """
    reasons: list[str] = []
    notes: list[str] = []

    if not isinstance(data, dict):
        return VerifyResult(False, False, ["continuity is not an object"], [])
    events = data.get("events")
    if not isinstance(events, list):
        return VerifyResult(False, False, ["events must be a list"], [])

    expected_prev = CONTINUITY_GENESIS
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            reasons.append(f"events[{i}] is not an object")
            break
        if e.get("seq") != i:
            reasons.append(f"events[{i}]: non-contiguous seq (gap)")
            break
        if e.get("prev_hash") != expected_prev:
            reasons.append(f"events[{i}]: prev_hash does not link")
            break
        try:
            recomputed = _continuity_entry_hash(e)
        except KeyError as k:
            reasons.append(f"events[{i}]: missing field {k}")
            break
        if recomputed != e.get("entry_hash"):
            reasons.append(f"events[{i}]: entry_hash mismatch")
            break
        expected_prev = e["entry_hash"]

    issuer_bound = False
    if not reasons:
        head = data.get("head")
        last = events[-1]["entry_hash"] if events else CONTINUITY_GENESIS
        if not isinstance(head, dict):
            reasons.append("head is missing or not an object")
        elif head.get("entry_hash") != last:
            reasons.append("head.entry_hash does not match the last event")
        elif head.get("alg") != "ed25519":
            reasons.append("head.alg unsupported (v1 = ed25519 only)")
        else:
            try:
                pub = public_key_from_did_key(str(head.get("issuer", "")))
                Ed25519PublicKey.from_public_bytes(pub).verify(
                    _b64url_decode(str(head.get("signature", ""))),
                    str(head.get("entry_hash", "")).encode("utf-8"),
                )
                issuer_bound = True
                notes.append(f"head signature verified against {str(head.get('issuer', ''))[:24]}…")
            except (InvalidSignature, ValueError):
                reasons.append("head.signature does not verify")

    if not reasons and not events:
        notes.append("empty chain (no events yet); signed head over genesis")
    return VerifyResult(not reasons, issuer_bound, reasons, notes)
