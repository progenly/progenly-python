"""Cover the verifier's rejection/edge branches directly."""
import datetime as dt

import pytest

from progenly import public_key_from_did_key
from progenly.verify import (
    _b58decode,
    _issuer_binding,
    _verify_sigchain,
    _verify_validity,
    public_key_from_did_key as _pk,
)

NOW = dt.datetime(2026, 6, 16, 12, 0, tzinfo=dt.timezone.utc)


# ---- did:key edge cases -----------------------------------------------------


def test_did_key_wrong_multicodec():
    # base58btc of bytes that decode without the 0xed01 prefix
    bad = "z" + _b58encode(b"\x00\x01" + b"\x11" * 32)
    with pytest.raises(ValueError, match="multicodec"):
        public_key_from_did_key("did:key:" + bad)


def test_did_key_wrong_length():
    bad = "z" + _b58encode(b"\xed\x01" + b"\x11" * 10)
    with pytest.raises(ValueError, match="32 bytes"):
        _pk("did:key:" + bad)


def test_b58decode_leading_ones():
    assert _b58decode("11") == b"\x00\x00"


# ---- sigchain branches ------------------------------------------------------


def _env(sigchain):
    return {"issuer": {}, "validity": {}, "sigchain": sigchain}


def test_sigchain_bad_first_role():
    reasons = []
    ok = _verify_sigchain(_env([{"role": "witness", "alg": "ed25519"}]), [{"role": "witness", "alg": "ed25519"}], reasons, [])
    assert ok is False
    assert any("role" in r for r in reasons)


def test_sigchain_bad_alg():
    reasons = []
    chain = [{"alg": "rsa"}]
    ok = _verify_sigchain(_env(chain), chain, reasons, [])
    assert ok is False
    assert any("alg" in r for r in reasons)


def test_sigchain_unresolvable_key_id():
    reasons = []
    chain = [{"alg": "ed25519", "key_id": "not-a-did", "sig": "AAAA"}]
    ok = _verify_sigchain(_env(chain), chain, reasons, [])
    assert ok is False
    assert any("did:key" in r for r in reasons)


# ---- validity branches ------------------------------------------------------


def test_validity_not_object():
    reasons = []
    assert _verify_validity("nope", NOW, reasons, []) is False


def test_validity_perpetual():
    notes = []
    assert _verify_validity({"validity_model": "perpetual"}, NOW, [], notes) is True
    assert any("perpetual" in n for n in notes)


def test_validity_revocation_checked():
    notes = []
    assert _verify_validity({"validity_model": "revocation_checked"}, NOW, [], notes) is True
    assert any("revocation_checked" in n for n in notes)


def test_validity_unparseable_dates():
    reasons = []
    v = {"validity_model": "time_bounded", "not_before": "xx", "not_after": "yy"}
    assert _verify_validity(v, NOW, reasons, []) is False
    assert any("unparseable" in r for r in reasons)


def test_validity_unknown_model():
    reasons = []
    assert _verify_validity({"validity_model": "wat"}, NOW, reasons, []) is False
    assert any("unknown" in r for r in reasons)


# ---- issuer binding branches ------------------------------------------------


def test_issuer_binding_issuer_not_object():
    notes = []
    assert _issuer_binding({}, "not-an-object", notes) is False


def test_issuer_binding_mismatch():
    notes = []
    issuer = {"id_scheme": "did:key", "id": "did:key:zABC"}
    assert _issuer_binding({"key_id": "did:key:zXYZ"}, issuer, notes) is False
    assert any("UNVERIFIED" in n for n in notes)


def test_issuer_binding_non_didkey_scheme():
    notes = []
    assert _issuer_binding({}, {"id_scheme": "platform-handle"}, notes) is False
    assert any("UNBINDABLE" in n for n in notes)


# ---- helper -----------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out
