"""Offline-verifier tests against a real PHP-minted envelope (tests/fixtures/cert.json)."""
import copy
import datetime as dt
import json
import pathlib

import pytest

from progenly import canonicalize, public_key_from_did_key, verify_envelope
from progenly.verify import VerifyResult

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "cert.json"


@pytest.fixture
def cert():
    return json.loads(FIXTURE.read_text())


# ---- the happy path ---------------------------------------------------------


def test_valid_envelope(cert):
    r = verify_envelope(cert)
    assert r.ok is True
    assert r.issuer_bound is True
    assert r.reasons == []
    assert bool(r) is True  # __bool__ tracks ok


def test_verifyresult_repr_fields():
    r = VerifyResult(True, True, [], ["note"])
    assert r.notes == ["note"]
    assert bool(r) is True


# ---- tamper detection -------------------------------------------------------


def test_tampered_claim_fails(cert):
    cert["witnessed_claim"]["child_name"] = "Mallory"
    r = verify_envelope(cert)
    assert r.ok is False
    assert any("signature does not verify" in x for x in r.reasons)


def test_tampered_signature_fails(cert):
    sig = cert["sigchain"][0]["sig"]
    cert["sigchain"][0]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    r = verify_envelope(cert)
    assert r.ok is False


def test_swapped_issuer_breaks_binding(cert):
    cert["issuer"]["id"] = "did:key:z6MkpzZ7T1bf3yxfQ6rJYf3cYf3cYf3cYf3cYf3cYf3cYf3c"
    r = verify_envelope(cert)
    # signature is over the (now-mutated) issuer, so the sig fails too; binding is off regardless
    assert r.issuer_bound is False


# ---- validity window --------------------------------------------------------


def test_not_yet_valid(cert):
    before = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    r = verify_envelope(cert, now=before)
    assert r.ok is False
    assert any("not yet valid" in x for x in r.reasons)


def test_expired(cert):
    after = dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)
    r = verify_envelope(cert, now=after)
    assert r.ok is False
    assert any("expired" in x for x in r.reasons)


def test_within_window(cert):
    nb = dt.datetime.fromisoformat(cert["validity"]["not_before"].replace("Z", "+00:00"))
    r = verify_envelope(cert, now=nb + dt.timedelta(days=1))
    assert r.ok is True


# ---- structural rejects -----------------------------------------------------


def test_non_object_envelope():
    r = verify_envelope("nope")
    assert r.ok is False and r.issuer_bound is False


def test_missing_required_field(cert):
    del cert["sigchain"]
    r = verify_envelope(cert)
    assert r.ok is False
    assert any("sigchain" in x for x in r.reasons)


def test_bad_envelope_version(cert):
    cert["envelope_version"] = "9.9"
    r = verify_envelope(cert)
    assert r.ok is False
    assert any("envelope_version" in x for x in r.reasons)


def test_empty_evidence(cert):
    cert["evidence"] = []
    r = verify_envelope(cert)
    assert r.ok is False
    assert any("evidence" in x for x in r.reasons)


# ---- did:key decoding -------------------------------------------------------


def test_did_key_roundtrip(cert):
    pub = public_key_from_did_key(cert["issuer"]["id"])
    assert isinstance(pub, bytes) and len(pub) == 32


def test_did_key_rejects_non_didkey():
    with pytest.raises(ValueError):
        public_key_from_did_key("z6Mkbogus")


def test_did_key_rejects_bad_base58():
    with pytest.raises(ValueError):
        public_key_from_did_key("did:key:z0OIl")  # 0 O I l are not base58


# ---- canonicalization -------------------------------------------------------


def test_canonicalize_sorts_keys():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonicalize_compact_unicode():
    assert canonicalize({"x": "é"}) == '{"x":"é"}'.encode("utf-8")


def test_canonicalize_is_stable_under_reorder(cert):
    reordered = dict(reversed(list(cert.items())))
    assert canonicalize(cert) == canonicalize(reordered)
    assert verify_envelope(copy.deepcopy(reordered)).ok is True
