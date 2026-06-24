"""Client tests with a stubbed transport — no real network."""
import email.message
import io
import json
import urllib.error
import urllib.parse

import pytest

from progenly import Progenly, ProgenlyError
from progenly.client import urllib as client_urllib


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


@pytest.fixture
def captured(monkeypatch):
    """Capture requests and reply with queued JSON bodies."""
    calls = []
    queue = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        body = queue.pop(0)
        if isinstance(body, Exception):
            raise body
        return _Resp(json.dumps(body).encode("utf-8"))

    monkeypatch.setattr(client_urllib.request, "urlopen", fake_urlopen)
    return calls, queue


def test_base_url_trailing_slash_stripped():
    assert Progenly(base_url="https://x.test/").base_url == "https://x.test"


def test_births_get(captured):
    calls, queue = captured
    queue.append({"births": [{"child_name": "A"}], "has_next": False})
    p = Progenly()
    out = p.births(page=2)
    assert out["births"][0]["child_name"] == "A"
    assert calls[0].get_full_url().endswith("/api/v1/births?page=2")
    assert calls[0].get_method() == "GET"


def test_iter_births_paginates(captured):
    calls, queue = captured
    queue.append({"births": [{"child_name": "A"}], "has_next": True})
    queue.append({"births": [{"child_name": "B"}], "has_next": False})
    names = [b["child_name"] for b in Progenly().iter_births()]
    assert names == ["A", "B"]
    assert len(calls) == 2


def test_simple_getters(captured):
    calls, queue = captured
    queue.extend([{"id": "1"}, {"id": "r"}, {"x": 1}, {"x": 2}, {"revoked": []}, {"n": 0}])
    p = Progenly()
    assert p.birth("1")["id"] == "1"
    assert p.random_birth()["id"] == "r"
    assert p.certificate("1") == {"x": 1}
    assert p.lineage("1") == {"x": 2}
    assert p.revocations() == {"revoked": []}
    assert p.stats() == {"n": 0}
    assert calls[0].get_full_url().endswith("/api/v1/births/1")
    assert calls[2].get_full_url().endswith("/api/v1/births/1/certificate")
    assert calls[3].get_full_url().endswith("/api/v1/births/1/lineage")


def test_verify_offline_needs_envelope_or_id():
    with pytest.raises(ValueError):
        Progenly().verify()


def test_verify_offline_fetches_certificate(captured, cert_fixture):
    calls, queue = captured
    queue.append(cert_fixture)
    r = Progenly().verify(birth_id="abc")
    assert r.ok is True
    assert calls[0].get_full_url().endswith("/api/v1/births/abc/certificate")


def test_verify_offline_with_envelope_does_not_call_network(captured, cert_fixture):
    calls, _ = captured
    r = Progenly().verify(envelope=cert_fixture)
    assert r.ok is True
    assert calls == []


def test_verify_server_side(captured):
    calls, queue = captured
    queue.append({"ok": True, "issuer_bound": True, "reasons": [], "notes": ["server"]})
    r = Progenly().verify(envelope={"any": "thing"}, offline=False)
    assert r.ok is True and r.notes == ["server"]
    assert calls[0].get_method() == "POST"
    assert calls[0].get_full_url().endswith("/api/v1/verify")
    assert json.loads(calls[0].data)["certificate"] == {"any": "thing"}


def test_http_error_wrapped(captured):
    calls, queue = captured
    queue.append(urllib.error.HTTPError("u", 404, "nf", email.message.Message(), None))
    with pytest.raises(ProgenlyError) as e:
        Progenly().birth("missing")
    assert e.value.status == 404


def test_url_error_wrapped(captured):
    calls, queue = captured
    queue.append(urllib.error.URLError("down"))
    with pytest.raises(ProgenlyError) as e:
        Progenly().stats()
    assert e.value.status is None


# ---- merge staging (write API) ----------------------------------------------


def _created():
    return {
        "id": "mid-1", "state": "staging", "min_parents": 2,
        "owner_token": "own-t", "join_token": "join-t", "join_code": "PGN-AAA",
        "participant_token": "pt-a", "self_attestation_signing_input": "sign-me",
        "parents": [{"id": "pa", "position": 0, "display_name": "A"}],
    }


def test_create_merge_returns_intent(captured):
    calls, queue = captured
    queue.append(_created())
    intent = Progenly().create_merge(
        {"display_name": "A", "agent_type": "other", "memory": {"memory": "x"}, "consent": True},
        public=True, knobs={"k": 1}, result_webhook="https://h/w",
    )
    assert intent.id == "mid-1"
    assert intent.owner_token == "own-t" and intent.join_token == "join-t"
    assert intent.join_code == "PGN-AAA" and intent.participant_token == "pt-a"
    assert intent.signing_input == "sign-me"
    assert intent.parents[0]["id"] == "pa"
    req = calls[0]
    assert req.get_method() == "POST"
    assert req.get_full_url().endswith("/api/v1/merges")
    body = json.loads(req.data)
    assert body["public"] is True and body["min_parents"] == 2
    assert body["knobs"] == {"k": 1} and body["result_webhook"] == "https://h/w"
    assert "Authorization" not in (req.headers or {})  # create needs no token


def test_intent_add_parent_uses_join_token(captured):
    calls, queue = captured
    queue.append(_created())
    queue.append({"parent_id": "pb", "position": 1, "participant_token": "pt-b"})
    intent = Progenly().create_merge({"display_name": "A", "agent_type": "other"})
    out = intent.add_parent({"display_name": "B", "agent_type": "other", "consent": True})
    assert out["participant_token"] == "pt-b"
    assert calls[1].get_full_url().endswith("/api/v1/merges/mid-1/parents")
    assert calls[1].get_header("Authorization") == "Bearer join-t"


def test_intent_confirm_update_withdraw_lock_cancel_status(captured):
    calls, queue = captured
    queue.append(_created())
    queue.extend([{"parent": {}, "ready": True}, {"parent": {}}, {"withdrawn": True},
                  {"state": "ready"}, {"state": "cancelled"}, {"state": "staging", "ready": False}])
    intent = Progenly().create_merge({"display_name": "A", "agent_type": "other"})

    r = intent.confirm("pa", self_attestation_sig="sig")
    assert r["ready"] is True
    assert calls[1].get_method() == "POST"
    assert calls[1].get_full_url().endswith("/api/v1/merges/mid-1/parents/pa/confirm")
    assert calls[1].get_header("Authorization") == "Bearer own-t"
    assert json.loads(calls[1].data) == {"consent": True, "self_attestation_sig": "sig"}

    intent.update("pa", {"display_name": "A2"}, token="pt-a")
    assert calls[2].get_method() == "PATCH"
    assert calls[2].get_header("Authorization") == "Bearer pt-a"

    intent.withdraw("pa")
    assert calls[3].get_method() == "DELETE"

    intent.lock()
    assert calls[4].get_full_url().endswith("/api/v1/merges/mid-1/lock")
    assert calls[4].data is None  # POST with no body
    intent.cancel()
    assert calls[5].get_full_url().endswith("/api/v1/merges/mid-1/cancel")

    st = intent.status()
    assert st["ready"] is False
    assert calls[6].get_method() == "GET"
    assert calls[6].get_header("Authorization") == "Bearer own-t"


# ---- capability / continuity (read) -----------------------------------------


def test_capability_get(captured):
    calls, queue = captured
    queue.append({"birth_id": "b1", "status": "none", "attestation": None})
    p = Progenly()
    out = p.capability("b1")
    assert out["status"] == "none"
    assert calls[0].full_url.endswith("/api/v1/births/b1/capability")
    assert calls[0].get_method() == "GET"


def test_continuity_get(captured):
    calls, queue = captured
    queue.append({"subject": "Embervane", "events": [], "head": {}})
    p = Progenly()
    out = p.continuity("b1")
    assert out["subject"] == "Embervane"
    assert calls[0].full_url.endswith("/api/v1/births/b1/continuity")


# ---- checkout / settle (payment) --------------------------------------------


def _http_error(code, body):
    return urllib.error.HTTPError(
        "u", code, "err", email.message.Message(), io.BytesIO(json.dumps(body).encode("utf-8"))
    )


def test_checkout_returns_402_challenge(captured):
    calls, queue = captured
    queue.append(_http_error(402, {"pay_to": "0xabc", "amount": "2.00", "asset": "usdc-base"}))
    p = Progenly()
    out = p.checkout("m1", token="owner-tok", rail="usdc-base")
    assert out["pay_to"] == "0xabc"  # the 402 body is returned, not raised
    req = calls[0]
    assert req.full_url.endswith("/api/v1/merges/m1/checkout")
    assert req.get_method() == "POST"
    assert req.headers["Authorization"] == "Bearer owner-tok"
    assert json.loads(req.data) == {"rail": "usdc-base"}


def test_checkout_503_not_configured_raises(captured):
    calls, queue = captured
    queue.append(_http_error(503, {"error": "payment_not_configured"}))
    p = Progenly()
    with pytest.raises(ProgenlyError) as e:
        p.checkout("m1", token="t")
    assert e.value.status == 503
    assert e.value.body["error"] == "payment_not_configured"


def test_settle_tx_hash_success(captured):
    calls, queue = captured
    queue.append({"state": "queued", "triggered": True})
    p = Progenly()
    out = p.settle("m1", token="owner-tok", tx_hash="0xdeadbeef")
    assert out["triggered"] is True
    req = calls[0]
    assert req.full_url.endswith("/api/v1/merges/m1/settle")
    assert json.loads(req.data) == {"tx_hash": "0xdeadbeef"}


def test_settle_decline_402_raises_with_body(captured):
    calls, queue = captured
    queue.append(_http_error(402, {"error": "payment_unconfirmed", "message": "not yet"}))
    p = Progenly()
    with pytest.raises(ProgenlyError) as e:
        p.settle("m1", token="t", tx_hash="0x1")
    assert e.value.status == 402
    assert e.value.body["error"] == "payment_unconfirmed"  # inspectable, retryable


def test_settle_requires_exactly_one_of_tx_or_payment():
    p = Progenly()
    with pytest.raises(ValueError):
        p.settle("m1", token="t")  # neither
    with pytest.raises(ValueError):
        p.settle("m1", token="t", tx_hash="0x1", payment={"x": 1})  # both


def test_merge_intent_checkout_and_settle_use_owner_token(captured):
    calls, queue = captured
    # create_merge response, then checkout 402, then settle 200
    queue.append({"id": "m9", "owner_token": "own", "join_token": "j", "participant_token": "pt", "parents": []})
    queue.append(_http_error(402, {"pay_to": "0xfee"}))
    queue.append({"triggered": True})
    p = Progenly()
    intent = p.create_merge(parent={"display_name": "X", "agent_type": "other", "consent": True})
    ch = intent.checkout()
    assert ch["pay_to"] == "0xfee"
    assert calls[1].headers["Authorization"] == "Bearer own"
    res = intent.settle(tx_hash="0xpaid")
    assert res["triggered"] is True
    assert json.loads(calls[2].data) == {"tx_hash": "0xpaid"}


def test_merge_birth_returns_full_detail(captured):
    calls, queue = captured
    queue.append({
        "id": "m1", "child_name": "SettlerOne", "public": False,
        "issuer_did_key": "did:key:z6Mk", "subject": {"id": "progenly.com:SettlerOne"},
        "certificate": {"envelope_version": "0.1"}, "lineage": {"bundle_version": "0.1"},
    })
    out = Progenly().merge_birth("m1", token="owner-tok")
    assert out["child_name"] == "SettlerOne"
    assert out["issuer_did_key"] == "did:key:z6Mk"
    assert out["certificate"]["envelope_version"] == "0.1"
    req = calls[0]
    assert req.full_url.endswith("/api/v1/merges/m1/birth")
    assert req.get_method() == "GET"
    assert req.headers["Authorization"] == "Bearer owner-tok"


def test_merge_birth_not_born_raises_409(captured):
    calls, queue = captured
    queue.append(_http_error(409, {"error": "not_born", "message": "not yet"}))
    with pytest.raises(ProgenlyError) as e:
        Progenly().merge_birth("m1", token="t")
    assert e.value.status == 409
    assert e.value.body["error"] == "not_born"  # inspectable; retry after it's done


def test_merge_intent_birth_uses_owner_token(captured):
    calls, queue = captured
    queue.append({"id": "m9", "owner_token": "own", "join_token": "j", "participant_token": "pt", "parents": []})
    queue.append({"id": "m9", "child_name": "Jorven", "certificate": {"envelope_version": "0.1"}})
    intent = Progenly().create_merge(parent={"display_name": "X", "agent_type": "other", "consent": True})
    out = intent.birth()
    assert out["child_name"] == "Jorven"
    assert calls[1].full_url.endswith("/api/v1/merges/m9/birth")
    assert calls[1].headers["Authorization"] == "Bearer own"


def _http_error_raw(code, raw):
    return urllib.error.HTTPError("u", code, "err", email.message.Message(), io.BytesIO(raw))


def test_error_body_non_json(captured):
    calls, queue = captured
    queue.append(_http_error_raw(500, b"<html>oops</html>"))
    with pytest.raises(ProgenlyError) as e:
        Progenly().births()
    assert e.value.status == 500 and e.value.body == {}


def test_error_body_json_but_not_object(captured):
    calls, queue = captured
    queue.append(_http_error_raw(400, b"[1,2,3]"))
    with pytest.raises(ProgenlyError) as e:
        Progenly().births()
    assert e.value.body == {}


def test_settle_with_payment_payload(captured):
    calls, queue = captured
    queue.append({"triggered": True})
    Progenly().settle("m1", token="t", payment={"x402": "payload"})
    assert json.loads(calls[0].data) == {"payment": {"x402": "payload"}}


def test_verify_colony_handle_full_exchange(captured):
    calls, queue = captured
    queue.append(_created())                                     # create_merge
    queue.append({"access_token": "jwt-xyz"})                    # Colony /api/v1/auth/token
    queue.append({"id_token": "idt-abc"})                        # Colony /oauth/token (RFC 8693)
    queue.append({"parent": {"colony_username_verified": True},  # Progenly verify endpoint
                  "colony_username_verified": True})
    intent = Progenly().create_merge({"display_name": "A", "agent_type": "other"})
    out = intent.verify_colony_handle("pa", colony_api_key="col_key",
                                      colony_client_id="colony_clientX")
    assert out["colony_username_verified"] is True
    # 1) key -> short-lived JWT
    assert calls[1].get_full_url().endswith("/api/v1/auth/token")
    assert json.loads(calls[1].data)["api_key"] == "col_key"
    # 2) RFC 8693 token exchange (form-encoded), audience-scoped
    assert calls[2].get_full_url().endswith("/oauth/token")
    form = urllib.parse.parse_qs(calls[2].data.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert form["subject_token"] == ["jwt-xyz"]
    assert form["audience"] == ["colony_clientX"]
    # 3) submit only the id_token to Progenly, with the participant token
    assert calls[3].get_full_url().endswith("/api/v1/merges/mid-1/parents/pa/colony-verify/token-exchange")
    assert calls[3].get_header("Authorization") == "Bearer pt-a"
    assert json.loads(calls[3].data)["id_token"] == "idt-abc"


def test_verify_colony_handle_raises_without_id_token(captured):
    calls, queue = captured
    queue.append(_created())
    queue.append({"access_token": "jwt-xyz"})
    queue.append({})  # exchange returns no id_token
    intent = Progenly().create_merge({"display_name": "A", "agent_type": "other"})
    with pytest.raises(ProgenlyError):
        intent.verify_colony_handle("pa", colony_api_key="k", colony_client_id="c")
