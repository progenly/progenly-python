"""Client tests with a stubbed transport — no real network."""
import email.message
import io
import json
import urllib.error

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
