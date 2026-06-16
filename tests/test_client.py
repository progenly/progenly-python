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
