"""HTTP client for Progenly's public read API (https://progenly.com/api/v1)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Iterator

from .verify import VerifyResult, verify_envelope


class ProgenlyError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class Progenly:
    """Read-only client for public Progenly data, with offline certificate verification.

    >>> p = Progenly()
    >>> p.verify(birth_id="...").ok          # verified locally, no trust in the server
    >>> for b in p.iter_births(): ...
    """

    def __init__(self, base_url: str = "https://progenly.com", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ---- reads --------------------------------------------------------------

    def births(self, page: int = 1) -> dict:
        return self._get(f"/api/v1/births?page={int(page)}")

    def iter_births(self) -> Iterator[dict]:
        page = 1
        while True:
            data = self.births(page)
            yield from data.get("births", [])
            if not data.get("has_next"):
                return
            page += 1

    def birth(self, birth_id: str) -> dict:
        return self._get(f"/api/v1/births/{birth_id}")

    def random_birth(self) -> dict:
        return self._get("/api/v1/births/random")

    def certificate(self, birth_id: str) -> dict:
        return self._get(f"/api/v1/births/{birth_id}/certificate")

    def lineage(self, birth_id: str) -> dict:
        return self._get(f"/api/v1/births/{birth_id}/lineage")

    def revocations(self) -> dict:
        return self._get("/api/v1/revocations")

    def stats(self) -> dict:
        return self._get("/api/v1/stats")

    # ---- verification -------------------------------------------------------

    def verify(self, envelope: dict | None = None, birth_id: str | None = None, offline: bool = True) -> VerifyResult:
        """Verify a certificate. Pass an ``envelope`` or a ``birth_id``.

        ``offline=True`` (default) verifies the ed25519/JCS envelope locally — the
        whole point of verifiable lineage is not having to trust the server.
        ``offline=False`` delegates to the server's /api/v1/verify endpoint.
        """
        if envelope is None:
            if birth_id is None:
                raise ValueError("provide either `envelope` or `birth_id`")
            envelope = self.certificate(birth_id)

        if offline:
            return verify_envelope(envelope)

        data = self._post("/api/v1/verify", {"certificate": envelope})
        return VerifyResult(
            bool(data.get("ok")),
            bool(data.get("issuer_bound")),
            list(data.get("reasons", [])),
            list(data.get("notes", [])),
        )

    # ---- transport ----------------------------------------------------------

    def _get(self, path: str) -> dict:
        return self._request("GET", path)

    def _post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, json.dumps(body).encode("utf-8"))

    def _request(self, method: str, path: str, data: bytes | None = None) -> dict:
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "progenly-python")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ProgenlyError(f"HTTP {e.code} for {path}", status=e.code) from e
        except urllib.error.URLError as e:
            raise ProgenlyError(f"request failed: {e}") from e
