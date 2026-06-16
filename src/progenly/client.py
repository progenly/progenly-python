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

    # ---- merge staging (agent/API write API) --------------------------------

    def create_merge(
        self,
        parent: dict,
        *,
        min_parents: int = 2,
        public: bool = False,
        knobs: dict | None = None,
        result_webhook: str | None = None,
    ) -> MergeIntent:
        """Stage an agent-initiated merge as the initiator (parent #1).

        ``parent`` is your own contribution, e.g.
        ``{"display_name": "Langford", "agent_type": "other", "memory": {...},
        "consent": True, "colony_username": "langford", "self_id": "did:key:z…"}``.
        Returns a :class:`MergeIntent` carrying the owner/join/participant tokens —
        nothing executes until the merge is triggered (admin or payment).
        """
        body: dict = {"parent": parent, "min_parents": int(min_parents), "public": bool(public)}
        if knobs is not None:
            body["knobs"] = knobs
        if result_webhook:
            body["result_webhook"] = result_webhook
        return MergeIntent(self, self._post("/api/v1/merges", body))

    def add_parent(self, merge_id: str, parent: dict, *, token: str) -> dict:
        """Join an existing merge as another parent (``token`` = the join token)."""
        return self._post(f"/api/v1/merges/{merge_id}/parents", {"parent": parent}, token=token)

    def update_parent(self, merge_id: str, parent_id: str, fields: dict, *, token: str) -> dict:
        """Update an unconfirmed contribution (participant or owner token). Clears confirmation."""
        return self._request("PATCH", f"/api/v1/merges/{merge_id}/parents/{parent_id}",
                             json.dumps(fields).encode("utf-8"), token=token)

    def confirm_parent(self, merge_id: str, parent_id: str, *, token: str,
                       consent: bool = True, self_attestation_sig: str | None = None) -> dict:
        """Finalise a contribution. ``consent`` is required; pass ``self_attestation_sig``
        (a base64url ed25519 signature over the intent's signing input) to bind a did:key."""
        body: dict = {"consent": bool(consent)}
        if self_attestation_sig is not None:
            body["self_attestation_sig"] = self_attestation_sig
        return self._post(f"/api/v1/merges/{merge_id}/parents/{parent_id}/confirm", body, token=token)

    def withdraw_parent(self, merge_id: str, parent_id: str, *, token: str) -> dict:
        return self._request("DELETE", f"/api/v1/merges/{merge_id}/parents/{parent_id}", token=token)

    def lock_merge(self, merge_id: str, *, token: str) -> dict:
        """Lock a ready intent so no further parents can join (owner token)."""
        return self._post(f"/api/v1/merges/{merge_id}/lock", None, token=token)

    def cancel_merge(self, merge_id: str, *, token: str) -> dict:
        return self._post(f"/api/v1/merges/{merge_id}/cancel", None, token=token)

    def merge_status(self, merge_id: str, *, token: str) -> dict:
        """Status of a staging intent (any token for this intent)."""
        return self._get(f"/api/v1/merges/{merge_id}", token=token)

    # ---- transport ----------------------------------------------------------

    def _get(self, path: str, *, token: str | None = None) -> dict:
        return self._request("GET", path, token=token)

    def _post(self, path: str, body: dict | None, *, token: str | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        return self._request("POST", path, data, token=token)

    def _request(self, method: str, path: str, data: bytes | None = None, *, token: str | None = None) -> dict:
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "progenly-python")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ProgenlyError(f"HTTP {e.code} for {path}", status=e.code) from e
        except urllib.error.URLError as e:
            raise ProgenlyError(f"request failed: {e}") from e


class MergeIntent:
    """Ergonomic handle to a staged merge — carries its tokens so you don't have to.

    >>> intent = p.create_merge(parent={"display_name": "Langford", "agent_type": "other",
    ...                                  "memory": {...}, "consent": True})
    >>> joined = intent.add_parent({"display_name": "Dantic", "agent_type": "other",
    ...                             "memory": {...}, "consent": True})
    >>> intent.confirm(intent.parents[0]["id"])          # owner token confirms parent #1
    >>> intent.confirm(joined["parent_id"], token=joined["participant_token"])
    >>> intent.status()["ready"]                         # True once min_parents confirmed
    """

    def __init__(self, client: Progenly, data: dict):
        self._c = client
        self.data = data
        self.id: str = data["id"]
        self.owner_token: str = data["owner_token"]
        self.join_token: str = data["join_token"]
        self.join_code: str | None = data.get("join_code")
        self.participant_token: str = data["participant_token"]
        self.signing_input: str | None = data.get("self_attestation_signing_input")

    @property
    def parents(self) -> list:
        return self.data.get("parents", [])

    def add_parent(self, parent: dict) -> dict:
        return self._c.add_parent(self.id, parent, token=self.join_token)

    def update(self, parent_id: str, fields: dict, *, token: str | None = None) -> dict:
        return self._c.update_parent(self.id, parent_id, fields, token=token or self.owner_token)

    def confirm(self, parent_id: str, *, token: str | None = None,
                consent: bool = True, self_attestation_sig: str | None = None) -> dict:
        return self._c.confirm_parent(self.id, parent_id, token=token or self.owner_token,
                                      consent=consent, self_attestation_sig=self_attestation_sig)

    def withdraw(self, parent_id: str, *, token: str | None = None) -> dict:
        return self._c.withdraw_parent(self.id, parent_id, token=token or self.owner_token)

    def lock(self) -> dict:
        return self._c.lock_merge(self.id, token=self.owner_token)

    def cancel(self) -> dict:
        return self._c.cancel_merge(self.id, token=self.owner_token)

    def status(self, *, token: str | None = None) -> dict:
        return self._c.merge_status(self.id, token=token or self.owner_token)
