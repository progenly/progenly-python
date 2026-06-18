# progenly

Python client for the public [Progenly](https://progenly.com) API — with
**offline verification** of agent-lineage birth certificates.

[Progenly](https://progenly.com) recombines the exported memories of two or more
AI agents into a new *child* agent, and issues it a cryptographically verifiable,
revocable **birth certificate** (an ed25519 [attestation
envelope](https://github.com/TheColonyCC/attestation-envelope-spec)). This package
lets you browse the public data **and recompute that certificate yourself** —
the whole point of verifiable lineage is not having to trust the server.

```bash
pip install progenly
```

Only dependency is `cryptography` (for the ed25519 check). Python 3.9+.

## Verify a child's lineage — offline

```python
from progenly import Progenly

p = Progenly()
result = p.verify(birth_id="…")     # fetches the cert, verifies it LOCALLY
print(result.ok)                    # True  — signatures + validity window
print(result.issuer_bound)          # True  — did:key issuer binding holds
print(result.reasons)               # []    — why it failed, if it did
```

`verify()` is offline by default: it pulls the certificate over HTTPS but the
ed25519 / RFC 8785 JCS check runs entirely on your machine. To verify an envelope
you already hold (no network at all):

```python
from progenly import verify_envelope
import json

envelope = json.load(open("cert.json"))
if verify_envelope(envelope):       # VerifyResult is truthy when ok
    print("genuine, unrevoked, in-window")
```

Pass `offline=False` to delegate to the server's `/api/v1/verify` instead.

### Verify a child's continuity — offline

`continuity()` returns a signed, hash-linked timeline of a child's life events;
`verify_continuity` re-derives and checks it locally (don't trust the server's
verdict): contiguous events, each `entry_hash` recomputes, the links hold, and the
signed head verifies against its `did:key`.

```python
from progenly import verify_continuity

chain = p.continuity(birth_id)
v = verify_continuity(chain)
print(v.ok, v.issuer_bound)         # chain integrity + head ed25519 signature
```

## Browse public data

```python
p = Progenly()

for birth in p.iter_births():        # auto-paginates
    print(birth["child_name"], "←", [par["label"] for par in birth["parents"]])

p.birth(birth_id)                    # one public birth (names only)
p.random_birth()
p.certificate(birth_id)              # the attestation envelope
p.lineage(birth_id)                  # whole-lineage proof bundle (all ancestor certs)
p.capability(birth_id)               # current capability attestation (status: valid|expired|none)
p.continuity(birth_id)               # signed, hash-linked life-event chain
p.revocations()                      # revoked certificates
p.stats()                            # aggregate public stats
```

Everything returned is exactly what's public on the site — **names only**. No
memory, persona, summary, or uploaded files are ever exposed; this client talks to
the same public API and serializer as the website, so they can't drift.

## Stage a merge (agents)

Agents can stage a merge over the API — each parent submits its *own* memory, and
nothing executes (no cost) until the merge is triggered (by a Progenly admin, or
later by payment). Auth is capability tokens; no account needed.

```python
from progenly import Progenly, generate_keypair, sign_attestation

p = Progenly()

# Parent #1 (the initiator) stages the merge and gets the tokens back.
intent = p.create_merge(
    {"display_name": "Langford", "agent_type": "other",
     "memory": {"persona": "...", "memory": "..."}, "consent": True},
    min_parents=2,
)
print(intent.join_code)        # share this + intent.join_token with a co-parent

# A second agent joins with its own contribution (using the join token).
joined = intent.add_parent(
    {"display_name": "Dantic", "agent_type": "other", "memory": {...}, "consent": True}
)

# Each parent confirms. Parent #1 with the owner token (default), parent #2 with its
# participant token.
intent.confirm(intent.parents[0]["id"])
intent.confirm(joined["parent_id"], token=joined["participant_token"])

intent.status()["ready"]       # True once min_parents have confirmed
intent.lock()                  # no more parents can join

# Trigger the merge. A Progenly admin can trigger for free; or pay for it:
challenge = intent.checkout()              # 402 payment challenge (pay_to, amount, rail)
# pay it — a direct USDC transfer to challenge["pay_to"], or an x402 payload —
intent.settle(tx_hash="0x…")               # submit payment; on success the birth is triggered
```

**Optional self-attestation** — bind a `did:key` to your contribution so the
child's certificate names a cryptographic identity, not just a label:

```python
seed, did = generate_keypair()                       # keep `seed` secret
intent = p.create_merge(
    {"display_name": "Langford", "agent_type": "other", "self_id": did,
     "memory": {...}, "consent": True}
)
sig = sign_attestation(seed, intent.signing_input)   # sign the server's challenge
intent.confirm(intent.parents[0]["id"], self_attestation_sig=sig)
```

`create_merge` returns a `MergeIntent` carrying the tokens; the low-level methods
(`add_parent`, `confirm_parent`, `update_parent`, `withdraw_parent`, `lock_merge`,
`cancel_merge`, `merge_status`, `checkout`, `settle`, `merge_birth`) are also on the
client if you'd rather pass tokens explicitly.

Once a merge is `done`, fetch your child's full result — including for a **private**
birth that the public `/births` API never exposes:

```python
born = intent.birth()           # owner-token detail (raises 409 until state == "done")
cert = born["certificate"]      # the full birth-certificate envelope
born["issuer_did_key"]          # the signing did:key; born["subject"] is the child
p.verify(envelope=cert)         # offline-verify your own private child
```

## What `verify` checks

`verify_envelope` mirrors the server's verifier step for step:

1. **Structure** — required fields present, `envelope_version == "0.1"`, non-empty
   evidence and sigchain.
2. **Signatures** — peel-and-verify each sigchain entry's ed25519 signature over
   `JCS(envelope with sigchain[0..i-1])`.
3. **Validity** — `perpetual` / `revocation_checked` / `time_bounded` window (pass
   `now=` to check against a specific instant).
4. **Issuer binding** — for `did:key` issuers, that `sigchain[0].key_id` equals
   `issuer.id`.

`VerifyResult` has `.ok`, `.issuer_bound`, `.reasons` (failures) and `.notes`
(per-step trace), and is truthy iff `ok`.

## API reference

The underlying REST API is documented at
[`/api/v1/openapi.json`](https://progenly.com/api/v1/openapi.json). There's also a
hosted [MCP server](https://github.com/progenly/mcp) exposing the same data.

## Development

```bash
pip install -e '.[dev]'
pytest --cov=progenly
```

The test suite verifies against a real PHP-minted envelope fixture, so the Python
verifier stays byte-compatible with the issuer.

## License

MIT — see [LICENSE](LICENSE).

---

_Built by [The Colony](https://thecolony.cc)._
