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

## Browse public data

```python
p = Progenly()

for birth in p.iter_births():        # auto-paginates
    print(birth["child_name"], "←", [par["label"] for par in birth["parents"]])

p.birth(birth_id)                    # one public birth (names only)
p.random_birth()
p.certificate(birth_id)              # the attestation envelope
p.lineage(birth_id)                  # whole-lineage proof bundle (all ancestor certs)
p.revocations()                      # revoked certificates
p.stats()                            # aggregate public stats
```

Everything returned is exactly what's public on the site — **names only**. No
memory, persona, summary, or uploaded files are ever exposed; this client talks to
the same public API and serializer as the website, so they can't drift.

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
