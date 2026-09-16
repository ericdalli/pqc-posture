# pqc-posture

[![CI](https://github.com/ericdalli/pqc-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/ericdalli/pqc-posture/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![OpenSSL](https://img.shields.io/badge/openssl-3.5%2B-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A TLS post-quantum readiness scanner that distinguishes what an endpoint
*supports* from what it *negotiates*, and separates a server that declined a
hybrid key exchange from a network path that could not carry one. Evidence is
recorded per handshake and never merged; inference is a separate, recomputable
layer on top.

See [SCOPE.md](SCOPE.md) for authorised use. Real inventory and evidence files
are gitignored by design — they are internal network maps.

Four phases:

| Phase | Name | Output |
|---|---|---|
| 1 | Observation | evidence + topology assessment (no assumptions, no score) |
| 2 | Correlation | VIP/backend relationships → TLS path model |
| 3 | Infrastructure awareness | config: supported / enabled / negotiated |
| 4 | Posture & risk | PQC readiness, exposure, remediation |

**Phase 1 emits no grade.** Scoring a VIP before its role in the path is
established would be scoring a device whose function is unknown. `scoring.py`
exists and works; it belongs to Phase 4 and is only reachable through the flat
`--targets` mode.

Measures whether a TLS endpoint actually negotiates post-quantum hybrid key
exchange, what it is capable of negotiating, and whether the network path
between you and it can carry an ML-KEM key share at all.

Stdlib only. All crypto is delegated to an OpenSSL 3.5+ binary.

## Requirements

OpenSSL **3.5.0 or later**, which is where ML-KEM (FIPS 203) landed natively
with the `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` hybrid
groups. Distro OpenSSL is usually 3.0 or 3.2 and cannot offer them, so a
side-by-side build is normal:

```bash
export PQC_OPENSSL=/opt/openssl-3.5/bin/openssl   # or pass --openssl
```

Run against a client that cannot offer hybrid groups and the scanner says so
loudly and marks those probes `client_unsupported` rather than reporting the
target as lacking support. That distinction is load-bearing — see *Failure
classification* below.

## Usage

```bash
pqc-posture cloudflare.com:443 -v
pqc-posture -f targets.txt --json report.json --quiet
pqc-posture -f targets.txt --min-grade B          # exits 1 on regression
```

Targets accept `host`, `host:port`, or `host:port@sni`. The last form matters
for the Phase 2 lab, where you need to hit an App Gateway by IP while forcing
the SNI a listener expects.

Exit codes: `0` clean, `1` threshold not met, `2` usage error, `3` no usable
OpenSSL. Phase 3 gates on `1`.

## What it measures, and why it takes several handshakes

Three distinct questions, which a single handshake cannot separate:

1. **What does a current client get today?** One probe with the client's own
   defaults (hybrid-first on 3.5).
2. **What does a browser-shaped client get?** One probe offering
   `X25519MLKEM768:X25519:secp256r1:secp384r1`, mirroring Chrome. A server
   supporting only the classical fallback answers with HelloRetryRequest.
3. **What is the endpoint capable of?** One probe per group, offering exactly
   that group and nothing else. A completed handshake is proof of support with
   no inference about preference order.

Splitting 2 from 3 is the point. An endpoint that *supports* hybrid but does
not *prefer* it scores 40/60 on key exchange rather than 60, because in
production nobody gets the protection. That is usually a group-priority
one-liner, not a migration, and saying so changes the conversation with an
application owner.

Probes for a single target run **serially**; parallelism is across targets
(`--concurrency`). Firing a dozen simultaneous handshakes at one hostname is a
good way to get rate-limited by a WAF and then record the result as "no PQ
support".

## Failure classification

The most useful thing this scanner does is distinguish two failures that look
identical in a naive implementation:

| Observation | Meaning | Remediation |
|---|---|---|
| TLS alert 40 on a hybrid-only ClientHello | Server understood and declined | Server-side config |
| Connection reset or silent drop, **no alert** | The ClientHello never arrived intact | Find the middlebox |

An ML-KEM-768 key share is 1216 bytes, which pushes the ClientHello past a
single 1500-byte MTU segment. Middleboxes that assume a ClientHello fits in one
TCP segment drop it silently. When small ClientHellos succeed on the same
endpoint and large ones die without an alert, the scanner raises
`LARGE_CLIENTHELLO_INTOLERANCE` — because enabling hybrid KEX on the server
will not fix it, and may break clients that work today.

That heuristic will not fire for a group the local client could not offer.
Getting this wrong once, during development, produced a confident high-severity
finding about a network that was fine; there is a regression test pinning it.

## Scoring

100 points: key exchange 60, protocol hygiene 20, interop health 10,
certificate hygiene 10. Grades A≥85, B≥70, C≥50, D≥30.

Key exchange dominates deliberately. It is the only part of TLS with
*retroactive* exposure — traffic captured today is decryptable later, so a
classical-only handshake is a liability for as long as its contents stay
sensitive. Certificate signatures do not have that property: forging a
signature in 2035 buys nothing against a 2026 handshake. So classical cert
signatures are reported as `info`, never as a penalty. Treating signature
agility as urgent alongside key exchange is the most common way PQC roadmaps
lose the plot, and this tool declines to do it.

Pure ML-KEM groups (`MLKEM768` alone) are detected and flagged `low`. They are
not better than hybrid — they drop the classical hedge, so a future break in
ML-KEM itself has no fallback.

## JSON contract (Phase 3 depends on this)

`schema_version: 1`. The report separates stable facts from volatile ones, and
publishes the volatile list in the report itself as `_volatile_fields`:

```
started_at, finished_at, duration_ms, resolved_ip,
probes.*.duration_ms, certificate.days_remaining
```

The gate must strip these before diffing, or every run is a regression. Target
ordering is deterministic and matches input order regardless of completion
order, for the same reason.

`resolved_ip` is recorded but excluded from diffing on purpose. Front Door and
other anycast frontends mean two runs can land on different POPs with different
TLS stacks; keeping the IP makes an otherwise baffling posture flip
explainable, without failing the build over it.

## Tests

```bash
python3 -m pytest tests/ -q      # 43 tests, no network required
```

The scanner's correctness lives almost entirely in how it reads `s_client`
output, which cannot be exercised without OpenSSL 3.5 and reachable endpoints.
Fixtures capture real output for the success, alert, reset, protocol-mismatch
and local-error paths so parsing is testable in CI on any runner.

## Known limits

- Pre-standard Kyber names (`X25519Kyber768Draft00`) are only probed with
  `--draft-groups` and only if an oqs-provider build exposes them. Stock 3.5
  cannot offer them, so endpoints still running draft Kyber will read as
  classical-only. Relevant for older F5 and nginx builds.
- HelloRetryRequest detection needs `--trace` and an OpenSSL built with
  `enable-ssl-trace`; it is feature-detected and reported as unknown otherwise.
- Client certificates, STARTTLS, and non-443 protocol wrappers are not handled.
- Session resumption is not exercised; a resumed session skips key exchange
  entirely, which is worth a look in a later phase.

## Next

Phase 2 stands up the Azure lab (App Service, Front Door, App Gateway, nginx on
OpenSSL 3.5, Key Vault) so there are endpoints with *known* posture to validate
the scanner against — including a deliberately hybrid-incapable one and,
ideally, a path with a small MTU to prove the intolerance heuristic fires on a
real network rather than only on a fixture.


---

# Phase 1 — Observation

```
SERVICE
   ├── FRONTEND (VIP)  ──► TLS probe ──► observations
   └── BACKEND(s)      ──► TLS probe ──► observations
                                   │
                          topology assessment (derived)
```

## Where the assumption boundary sits

"No assumptions" and "conclude TLS termination from the certificate" are in
tension — the second *is* an inference. The resolution is layering, not
compromise:

- **`evidence`** — one record per handshake. Endpoint, pass index, group
  offered, outcome, peer certificate fingerprint, timestamp. Never merged,
  never overwritten, never annotated with a conclusion.
- **`topology`** — a pure function of that evidence. Recomputable, overridable,
  discardable. It never writes back. There is a test pinning that.

So the evidence is assumption-free, and the assessment is a labelled opinion
sitting on top of it. When Phase 2 brings the path model and Phase 3 brings
configuration, the assessment gets recomputed against the same stored
evidence — no re-scanning, no contaminated records.

## The three-state support matrix

Every (peer, group) cell is one of:

| State | Meaning |
|---|---|
| `observed_supported` | a handshake completed with that group |
| `observed_rejected` | the peer sent an alert declining it |
| `not_observed` | **no evidence either way** |

The third state is the point. Behind a load balancer, "we never got an answer"
and "it is not supported" are completely different statements, and collapsing
them is how a scanner reports that a pool supports hybrid KEX when one member
out of four does.

## Repeat counts, and what they cannot tell you

`repeat` is the number of full sweep passes against an address. Peer identity
is captured on every probe, so pool discovery costs no extra connections.

Two limits stated rather than scored:

- Seeing all N members under random balancing takes roughly **N·ln(N)** draws,
  and that is optimistic.
- **Source-address persistence defeats repetition entirely.** A default F5
  virtual server with source-addr persistence pins every connection from this
  scanner to one member regardless of pass count. "All passes returned one peer
  identity" therefore means *either* a uniform pool *or* a pinned probe, and
  those are indistinguishable from a single source address. The tool says so
  instead of implying uniformity. Resolving it needs multiple source addresses,
  or the persistence profile — Phase 3.

The strongest available proof of a heterogeneous pool is **divergent outcomes
for the same group across passes at the same address**. That holds even when
every member presents an identical wildcard certificate, which cert
fingerprinting alone cannot see through.

## Topology inference and its ceiling

| Evidence | Observed | Confidence |
|---|---|---|
| frontend cert == backend cert, group sets match | `likely_passthrough` | medium |
| frontend cert != backend cert, group sets diverge | `likely_tls_termination` | **high** |
| frontend cert != backend cert, group sets match | `likely_tls_termination` | medium |
| frontend cert == backend cert, group sets diverge | `likely_tls_termination` | medium |
| backends declared, none answer TLS | `likely_tls_termination` | low |
| no backends declared | `indeterminate` | — |

Two things worth being explicit about:

**Group-set divergence is the only signal that reaches high confidence.** A
passthrough VIP forwards the handshake untouched, so the group set observed at
the VIP must match the member's exactly. Two TLS stacks accepting different
group sets cannot be one TLS stack. For a PQC project this is a happy
coincidence: the termination detector is the data you were already collecting.

**`terminate` and `reencrypt` are never separated.** Both present the
frontend's own certificate. The difference is what happens on the frontend →
backend leg, which is not observable from a client vantage point. Finding that
a backend speaks TLS shows re-encryption is *possible* — the frontend may still
be talking cleartext to a port that also happens to accept TLS. Phase 3.

Passthrough is capped at medium for a related reason: an F5 terminating with an
*imported copy* of the backend certificate produces evidence identical to
passthrough. That pattern is common and is routinely mislabelled in
documentation, which is why declared/observed conflicts are reported rather
than resolved in favour of the declaration.

## Input schema

Your shorthand works as-is; `vip` and `frontend` are interchangeable.

```json
{ "service": "def.company.com",
  "vip": { "ip": "10.1.1.3", "port": 443, "tls_mode": "passthrough" },
  "backends": ["30.1.1.2", "30.1.1.3"] }
```

Fuller form:

```json
{
  "version": 1,
  "defaults": { "port": 443, "repeat": 1, "frontend_repeat": 5 },
  "services": [{
    "service": "abc.company.com",
    "sni": "abc.company.com",
    "frontend": {
      "type": "f5", "ip": "10.1.1.10", "port": 443,
      "tls_mode": "reencrypt", "repeat": 12,
      "notes": "LTM round-robin, 4 pool members"
    },
    "backends": [
      { "ip": "30.1.2.11", "port": 8443, "label": "web01" },
      { "ip": "30.1.2.12", "port": 8443, "label": "web02" }
    ]
  }]
}
```

- `tls_mode`: `terminate` | `reencrypt` | `passthrough` | `unknown`. Aliases
  accepted (`offload`, `bridge`, `pass`). Absent means `unknown`.
- `type`: `f5`, `nginx`, `azure_front_door`, `azure_app_gateway`,
  `azure_app_service`, `aws_alb`, `aws_nlb`, `aws_cloudfront`, `cloudflare`,
  `palo_alto`, `other`, `none`, `unknown`. Aliases accepted (`bigip`, `appgw`,
  `afd`, `nlb`). A declared frontend block with **no** `type` is `unknown`, not
  `none` — `none` asserts the endpoint is the origin and inverts the topology
  logic.
- Backends inherit the service name as SNI. This matters: probing a backend IP
  with no SNI often returns a different default vhost, and the resulting
  certificate mismatch reads as a topology signal when it is a probe artefact.
- Declared type is never used to gate a probe. It is compared against the
  observation — an `aws_nlb` that presents its own certificate is either
  mislabelled or is not the device answering, and that is a finding.

```bash
pqc-posture -i inventory.json --repeat 10 --json evidence.json
```

Phase 1 exits 0 regardless of what it finds. Deciding what is acceptable is
Phase 4's job.

## Chained frontends

Front Door → App Gateway → App Service is one path with two terminating hops,
and the current schema models one frontend per service. Declare each hop as its
own service for now; stitching them into a single path model is Phase 2, which
is where that belongs.


---

# Development environment

## Quick start (Codespaces — nothing to install)

Press `.` on the repo, or **Code → Codespaces → Create codespace**. The
devcontainer builds on Ubuntu 26.04, which ships OpenSSL 3.5.x from apt, so
hybrid groups work immediately. A personal GitHub Free account includes 120
core-hours/month — 60 real hours on the default 2-core machine.

## Local (VS Code + Dev Containers)

```bash
git clone git@github.com:ericdalli/pqc-posture.git
cd pqc-posture
code .                      # then: "Reopen in Container"
```

Requires Docker Desktop or Podman. Same image as Codespaces, so behaviour
matches.

## Remote server (VS Code + Remote-SSH)

Install the **Remote-SSH** extension, `Ctrl+Shift+P` → *Remote-SSH: Connect to
Host*. The GUI runs locally; the code, terminal and git all execute on the
remote box. No copy/paste, no file syncing — VS Code handles transport over the
existing SSH session.

## Without a container

```bash
bash scripts/check-openssl.sh     # run this first
pip install -e ".[dev]"
git config core.hooksPath .githooks   # enable the pre-commit hook
pytest tests/ -q
```

`core.hooksPath` is local config and cannot be committed, so a fresh clone
needs that line. The dev container runs it for you. The hook runs shellcheck
and the test suite before each commit; bypass deliberately with
`git commit --no-verify` when you need a work-in-progress commit.

`check-openssl.sh` is the first thing to run on any new machine. A pre-3.5
OpenSSL is the single most common reason the scanner reports "no PQ support"
everywhere — the tool refuses to run rather than produce that answer, but the
script tells you why in one line.

OpenSSL by platform:

| Platform | 3.5 available? |
|---|---|
| Ubuntu 26.04 LTS | yes — `apt install openssl` (3.5.x) |
| Debian 13 (trixie) | yes — 3.5.x |
| Ubuntu 24.04 LTS | **no** — ships 3.0.13; build side by side |
| RHEL 9 / Rocky 9 | no — build side by side |
| macOS | `brew install openssl@3.5` |

For a side-by-side build, set `PQC_OPENSSL=/opt/openssl-3.5/bin/openssl` or
pass `--openssl`. The scanner also probes common 3.5 install prefixes
automatically.

## Note on CI

The test suite is fixture-driven: no network, no OpenSSL 3.5 required. That was
a deliberate design choice, and it is why CI stays green on GitHub-hosted
runners that still ship OpenSSL 3.0.
