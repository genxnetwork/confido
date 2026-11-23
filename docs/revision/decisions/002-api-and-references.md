# Decision 002: immutable references, typed results and compatibility

The demonstration caller accepts a locally controlled policy containing an
exact HTTPS origin, profile, AMD root digest, launch measurement, minimum TCB
and a GitHub repository/commit/path/content digest. Network responses cannot
supply trusted policy. This API does not select a reference from DNS or IP
metadata.

Collection and pure appraisal are separate. Frozen bundles contain evidence,
public endorsements, challenge and exact reference bytes. Pure appraisal
accepts an independent policy and evaluation time; its result is historical
and never constructs an application client. Live connection establishment
generates its own challenge, verifies evidence, then probes the report
endpoint over HTTPS using the appraised certificate before exposing an
origin-scoped client. Redirects and HTTP downgrade are rejected. Shared
certificates do not share admission decisions across origins.

Results carry ordered checks, stable reason codes and the `verified`,
`invalid_evidence`, `policy_mismatch`, `unsupported_profile` and
`incomplete_input` statuses. They also carry fingerprints, reference identity,
coverage, bindings and limitations. Caller timings are recorded separately;
the evidence result is not a signed remote attestation result.

Confido 0.2.0 exposes the pure verification API. Legacy `aTLS_connect*` entry
points were removed; callers use the explicit verification result and manage
transport admission separately. The demo and CLI use the pure API. The Rust
core has no Python or WASM dependency; the Python wheel adds a PyO3 wrapper.
Linux x86_64 / CPython 3.10 is the frozen demonstration target.

## Digest definitions

`reference.sha256` covers the exact fetched UTF-8 reference bytes, including
whitespace. `report_sha256` covers the exact report JSON bytes supplied to the
verifier; it is not a digest of reserialized JSON. Certificate and AMD ARK
fingerprints cover complete X.509 DER; the vTPM key fingerprint covers DER
SubjectPublicKeyInfo. The quote's IMA digest uses the fixed Rust struct field
order, independently checked against `lib/tests/fixtures/binding-v1.json`.
These serializations serve different purposes and must not be interchanged.
