# Decision 002: immutable references, typed results and compatibility

The demonstration caller accepts a locally controlled policy containing an exact HTTPS origin, profile, AMD root digest, launch measurement, minimum TCB and a GitHub repository/commit/path/content digest. Network responses cannot supply trusted policy. No automatic DNS/IP reference selection is used by this API.

Collection and pure appraisal are separate. Frozen bundles contain evidence, public endorsements, challenge and exact reference bytes. Pure appraisal accepts an independent policy and evaluation time; its result is historical and never constructs an application client. Live connection establishment generates its own challenge, verifies evidence, then probes the report endpoint over HTTPS using only the appraised certificate before exposing an origin-scoped client. No redirect or HTTP downgrade is allowed. Shared certificates do not share admission decisions across origins.

Results carry ordered checks, stable reason codes and distinct invalid-evidence, policy-mismatch, unsupported-profile and dependency-unavailable statuses. They also carry fingerprints, reference identity, coverage, bindings, timings and limitations. The result is not a signed remote attestation result.

Confido 0.2.0 exposes the pure verification API. Legacy `aTLS_connect*` entry points were removed from the current library; callers must migrate to the explicit verification result and manage transport admission separately. The demo and revised CLI use the pure API. Rust does not require Python or WASM dependencies; the wheel enables the `python` feature. Linux x86_64 / CPython 3.10 is the frozen demonstration target.

## Digest definitions

`reference.sha256` covers the exact fetched UTF-8 reference bytes, including whitespace. `evidence_sha256` covers compact `serde_json` serialization of the complete report JSON value (object keys ordered lexicographically), rather than the HTTP transfer's whitespace. Certificate and AMD ARK fingerprints cover complete X.509 DER; the vTPM key fingerprint covers DER SubjectPublicKeyInfo. The quote's IMA digest uses the fixed Rust struct field order, independently checked against `lib/tests/fixtures/binding-v1.json`. These are distinct serializations and must not be interchanged.
