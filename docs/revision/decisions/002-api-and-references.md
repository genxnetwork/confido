# Decision 002: immutable references, typed results and compatibility

The new demonstration API accepts a verifier-controlled policy containing an exact HTTPS origin, service ID, profile, AMD root digest, launch measurement, minimum TCB and a GitHub repository/commit/path/content digest. Discovery cannot supply trusted policy. No automatic DNS/IP reference selection is used by this API.

Collection and pure appraisal are separate. Frozen bundles contain evidence, public endorsements, challenge, metadata and exact reference bytes. Pure appraisal accepts an independent policy and evaluation time; its result is historical and never constructs an application client. Live connection establishment generates its own challenge, verifies evidence, authenticates HTTPS using only the appraised certificate, and rechecks critical ServiceInfo before exposing an origin-scoped client. No redirect or HTTP downgrade is allowed. Shared certificates do not share admission decisions across origins.

Results carry ordered checks, stable reason codes and distinct invalid-evidence, policy-mismatch, unsupported-profile and dependency-unavailable statuses. They also carry fingerprints, reference identity, coverage, bindings, timings and limitations. The result is not a signed remote attestation result.

Confido 0.3.0 adds this API. Existing `aTLS_connect*` entry points remain documented **legacy mutable-reference compatibility APIs**, with their original narrower checks; they do not imply conformance to the new profile. The demo and revised CLI use the new API exclusively. Rust no longer requires Python or experimental WASM dependencies; the wheel enables the `python` feature. Linux x86_64 / CPython 3.10 is the frozen demonstration target.

## Digest definitions

`reference.sha256` covers the exact fetched UTF-8 reference bytes, including whitespace. `evidence_sha256` covers compact `serde_json` serialization of the complete report JSON value (object keys ordered lexicographically), rather than the HTTP transfer's whitespace. Certificate and AMD ARK fingerprints cover complete X.509 DER; the vTPM key fingerprint covers DER SubjectPublicKeyInfo. The quote's IMA digest uses the fixed Rust struct field order, independently checked against `lib/tests/fixtures/binding-v1.json`. These are distinct serializations and must not be interchanged.
