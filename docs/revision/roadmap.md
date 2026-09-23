# Technical roadmap and interfaces

| Future function | Confido interface supplied now | Owning component / prerequisite |
|---|---|---|
| TLS session binding and re-attestation | versioned evidence contract, challenge and certificate/AK identifiers | TLS terminator/BoringSSL; connection-bound Exported Authenticators and an explicit SEAT profile |
| Bounded formal analysis | stated transcript v1, trust boundaries, failure states and fixture vectors | protocol analysis; model relay, substitution, replay and time-of-check/time-of-use assumptions before changing transcript |
| Governed reference updates | immutable repository/commit/path/digest and platform policy | reference authority; signed promotion, issuer/expiry, rollback protection, revocation and independently approved enrollment |
| Validated Trust Epoch | structured local result and timestamps | verifier/epoch authority; signed statements, audiences, expiry and event-driven invalidation |
| Capability Authority / protected operations | admission boundary and scoped client | capability issuer plus server enforcement; operation/resource binding, revocation and retained receipt |
| Restoration after invalidation | explicit failed decisions and fresh collection API | lifecycle controller; a fresh appraisal must create a new epoch/capability; current demo does not implement RESTORE |
| TPM/OpenHCL unwrap/unseal | authenticated AK/report context | guest/key manager; measured policy, sealed key custody, capability-aware release |
| Guix reproduction | source/lock/config/artifact identifiers | build system and reference enrollment; bit-identical audited builds and measurement correspondence |
| OPNsense integration | stable appraisal reason codes and evidence API | network policy controller; enforcement and attester-to-flow identity |
| GA4GH TES/WES/SDK integration | ServiceInfo advertisement and origin-scoped Rust/Python API | relying-party SDK/service adapters; workload identity, user consent and operation admission |
| SOC/GRC integration | redacted result schema, evidence digests and run records | audit adapters and retention policy; identity, access controls and external evidence review |

RFC 9261 is a standard; the remote-attestation SEAT integration remains draft work. No IETF consensus on a completed attestation profile or existing local BoringSSL integration is implied. A JSON declaration and certificate hash provide no TLS exporter context.

First prerequisites for stronger operational assurance: review AMD revocation/advisory handling and current minimum TCB policy; validate/enroll application/configuration measurements; define TLS key custody and post-appraisal invalidation. These changes must produce their own evidence and tests before stronger claims are made.
