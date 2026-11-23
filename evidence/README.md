# Evidence

This workspace contains the shared, versioned evidence contract used by the
Confido verifier and the native Attestor collector. It is organized for a later
move to a standalone `evidence` repository without separating the two crates.

| Crate | Responsibility |
| --- | --- |
| [`evidence-protocol`](protocol/README.md) | Wire-v1 request and response types, profile/version envelope, and quote-binding transcript. |
| [`evidence-core`](core/README.md) | Bounded SNP/HCL/vTPM parsing and collected-snapshot consistency checks. |

The core depends on the protocol. Both consumers must use compatible versions
of the two crates. The collector checks a snapshot before sending it; the
verifier independently appraises received evidence against its own trust
anchors, policy, and reference values. This workspace does not own device
collection, HTTP transport, endorsement retrieval, policy, or application
admission.

Run `cargo test --locked --workspace` from this directory. The normal
dependency graph remains free of native TPM,
network, and application transport crates. Project licensing and adapted
Microsoft source attribution are in [`LICENSE`](LICENSE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
