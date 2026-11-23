# Confido JSON contracts

This directory contains JSON Schema Draft 2020-12 descriptions of the Confido
0.2 caller and verifier records. The schemas describe serialized shapes; the
portable verifier still performs its own bounded parsing, cryptographic checks,
policy checks, and exact-byte comparisons.

| Schema | Record and owner |
| --- | --- |
| [application-policy-v2.json](application-policy-v2.json) | Caller-selected HTTPS origin and a path to a verifier policy. The demo application owns this choice. |
| [verifier-policy-v2.json](verifier-policy-v2.json) | Caller-approved AMD platform constraints and an immutable reference pin. Confido consumes these policy bytes; a registry response cannot select trust anchors. |
| [verification-input-v2.json](verification-input-v2.json) | Optional serialized envelope for the evidence bytes, policy bytes, expected nonce, and evaluation time supplied to verification. The Rust and Python APIs also accept these arguments directly. |
| [verification-result-v2.json](verification-result-v2.json) | Evidence-only verdict, ordered checks, confirmed claims, bindings, and coverage. It does not grant application access or authenticate the observed TLS peer. |
| [verification-archive-v2.json](verification-archive-v2.json) | Caller-held evidence inputs and context, with an optional saved result. A saved result is historical data; replay must run the verifier again. |
| [application-decision-v2.json](application-decision-v2.json) | Separate caller/application admission decision after evidence verification and the application's transport and identity checks. Confido does not issue it. |

The two application schemas live here to document the shared caller/verifier
boundary; their decisions remain application-owned. The cooperating demo keeps
its actual policy files in `confidential-ai-example/profiles/`.

## Version and trust boundaries

Confido's current package version is **0.2.0**. These records use
`schema_version: 2`; the supported evidence profile is
`azure-snp-vtpm-ima/1`, with wire/binding version **1** and verifier pipeline
revision **2**. Those numbers describe different contracts and need not move
together. The demo's native transport package also targets **0.2.0**.
See the [0.2 migration guide](../docs/migration-0.2.md) for the API transition.

The verifier receives exact report, AMD chain, VCEK, reference, and policy
bytes. Base64 in an input or archive is only a JSON representation of those
bytes. The caller supplies the expected nonce and evaluation time; a live caller
also owns challenge generation, deadlines, and reuse prevention. An archive
does not recreate a live session. Reference publication and publisher approval
are separate from evidence verification.

JSON Schema keywords such as `description`, `format`, and `contentEncoding`
help document data but do not by themselves establish HTTPS validity, decode
and appraise evidence, verify a publisher, or enforce application admission.
Consumers must use the relevant runtime checks. Keep raw archives private:
they contain full evidence and may expose hardware or deployment identifiers.

The archive embeds a copy of the result schema so it remains independently
validatable. Changes to [verification-result-v2.json](verification-result-v2.json)
must be reviewed against the `verification` property in
[verification-archive-v2.json](verification-archive-v2.json).
