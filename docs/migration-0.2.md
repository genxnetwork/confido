# Migrating to Confido 0.2

The earlier branches used provisional 0.3/0.4 numbers; this consolidated JAN
revision targets 0.2.0. Historical reports and deployed artifacts retain their
original identifiers. Those numbers do not describe a released upgrade path.

This is a breaking API change from the original attested-client interface. Wire profile `azure-snp-vtpm-ima/1` and the quote
transcript stay at v1. Result, policy and archive schemas are now v2.

| Earlier development API | Confido 0.2 owner/API |
|---|---|
| `confido-atls`, `import confido` | `confido-verifier`, `import confido_verifier` |
| `discover_py` | Caller HTTP and discovery validation |
| `connect_py`, `AttestedSession` | Removed; caller collection → verify → transport → admission |
| `appraise_offline_py` | Caller decodes archive, supplies nonce/time to `verify` |
| legacy `aTLS_connect_py` | Removed |
| `AppraisalConfig` with origin | Separate local verifier and application policies |
| `application_admitted` in result | Separate application-decision-v2 record |
| `timings_ms`, live/fresh/session claims | Caller measurements/context only |

The demo's `confidential-ai-example/profiles/{match,mismatch}.json` point to
neighboring `verifier-*.json` files.
Root, launch/TCB enrollments and immutable reference bytes/digests are preserved.
A schema-valid policy still undergoes semantic/path validation in Rust.

Core arguments: exact report JSON bytes, ASK+ARK PEM bytes, VCEK DER, exact
reference bytes, local policy bytes, independently held 32-byte expected nonce,
and explicit Unix evaluation time. Python returns a dict. WASM returns JSON;
DER artifacts use base64 consistently across wrappers. No timestamps are read
from input as an assertion of current freshness.

Live callers create their own unpredictable challenge and enforce a deadline.
Historical replay can reuse an archived challenge, but must label the operation
historical. Stored result JSON is never a substitute for running the verifier.
Use `confido_client migrate-archive OLD NEW TIME` for extension-compatible v2 input;
legacy report reserialization changes its raw-byte fingerprint, not its v1 binding.

The native chat demo owns its `_confai_transport` wheel. It verifies exact peer
certificate, hostname and validity on each connection, confirms service metadata
without credentials, then reads chat credentials. The extension does not depend
on this native transport and does not provide application admission.

The transport package keeps its own version. When a downstream build invokes
maturin directly, first run `make -C bindings/python licenses` in Confido to
prepare the attribution files required by the verifier wheel. Confido's normal
`make -C bindings/python wheel` entry point performs that step automatically.

Packages retain individual Cargo locks/target paths to preserve collector scripts.
There is no root Cargo workspace in this implementation. Portable cryptography is
`ring` plus bounded parsers; clang builds its C backend into WASM. No OpenSSL/TPM
runtime is linked into the verifier. Native test fixtures may use vendored OpenSSL.

Roll out a matched set of verifier + app transport + caller code. Keep historical
0.3 artifacts separate. Production certificate provisioning/reloads and package
publication remain deployment actions; this source migration does not perform them.

## Verification pipeline revision 2

The successful `checks` sequence is:

```text
endorsements → snp_signature → vcek_correspondence → platform_policy
→ hcl_key → quote_signature → quote_binding → quoted_pcrs → reference
→ ima_reference → boot_aggregate → pcr10
```

The pinned AMD chain authenticates the VCEK used for the SNP signature. Reported/
committed TCB consistency and chip/TCB correspondence are evaluated afterward.
An inconsistent TCB gives `snp_tcb_inconsistent` at `vcek_correspondence`.
The included leaf certificate is parsed after the quote signature; an unsupported
CA still gives `ca_certificate_unsupported` at `certificate`.

`quote_binding` confirms one combined nonce/certificate/IMA transcript. All three
binding flags remain false until that check succeeds. `quoted_pcrs` authenticates
the supplied PCR banks and values separately. Quote failures retain the reason
`quote_binding_invalid`; use the actual stage to identify the failed dependency.
`ima_reference`, `boot_aggregate` and `pcr10` retain `measurement_mismatch` for
measurement failures. No later check is marked passed after an earlier failure.

`verified_artifacts` can contain the authenticated AK without a bound certificate.
Confirmed IMA coverage stays zero until all measurement stages pass. The optional
`coverage.pcr10_method` names the attempted method; the corresponding check tells
whether it passed. `enrolled_sha256` is a pinned PCR comparison,
`template_digest_replay` is template-digest replay.

Result/archive schema 2 and wire/binding v1 stay compatible. Legacy archives may
contain combined `quote`/`measurements` checks; render them as legacy or replay the
original inputs with independently selected nonce/time to obtain current checks.
The Python formatter never recomputes an IMA verdict.

### Matched runtimes

Python `confido_verifier.build_info()`, WASM `build_info()` (JSON string) and CLI
`confido_client --build-info` expose `pipeline_revision = 2` in core metadata.
Core source SHA-256 is target independent; each wrapper also records its own
source SHA-256, Rust toolchain, target, build profile, feature list and flags.
These fields are diagnostic metadata, not part of evidence claims or results.

Source fingerprints cover explicit source/manifests/locks/build scripts, including
uncommitted changes and additions. The chat app's `build/runtime.json` links those
fingerprints to wheel bytes and the loaded native binary. `make dev-chat` rebuilds
stale development artifacts and starts a fresh Python process. Direct invocation
checks the manifest before discovery and suggests `make dev-update` on mismatch.
Containers check their embedded manifest and caller/native bytes without a checkout.

Extension packaging emits `runtime-manifest.json`; the Worker checks bundled
assets and embedded core/wrapper identities before handling evidence. Rebuild the
extension after source changes. Safari packaging is not Safari runtime acceptance.
