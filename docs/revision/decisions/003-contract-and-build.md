# Decision 003: discovery, deployment and reproducibility

Public HTTPS 443 serves `GET /service-info`, `POST /tee-report` and `/v1/...`. Port 80 redirects with 308. `/aTLS` is retired. Reports are never cached. Evidence, sidecar and metrics backends listen on loopback. The TEE advertisement is a custom GA4GH extension, not a standard GA4GH TEE endpoint.

The 0.3.0 advertisement explicitly declares `profile: azure-snp-vtpm-ima/1`, `wireVersion: 1`, the existing nonce/request/response shape and `sessionBinding.supported: false`. A missing/unknown version fails closed in the new API. Old clients may ignore the additive fields. New clients require upgrading the sidecar; they must not silently fall back to the legacy path.

The Nginx TLS terminator currently owns the application TLS key. A future connection binder must run there or receive a securely associated connection context. An HTTP sidecar cannot recover a client's TLS exporter from a JSON field. RFC 9261 Exported Authenticators are standardized; the SEAT attestation profile is draft work, and BoringSSL integration is a future implementation target. See [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261.html) and [SEAT documents](https://datatracker.ietf.org/wg/seat/documents/).

Freeze Rust/Cargo, dependency locks, wheel and Python dependency hashes, image digests and configuration identifiers. Build a local wheel into the chat image rather than installing an older published version. Test isolated listeners before any deployment promotion. This revision does not authorize publication or relicensing. Confido's owner must choose licence metadata before an open release; inherited upstream notices must remain.
