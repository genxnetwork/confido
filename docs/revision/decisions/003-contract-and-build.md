# Decision 003: direct report endpoint, deployment and reproducibility

Public HTTPS 443 serves `POST /tee-report`, credentialless `HEAD /tee-report` and `/v1/...`. Port 80 redirects with 308. `/aTLS` is retired. Reports are never cached. Evidence and application backends listen on loopback.

The caller knows the report path and expected profile from local configuration. The report has its own wire version, and unsupported versions fail closed. The 32-byte nonce is sent in a JSON POST body; the response carries evidence and the quote-bound certificate. A successful 204 HEAD response over certificate-pinned TLS confirms the intended HTTPS peer before credentials are read.

The Nginx TLS terminator currently owns the application TLS key. A future connection binder must run there or receive a securely associated connection context. A JSON report cannot recover the client's TLS exporter. RFC 9261 Exported Authenticators are standardized; the SEAT attestation profile is draft work, and BoringSSL integration is a future implementation target. See [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261.html) and [SEAT documents](https://datatracker.ietf.org/wg/seat/documents/).

Freeze Rust/Cargo, dependency locks, wheel and Python dependency hashes, image digests and configuration identifiers. Build a local wheel into the chat image rather than installing an older published version. Test isolated listeners before any deployment promotion. This revision does not authorize publication or relicensing. The repository and package metadata declare Apache-2.0; review third-party notices and release artifacts before publication.
