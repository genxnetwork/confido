# Decision 003: direct report endpoint, deployment and reproducibility

The reviewed deployment template routes public HTTPS 443 to
`POST /tee-report`, credentialless `HEAD /tee-report` and `/v1/...`. Port 80
redirects with 308; `/aTLS` is retired. Reports are never cached, and evidence
and application backends listen on loopback. The current acceptance used
isolated local ports; public promotion remains a separate deployment action.

The caller knows the report path and expected profile from local
configuration. The report has its own wire version, and unsupported versions
fail closed. The 32-byte nonce is sent in a JSON POST body; the response
carries evidence and the quote-bound certificate. A 204 HEAD response over
certificate-pinned TLS, with the expected hostname and validity, confirms the
intended HTTPS peer before credentials are read.

The Nginx TLS terminator owns the application TLS key in the reviewed
deployment. A future connection binder must run there or receive a securely
associated connection context. A JSON report cannot recover the client's TLS
exporter. RFC 9261 specifies Exported Authenticators as a Proposed Standard;
SEAT attestation integration remains Internet-Draft work as of 2026-11-23,
and BoringSSL integration is a future target. See
[RFC 9261](https://www.rfc-editor.org/rfc/rfc9261.html) and
[SEAT documents](https://datatracker.ietf.org/wg/seat/documents/).

Freeze Rust/Cargo, dependency locks, wheel and Python dependency hashes, image
digests and configuration identifiers. Build a local wheel into the chat image.
Test isolated listeners before any deployment promotion. The repository and
package metadata declare Apache-2.0; review third-party notices and release
artifacts before publication.
