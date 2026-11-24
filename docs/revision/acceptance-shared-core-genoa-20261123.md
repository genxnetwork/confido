# Shared evidence core: isolated Genoa validation, 2026-11-23

This run validated the extraction of `evidence-core/` from the Confido verifier.
The collector was rebuilt from this revision and depends on `protocol/` and
`evidence-core/`, without the full `confido` verifier crate. The verifier and
the application's native transport wheels were rebuilt and installed together;
application preflight passed. The clean `confidential-ai-example` checkout was
`1f950d06cc0dabfa0f7981d1004fd6090d73359c`. The host kernel was
`6.8.0-1071-azure-fde`.

The Confido core source fingerprint embedded in the verifier wheel was
`cb336edf42dafe028da882c029383aefb357732b26efc6cb25bd6f8f8a4b3466`.
The rebuilt collector binary SHA-256 was
`8f2c68e95aae9ad53e5165cb0d6ef3d031f1bbed5e9beb5c6fa7455b9b40d0bb`;
the installed verifier and application transport binary SHA-256 values were
`54ce626d5522c2fdc53fcc0d75b6c77e4c0f7a5d09272ba65f39888402febf8b`
and `de5b07011afad7b1799f450eae7aa432174149377ca7021dd8fa3065e76d1d7d`.
The stage used the unchanged positive and negative Genoa policy hashes
`7d3cf06255a691ecec351bfbeaa147317eb2de272a96969d437b051e8aceb3c1`
and `2933581a0995279e872e78b2bb2e06eb6365777e13aa256905364f5d7920453e`.

| Isolated check | Observed result |
|---|---|
| Match | Verified and admitted one synthetic application request |
| Mismatched reference | Rejected with zero application requests |
| Shared certificate at another origin | Three targets rejected before application traffic |
| Wrong TLS hostname | Rejected before application traffic |
| Report collection | Six `/tee-report` requests, none bearing application credentials |

The stage ran from `2026-11-23T20:50:57.658982+00:00` to
`2026-11-23T20:51:01.207474+00:00`. The private `acceptance.json` SHA-256 is
`dcd754e8e7de786764e1d0295e316667b04736cbd5c993289b39e4d700885d65`.
The positive archive then passed 27 hardware-evidence replay cases; 30 local
appraisals had p95 `3.926 ms` with all inputs already local. The private replay
record SHA-256 is
`9332fede28d0f08cfef99064c767fcf1755d389191bdbd5febffc9b89681b033`.
Raw archives and logs remain outside the repository.

Locked Rust tests passed for the evidence core, verifier and collector; the CLI,
Python and WASM bindings compiled. Seven installed-wheel API tests and seven
collector launcher tests passed. This is a local, synthetic downstream run;
the container was not rebuilt for this extraction, and external inference,
public deployment and independent reproduction were not evaluated.
