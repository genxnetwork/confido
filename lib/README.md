# confido 0.4 — pure evidence verifier

`verify(VerificationInput, policy_bytes, VerificationContext)` synchronously
validates supplied evidence. No HTTP, TPM, TLS session, files, clock lookup,
random challenge generation or application admission is performed here.

Python packaging moved to `../bindings/python` (`confido_verifier`). WASM packaging
is in `../bindings/wasm`. `make wheel`/`make install` forward to the Python package.
Legacy connection APIs were removed; see [migration](../docs/migration-0.4.md).

A `verified` result concerns evidence only. The caller must separately authenticate
its actual TLS peer and decide whether to send credentials or application requests.
The fixed Milan SNP/HCL/vTPM profile and its coverage limits are described in the
[repository README](../README.md).
