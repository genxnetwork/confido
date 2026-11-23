# confido 0.2 — pure evidence verifier

`verify(VerificationInput, policy_bytes, VerificationContext)` synchronously
validates supplied evidence. No HTTP, TPM, TLS session, files, clock lookup,
random challenge generation or application admission is performed here.

Python packaging moved to `../bindings/python` (`confido_verifier`). WASM packaging
is in `../bindings/wasm`. `make wheel`/`make install` forward to the Python package.
Legacy connection APIs were removed; see [migration](../docs/migration-0.2.md).

A `verified` result concerns evidence only. The caller must separately authenticate
its actual TLS peer and decide whether to send credentials or application requests.
The bounded Milan/Genoa SNP/HCL/vTPM profile and its coverage limits are described in the
[repository README](../README.md).

The decoder accepts SNP report versions 2, 3 and 5. Version 5 preserves the
SNP field offsets and signature boundary used here (AMD [ABI 1.58, table
23](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf)).
Mitigation vectors, SEV-TIO and page-swap policy are not appraised or claimed.
Other report versions and processor products remain rejected. Each supported
product requires its own locally enrolled AMD ARK digest, launch measurement,
TCB floor and IMA reference; a Milan enrollment cannot authorize Genoa.
