# Decision 001: bounded Azure SNP/HCL appraisal

Status: accepted for implementation; tests and observations are tracked in the coverage matrix.

## Scope

Profile `azure-snp-vtpm-ima/1` supports Milan VCEK-backed SNP reports (versions 2 and 3), Azure HCL SHA-256 variable data containing the vTPM attestation key, an RSA/SHA-256 TPM quote, contiguous signed PCR selection, and an exact enrolled IMA reference. Report version 3 retains the fields used here; no interpretation of later/reserved fields is claimed. Other report versions, VLEK, TDX and GPU appraisal are unsupported.

The verifier pins AMD's Milan ARK certificate digest, verifies the endorsement chain and validity at an independently supplied evaluation time, checks VCEK chip/TCB/product extensions, verifies the SNP signature and committed/reported TCB equality, denies debugging and migration, and enforces an enrolled launch measurement and component-wise minimum TCB. The initial minimum is the observed enrollment baseline, **not** a vendor declaration of vulnerability remediation. Revocation checking and automated security-advisory policy updates remain limitations. Enrollment remains an operator trust decision.

AMD documentation: [VCEK/KDS specification, publication 57230](https://docs.amd.com/api/khub/documents/dWGhwYpo1Wv51rJN4d~47g/content), [SNP firmware ABI](https://docs.amd.com/api/khub/documents/x_tYkgJNtfpvqwPq45NrSQ/content). Root enrollment uses the [AMD Milan KDS chain](https://kdsintf.amd.com/vcek/v1/Milan/cert_chain) over ordinary authenticated HTTPS and records its certificate digest. The attester does not choose the root or policy.

## Bindings and freshness

Preserve wire transcript v1 unchanged: `SHA256(nonce[32] || certificate_DER || SHA256(serde_JSON(IMA entries)))` is the quote's extraData. The IMA serializer's field order is fixed by the Rust struct and covered by a shared vector. A future domain-separated transcript requires a new wire version. The quote is fresh for the challenge; the SNP/HCL report retrieved from the vTPM need not be regenerated.

The SNP report authenticates HCL variable data, which contains the vTPM AK. That key verifies the quote. The quote authenticates PCR values, the challenge, certificate digest input and IMA log digest input. Certificate-bound evidence authenticates no particular TLS connection. TLS key custody and cooperation of the guest collector/TLS terminator remain assumptions; relay/diversion and subsequent state changes are not ruled out.

## Actual coverage and topology

The enrolled demonstration log has a boot aggregate and kernel modules. Application code, configuration, model files, prompts and GPU state are not covered by that log. `llama-default` forwards to Azure-hosted inference outside the appraised VM.

The two DNS names/IPs route to one VM, TLS terminator and application workload, with separate metadata identities and deliberately different enrolled references. Both use the same appraisal algorithm; the negative reference is intentionally incompatible. This topology belongs in technical documentation, not the routine console walkthrough.

Admission is a cooperating client's decision to withhold credentials and application traffic. The server does not enforce a signed capability. Appraisal is a point-in-time decision.
