# Decision 001: bounded Azure SNP/HCL appraisal

Status: historical initial Milan scope. [Decision 004](004-amd-product-selection.md)
extends the current profile to Genoa and SNP report version 5. Current tests
and observations are tracked in the [coverage matrix](../coverage.md).

## Scope

The initial `azure-snp-vtpm-ima/1` scope supports Milan VCEK-backed SNP
reports (versions 2 and 3), Azure HCL SHA-256 variable data containing the
vTPM attestation key, an RSA/SHA-256 TPM quote, contiguous signed PCR
selection, and an exact enrolled IMA reference. Report version 3 retains the
fields used here; later or reserved fields are not appraised. Decision 004
records the subsequent Genoa and SNP-v5 extension. VLEK, TDX and GPU
appraisal remain unsupported.

The verifier pins AMD's Milan ARK certificate digest, verifies the endorsement
chain and validity at an independently supplied evaluation time, checks VCEK
chip/TCB/product extensions, and verifies the SNP signature and
committed/reported TCB equality. It denies debugging and migration and enforces
an enrolled launch measurement and component-wise minimum TCB. The initial
minimum is the observed enrollment baseline, **not** a vendor declaration of
vulnerability remediation. Revocation checking and automated
security-advisory policy updates remain limitations. Enrollment remains an
operator trust decision.

AMD documentation: [VCEK/KDS specification, publication 57230](https://docs.amd.com/v/u/en-US/57230)
and [SNP firmware ABI](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).
Root enrollment uses the [AMD Milan KDS chain](https://kdsintf.amd.com/vcek/v1/Milan/cert_chain)
over authenticated HTTPS and records its certificate digest. The attester
does not choose the root or policy.

## Bindings and freshness

The v1 quote transcript is
`SHA256(nonce[32] || certificate_DER || SHA256(serde_json(IMA entries)))`.
The IMA serializer's field order is fixed by the Rust struct and checked by a
shared vector. A changed transcript requires a new wire version. The quote
responds to the challenge; the SNP/HCL report retrieved from the vTPM need
not be regenerated.

The SNP report authenticates HCL variable data, which contains the vTPM AK.
That key verifies the quote. The quote authenticates PCR values and the
transcript containing the challenge, certificate DER and IMA log digest.
Certificate-bound evidence authenticates no particular TLS connection. TLS
key custody and cooperation of the guest collector/TLS terminator remain
assumptions; relay/diversion and subsequent state changes are not ruled out.

## Actual coverage and topology

The enrolled demonstration log has a boot aggregate and kernel modules.
Application code, configuration, model files, prompts and GPU state are not
covered by that log. `llama-default` forwards to Azure-hosted inference
outside the appraised VM.

The two DNS names/IPs route to one VM, TLS terminator and application workload,
with separate metadata identities and deliberately different enrolled
references. Both use the same appraisal algorithm; the negative reference is
intentionally incompatible.

Admission is a cooperating client's decision to withhold credentials and
application traffic. The server does not enforce a signed capability.
Appraisal is a point-in-time decision.
