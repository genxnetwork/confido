# Claim → code → test matrix

This file records implementation status; completion evidence is added after execution. Baseline identity and deployed/source distinctions are in `checkpoint.json`.

| Claim | Code / artifact | Test evidence | Initial status |
|---|---|---|---|
| SNP → HCL AK → signed quote | `lib/src/evidence.rs`, `quote.rs`, `vtpm.rs` | existing quote substitution fixtures; hardware appraisal pending | implemented but not yet demonstrated in revised API |
| Signed PCR bank/selection, nonce/cert/log binding | `quote.rs`, `nonce.rs` | existing negative cryptographic fixtures | implemented and tested in baseline |
| Exact IMA/reference, boot aggregate, PCR 10 | `evidence.rs`, `trs.rs` | existing TRS/IMA tests; frozen reference pair | implemented and tested in baseline |
| Independent AMD root/platform policy | planned `profile.rs` | positive/negative vectors pending | planned |
| Immutable reference identity/content | planned `appraisal.rs` | digest/identity substitution pending | planned |
| Typed stage results and offline replay | planned `appraisal.rs` | replay and status tests pending | planned |
| Origin-scoped authenticated admission | planned live client / Python transport | hostname/redirect/metadata/zero-credential tests pending | planned |
| Consistent collection, bounded resource use | server / KDS | snapshot and request limit tests pending | planned |
| Current wheel/container match and mismatch | frozen demo package | isolated hardware runs pending | planned |
| TLS session binding / relay resistance | no binder | none | unsupported |
| Full application/model/GPU measurement | current IMA log lacks these entries | enrollment observation: 1 boot aggregate + 46 modules | unsupported |
| Server-enforced capabilities / continuous trust epochs | roadmap only | none | planned |
| Independent evaluator reproduction | rerun checklist | non-implementer sign-off pending | planned |

Priority: first fail-closed trust/policy boundaries; then collection/transport/resource controls; then reproducible packaging and retained demonstration evidence. No observed outcome should be inferred from a planned test.
