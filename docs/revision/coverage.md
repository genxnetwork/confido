# Claim → code → test matrix

Observed implementation run: **2026-09-23**. See [results](results.md) and the [machine-readable run record](run-20260923.json). “Tested” refers to this bounded revision; it does not imply independent review or public deployment promotion.

| Claim | Code / artifact | Retained test evidence | Status |
|---|---|---|---|
| Pinned AMD root, endorsement signatures/validity and VCEK chip/TCB/product correspondence | `lib/src/profile.rs`, `appraisal.rs` | real hardware acceptance; root/chip/date mutations in `replay-checks.json` | implemented and tested |
| SNP signature, HCL variable-data binding and recovered vTPM AK | `evidence.rs`, `profile.rs` | SNP-signature/HCL-AK substitutions; genuine fresh collection | implemented and tested |
| Explicit debug/migration/VMPL, launch measurement and minimum TCB policy | `profile.rs`, `confidential-ai-example/profiles/*.json` | direct policy vectors; valid hardware evidence rejected under incompatible launch/TCB policy | implemented and tested |
| Signed quote, nonce/certificate/log binding, PCR bank/selection | `quote.rs`, `nonce.rs`, `vtpm.rs` | RSA-signed fixture mutations, independent transcript vector, live quote, hardware replay mutations | implemented and tested |
| Exact IMA reference, boot aggregate and PCR 10 | `trs.rs`, `evidence.rs` | replay/enrolled-PCR tests; match and deliberate mismatch through the same verifier | implemented and tested |
| Immutable reference identity and content | `appraisal.rs` | commit/path/digest pinning; reference/origin substitution rejection | implemented and tested |
| Typed stages and offline historical replay | `appraisal.rs`, `pylib.rs`, result schema | 21 replay cases; seven observed result records schema-validated; offline admission always false | implemented and tested |
| Origin-scoped HTTPS, intended hostname and unchanged critical metadata | `AppraisedClient`, `AttestedSession` | shared-certificate cross-origin rejection, wrong hostname, changed identity, redirect/downgrade tests | implemented and tested |
| Withhold application credentials/traffic before required checks | chat client and Rust transport | 12 installed-wheel tests, 5 chat tests, actual staged counters: 18 discovery/report requests with zero application credentials | implemented and tested |
| Versioned GA4GH discovery and report contract | sidecar handler/schema; report server | Go tests; both observed advertisements validated against frozen GA4GH v1 + extension; negative schema cases | implemented and tested |
| Bounded HTTP/KDS/TPM resource use | `kds.rs`, report handler | oversized input, KDS retry limit, busy collector and malformed nonce tests; isolated hardware collection | implemented and tested |
| Consistent quote/PCR/log snapshots with three attempts | `gather_evidence`, `verify_quote_snapshot` | real stable snapshots and rejected cryptographic mutations; retry logic reviewed; no adversarial live IMA mutation injected | implemented but live race injection not demonstrated |
| Frozen installed wheel/container match and mismatch | local wheel, hashed requirements, saved OCI image | actual SDK request through each accepted path; zero application requests for both mismatch paths | implemented and tested |
| Local appraisal p95 below provisional 3-second target | release wheel with all inputs local | 30 repeated hardware-bundle appraisals; observed p95 2.32 ms; collection/KDS timing recorded separately | implemented and tested for this workload |
| Public 0.3.0 deployment promotion | aligned templates and preflight | running configuration/binary hashes still match checkpoint | planned; staged revision only |
| TLS session binding / relay resistance | no binder | none | unsupported |
| Full application/model/GPU measurement or external inference validation | current IMA log lacks this coverage | enrolled log: 1 boot aggregate + 46 kernel modules; test downstream explicitly synthetic | unsupported |
| Server-enforced capabilities / continuous trust epochs / restoration | roadmap | none | planned |
| Independent evaluator reproduction | rerun checklist | non-implementer identity/sign-off pending | planned |

## Remaining decisions and assumptions

- Confido licence metadata remains an owner decision before an open release; upstream notices are preserved.
- AMD revocation and security-advisory updates are not automatic. The minimum TCB and launch measurement are operator-enrolled baselines.
- Guest collector behavior, TLS key custody, enrollment integrity and post-appraisal changes remain assumptions. A fresh quote does not prove a newly generated SNP report.
- The public demonstration's external inference is outside the measured boundary; admission is enforced by a cooperating client.
