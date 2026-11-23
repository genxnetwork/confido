# Claim → code → test matrix

The [latest local review run](acceptance-genoa-review-20261124.md) rechecked
fresh Genoa match/mismatch, container, 27-case replay and browser parity with
the published Evidence dependency. Earlier [direct-endpoint](acceptance-genoa-direct-20261123.md)
and [shared-core](acceptance-shared-core-genoa-20261123.md) records identify
their own source and artifacts.
It tested an isolated local route and synthetic downstream responder, not public
deployment or external inference.

| Claim | Code / artifact | Retained test evidence | Status |
|---|---|---|---|
| Pinned AMD root, endorsement signatures/validity and VCEK chip/TCB/product correspondence | `lib/src/{crypto,verify}.rs`, `evidence-core::formats` | Rust tests, 27 replay cases and fresh Genoa evidence | implemented for Milan/Genoa; revocation is not automatic |
| SNP signature, HCL variable-data binding and recovered vTPM AK | `lib/src/{crypto,verify}.rs`, `evidence-core::formats` | signed-report and HCL-key mutations; live Genoa run | implemented and tested |
| Debug/migration/VMPL, launch measurement and minimum TCB policy | `lib/src/verify.rs`; application-owned `profiles/*.json` | policy mutations in replay and live Genoa enrollment | implemented and tested for enrolled baseline |
| Signed quote, nonce/certificate/log binding and PCR mapping | `evidence-protocol`, `evidence-core::formats` | signed fixture vectors, challenge/quote/PCR mutations and fresh TPM quote | implemented and tested |
| Exact IMA reference, boot aggregate and PCR 10 | `lib/src/{reference,verify}.rs` | Rust tests, replay mutations and fresh match/mismatch | implemented for 45 enrolled boot/module entries |
| Immutable reference content and locally selected identity | `lib/src/verify.rs`; application `demo/collection.py`, `scripts/enroll_reference.py` | commit/path/digest pinning, publisher verification and live Teraveri retrieval | implemented for approved local policy |
| Typed evidence result and historical replay | `lib/src/result.rs`, `bindings/{python,wasm}/`, `client/`, result/archive schemas | Python API tests, 27 replay cases, seven-case CLI/Python/Chromium/Firefox parity | implemented; no admission claim in result |
| Origin-scoped HTTPS and intended hostname | application `native_transport/`, `demo/admission.py` | transport tests and live shared-certificate/wrong-host rejection | implemented in cooperating native application |
| Withhold credentials and application traffic until admission | application `demo/`, `confai-promter.py` | 40 application tests; live match sent one synthetic request, mismatch sent zero | implemented in cooperating native application |
| Direct challenge-bound report endpoint | `server/src/main.rs`, `client/src/main.rs`; application `demo/collection.py`; extension | POST nonce/no-store and credentialless HEAD; fresh Genoa run | implemented and locally accepted |
| Bounded collection and retrieval | `server/src/main.rs`; application `demo/collection.py` | 7 server tests, 7 launcher tests, application retry/size tests | implemented; adversarial live IMA race not injected |
| Python, CLI and browser verifier parity | `bindings/`, `extension/`, `scripts/browser_checks.py` | seven current-hardware cases per runtime; installed Chromium MV3/CSP/asset checks | implemented; Safari runtime not accepted |
| Local appraisal under provisional 3-second target | installed Python wheel with local inputs | 30 Genoa replays, p95 2.85 ms in the latest local run; network excluded | target met for this local workload only |
| Frozen container on the direct endpoint | application Docker build and runtime manifest | current Genoa match/mismatch in both installed wheel and rebuilt local image; image digest in acceptance record | implemented and locally accepted |
| Public 0.2.0 deployment promotion | application-owned `deploy/genxt-demo/` and preflight | current run used isolated localhost listeners | pending public configuration review and promotion |
| TLS session binding / relay resistance | no binder | none | unsupported |
| Full application/model/GPU measurement or external inference validation | current IMA log lacks this coverage | enrolled log: one boot aggregate + 44 kernel modules; downstream synthetic | unsupported |
| Server-enforced capabilities / continuous trust epochs / restoration | roadmap | none | planned |
| Independent evaluator reproduction | rerun checklist | non-implementer identity/sign-off pending | planned |

## Remaining decisions and assumptions

- Repository and package metadata declare Apache-2.0; third-party attribution
  and release artifacts still need final review before publication. The local
  attribution archives passed, but RPM construction was not run on this VM.
- AMD revocation and security-advisory updates are not automatic. The minimum
  TCB and launch measurement are operator-enrolled baselines.
- Guest collector behavior, TLS key custody, enrollment integrity and
  post-appraisal changes remain assumptions. A fresh quote does not prove a
  newly generated SNP report.
- The public demonstration's external inference is outside the measured
  boundary; admission is enforced by a cooperating client.
