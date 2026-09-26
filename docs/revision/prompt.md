# Confido evidence and appraisal revision prompt

Use this as the implementation brief for the next Confido revision. The immediate scope, future integration points and completion criteria are defined below.

---

Revise Confido as a reusable reference implementation for execution-environment evidence verification and reference appraisal. Deliver a reliable, technically precise and reproducible implementation with a clear demonstration of matching admission and reference-mismatch rejection.

## 1. Read the evidence and establish the baseline

Review the complete current trees:

- `/mnt/confido`: Rust library, evidence server, Rust CLI, Python binding, tests, packaging, CI and deployment.
- `/mnt/confidential-ai-example`: relying-party chat demonstrator.
- `/mnt/ga4gh_service_info_sidecar_gsoc_2026`: GA4GH metadata and the custom evidence advertisement.
- `/mnt/flint`: application gateway and Nginx integration.

Start with the accompanying [review](review.md), but recheck time-sensitive observations. Preserve all existing user work and record repository revisions and dirty-tree state before editing.

Create local baseline checkpoints on `checkpoint/pre-revision-20260923` in each repository. Commit reviewed source, documentation and deployment templates while excluding credentials, private keys, secret environment files and generated build artifacts. Initialize Flint as a local repository if it is still unversioned. Record all checkpoint SHAs, dependency locks and deployed image/configuration identifiers in a shared manifest. Then create `revision/attestation-update` from each baseline and implement in small, reviewable commits. Preserve these planning documents under `docs/revision/`.

Use the technical scope and completion criteria in this brief to guide the work. Branch names, commit messages, documentation and demonstration copy should describe the software changes and their technical purpose.

Create a claim-to-code-to-test matrix. Label each claim as implemented and tested, implemented but not yet demonstrated, unsupported, or planned. Keep observations, hypotheses and recommendations distinct.

## 2. Matter, scope and goals

**Matter:** remote evidence about an execution environment, its cryptographic authentication, comparison with verifier-approved reference state, and the application client's resulting decision to submit or withhold a request.

**Immediate scope:** a bounded Azure SEV-SNP/HCL/vTPM/IMA profile, the Rust/Python interfaces, report discovery, reference selection, deployable packaging and the two-case chat demonstration.

**Goals:**

1. Make every displayed security statement traceable to a check and a declared assumption.
2. Make matching and mismatching outcomes reproducible using the same verification path.
3. Withhold application credentials and prompts until required appraisal and HTTPS peer authentication succeed.
4. Produce an evidence package that an independent evaluator can inspect and rerun.
5. Expose clean boundaries for later transport, reference-governance and capability-control work.

The current demo exercises client-side admission/withholding at a point in time. The longer-term architecture connects Reference State → Evidence → Appraisal → signed Validated Trust Epoch → Capability Authority → protected operation → retained receipt/result, with invalidation and fresh restoration. Limit this revision to the immediate scope above; document interfaces for later lifecycle work.

Keep post-handshake BoringSSL connection binding/re-attestation, signed governed reference updates, Epoch/Capability Authority, TPM/OpenHCL unwrap/unseal, Guix reproduction, OPNsense, TES/WES and SOC/GRC integrations in an explicit future-work map unless separately authorized. Identify the interfaces Confido will supply and the owning component for each future function.

## 3. Correct the assurance boundary first

Verify and document:

- The source and authentication of the AMD root, ASK and VCEK; SNP signature verification; HCL variable-data binding; recovery of the vTPM attestation key; quote signature, nonce and signed PCR selection; boot aggregate and PCR 10/IMA checks.
- The certificate/log/challenge binding transcript and its serialization. Add versioning and domain separation only through an explicit compatible migration with shared vectors.
- Which object is fresh: a quote generated for this challenge must not be described as proof that the hardware SNP report was regenerated.
- Which files/configuration/models are measured and which are merely declared. The reviewed live log contained only the boot aggregate and kernel modules.
- Where inference executes. The reviewed `llama-default` path forwarded to Azure-hosted inference, outside this VM's attestation boundary.
- What enforces withholding. A cooperating client declining to submit a request is distinct from server-side capability enforcement.
- The negative path: use the same verification code against an intentionally incompatible trusted reference. Present this as a two-endpoint match/mismatch test. Retain accurate deployment topology in the technical architecture documentation; omit topology details from the routine console flow and main demonstration narrative.
- TLS key custody, trusted guest components and residual relay/diversion or post-appraisal state-change assumptions.

Remove unsupported entire-stack, GPU, model-execution, memory-isolation-policy and CPU-only-trust-anchor claims. A valid signature alone is insufficient to establish all those properties. GPU evidence is unverified/unsupported unless a real verifier and tests are added under a separate scope.

## 4. Revise the architecture and interfaces

Organize the code around explicit stages: discovery, collection, cryptographic verification, policy/reference appraisal, HTTPS peer authentication, and application admission.

Introduce a typed appraisal result available to Rust and Python. Include overall status; individual checks and stable reason codes; supported profile/version; evidence digest; challenge context; certificate fingerprint; vTPM key fingerprint; reference source/revision/digest; measured coverage; binding properties; timing and limitations. Represent invalid evidence, policy mismatch, unsupported profile and unavailable dependencies distinctly.

Do not collapse all failures into “TEE failed.” A valid platform/quote with a reference mismatch should show the stages actually completed.

Provide a safe origin-scoped HTTPS integration so callers cannot accidentally substitute ordinary roots, follow redirects, downgrade to HTTP, or reuse an appraisal for a different service/reference merely because its certificate is shared. Preserve existing public entry points through documented compatibility wrappers where feasible.

Separate network retrieval from pure verification/appraisal so frozen evidence and references can be replayed offline. An offline recorded decision is historical evidence, not a fresh authorization for chat.

Minimize unnecessary native/Python/WASM dependencies and clarify supported platforms. Keep the component split proportionate; avoid a broad framework rewrite.

## 5. Make reference and platform policy explicit

Replace implicit mutable registry selection in the demonstration path with a verifier-controlled reference identity, immutable revision and checked content digest. Show the exact reference locator in output and evidence records. Preserve legacy IP lookup only as an explicit documented compatibility mode. Do not trust a registry chosen by unauthenticated ServiceInfo.

For the initial frozen demo, use immutable references. Document signed promotion, expiry/rollback protection and continuous reference updates as future reference-governance work.

Define an explicit supported SNP profile and validate its assumptions against authoritative platform documentation. Assess AMD trust-anchor identity/distribution, endorsement validity and relevant extensions, chip/TCB correspondence, supported product family, minimum TCB, guest policy/debug/migration conditions and launch-measurement policy. Implement the checks required by the declared profile with independent positive/negative vectors; mark unresolved requirements visibly and withhold an unsupported high-assurance claim.

Preserve signed PCR-bank/selection validation, exact IMA comparison and the existing SHA-256 PCR 10 enrollment case. Explain replay versus enrolled-value comparison and reject inconsistent/uncovered inputs. Bound collection/read races with a documented fail-safe snapshot/retry strategy; never relax a mismatch simply to make the demo pass.

## 6. Keep one consistent public contract

Both names use HTTPS 443:

- `GET /service-info`: GA4GH metadata with a documented custom `teeReport` advertisement.
- `POST /tee-report`: fresh 32-byte base64 nonce in a JSON body; report response with `Cache-Control: no-store`.
- `/v1/...`: the application route.

Port 80 redirects to HTTPS. Retired `/aTLS` stays retired. Backend and metrics listeners remain private.

Preserve separate service IDs and `type.group: network.genxt.demo`. Validate metadata against the pinned GA4GH schema plus the extension schema. Make the evidence profile/wire version and supported binding properties machine-readable; the client enforces its own requirements independently of the advertisement.

Keep `sessionBinding.supported: false` while no connection binder exists. A report resource path is an integration choice, not a GA4GH-mandated TEE endpoint. Reject cross-origin discovery, redirects, malformed encodings, unsupported versions and silent downgrade.

For future Exported Authenticators, identify the TLS terminator and how authenticators will relate to that actual connection. A sidecar behind ordinary HTTP proxying has no automatic access to the client's TLS exporter context. Document the required future transport boundary without pretending that a JSON field or certificate hash implements it.

## 7. Preserve the requested terminal UX

Use a readable sequence:

1. Print ServiceInfo, explicitly identifying its initial bootstrap authentication status.
2. Show report availability and the exact configured TRS/reference link.
3. Explain the current nonce/certificate binding and unsupported TLS session binding.
4. Prompt `Retrieve and appraise the report before chat? [Y/n]:`; Enter accepts, decline withholds chat.
5. Preserve the full attestation log output.
6. Present a compact stage summary, measured coverage and decision.
7. Re-fetch metadata using the appraised certificate and authenticate the intended HTTPS peer before application use. A changed preview must not silently change trusted policy or service identity.
8. On acceptance, show where the prompt will be processed and open chat. On rejection or error, send no application request or credential.

Explain that the vTPM key comes from HCL metadata authenticated by the SNP report and verifies the quote. Describe the certificate binding through that quote. Prefer “The measured boot and IMA state matches the configured reference” when that is the implemented coverage.

Keep the acronym block after a blank line: TEE; TPM/vTPM and PCR together; IMA. Keep detailed logs readable and available in a saved run transcript, without secrets.

Use precise standards wording: RFC 9261 Exported Authenticators are standardized; remote attestation using them is ongoing SEAT draft work; the BoringSSL integration is an implementation target. Neither IETF consensus on that attestation profile nor a completed local implementation may be implied. Cite [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261.html) and [SEAT documents](https://datatracker.ietf.org/wg/seat/documents/).

## 8. Make the build and deployment reproducible

Repair the Docker path so it runs the current ServiceInfo protocol. Give incompatible protocol changes an unambiguous release/version. Freeze Cargo locks, toolchain, Python dependencies, wheel hash, base/application image digests and configuration hashes.

Consolidate systemd/Nginx examples: listener ports, required arguments, TLS certificate identity and paths, two sidecar configurations, loopback bindings and application routing must agree. Provide a preflight command that detects stale wheels, retired routes, wrong certificates and incompatible advertisements.

Bound HTTP sizes, timeouts, KDS retry/cache behaviour and expensive TPM collection concurrency. Keep parsing failures controlled. Move optional GPU collection out of the mandatory acceptance path and remove misleading GPU success text.

Move reusable application credentials out of source into an operator-controlled input. Never include secrets in bundles or logs.

Resolve the missing/ambiguous Confido licence metadata and proprietary RPM labels through an owner decision before claiming an open release. Preserve lawful upstream attribution and record which components are reused and which changes this revision introduces. Do not publish, relicense or alter live deployments merely to produce a reviewable revision.

## 9. Test the claims and retain evidence

Preserve existing meaningful tests. Add focused coverage for:

- Correct signature/AK/quote linkage and rejected substitutions.
- Nonce replay, changed certificate/log/PCR bank/selection, malformed and oversized data.
- Required platform-policy rejection and reference identity/digest mismatch.
- Unsupported discovery, origin/hostname mismatch, redirect/downgrade and service identity changes.
- Dependency failure, KDS limits and consistent evidence snapshots.
- Matching admission and mismatching withholding through the actual installed wheel/container path.
- Zero inference requests and zero application credentials emitted by the demo client before successful appraisal and HTTPS authentication.

Report cryptographic fixture tests separately from hardware-backed runs. Never present a mocked signature as hardware validation. Do not claim relay resistance, connection binding, continuous enforcement or RESTORE based on tests that do not exercise those properties.

Produce one run bundle with test IDs, UTC time, source/tree and image/wheel hashes, schema/profile versions, endpoint/reference identities, challenge/evidence/certificate identifiers, expected and observed results, stage timings, complete redacted logs and variance notes. Sensitive host evidence must be handled deliberately; exclude private keys, tokens and protected prompts.

Measure collection/network/KDS time separately from local appraisal. Use a provisional engineering target of p95 local appraisal within three seconds after all required evidence is locally available. Record the workload, hardware and sample count before evaluating that target; report measured results and remaining gaps.

Provide an independent rerun checklist and leave reviewer identity/sign-off pending until a non-implementer actually performs it. Do not fill attestation or reproduction evidence with invented results.

## 10. Deliverables and order

Deliver, in order:

1. Claim/coverage matrix, current architecture and prioritized findings.
2. A small set of documented decisions: assurance profile, reference pinning, API result, compatibility/versioning and deployment contract.
3. Reviewable implementation changes for the immediate scope.
4. Passing relevant tests, immutable demo build, preflight and reproducible run instructions.
5. A 10–12 minute technical walkthrough: measured coverage and checks → matching acceptance → reference mismatch rejection → retained evidence → future capabilities.
6. A local demonstration evidence record containing observed results and explicitly marked outstanding items.
7. A technical roadmap covering the future BoringSSL transport integration, bounded formal analysis, governed references and capability control, with component boundaries and dependencies.

Completion means another evaluator can build/run the frozen package, inspect why each decision occurred, understand precisely what evidence covers, and reproduce the recorded decision. Every claimed result must have a corresponding artifact or a stated remaining gap.

Begin with the baseline and risk-ranked plan, then implement the bounded revision. Ask for missing facts one at a time with suggested values only when they materially affect a decision; continue independent authorized work.
