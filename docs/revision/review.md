# Confido technical revision review

Review date: 23 September 2026. This document records source/configuration observations and the technical revision plan.

## Recommendation

Position Confido as a reusable evidence verification and reference appraisal component for execution trust. Its immediate deliverable should be a reproducible demonstration of a relying-party client deciding whether to submit an application request after appraisal.

The next revision should make the security profile explicit, return structured appraisal results, repair the release/demo path and retain independently inspectable evidence. Continuous capability control belongs to a separate development stage.

## Sources and scope

Read the Rust library, attestation server, CLI, Python interface, test sources, manifests, build scripts, release workflows and deployment templates. Also reviewed the chat client and its Docker/development paths, the sidecar advertisement and schema, Flint routing/model configuration, the pinned Azure attestation dependency's certificate/report checks, and a read-only snapshot of live IMA coverage. All five relevant systemd services were active at inspection.

This was source/configuration review, with limited read-only live inspection. The test sources were inspected; their suites and the complete live inference flow were not rerun during this review. It is not an independent reproduction record.

Repository baselines, before the existing uncommitted changes:

- Confido: `622c4e6edf0de49aab2f8ec6464b4cc734faede5`.
- confidential-ai-example: `41b0d5e536e67a08d70f0aedd2e3255ea0c791cd`.
- GA4GH sidecar: `9f4236bacc04df5dfa3a5a5cd823b3bc0042db05`.
- Flint has no Git repository at its current workspace root.

These commit IDs alone do not reproduce the dirty working trees.

## Technical direction

The immediate revision should make one client's matching admission and reference-mismatch rejection reproducible, with exact source, image and reference identifiers, inspectable checks and retained run evidence.

The longer-term architecture connects Reference State → Evidence → Appraisal → signed Validated Trust Epoch → Capability Authority → protected operation → retained receipt/result evidence. Continued authority, invalidation and fresh restoration require additional implementation and tests.

Connection-bound post-handshake attestation, re-attestation, governed reference evolution and protected capability operations are future integration points. Define the relevant interfaces now while keeping their implementation outside this revision's immediate scope.

Formal-security work should specify selected properties, assumptions, adversarial traces and executable test oracles. Keep claims bounded to the analyzed properties and demonstrated behavior. Preserve upstream attribution and distinguish existing components from newly implemented changes.

## Checkpoint and branch plan

Use the same neutral branch names across the repositories:

- Baseline: `checkpoint/pre-revision-20260923`.
- Implementation: `revision/attestation-update`.

Checkpoint reviewed source, documentation and deployment templates locally before implementation. Initialize Flint as a local repository if it is still unversioned. Keep credentials, private keys, environment files containing secrets and generated build artifacts outside Git. Record all baseline SHAs, dependency locks and deployed image/configuration identifiers in a shared manifest. A code checkpoint must identify any separate deployment state needed for recovery.

Keep this review and the [revision prompt](prompt.md) under `docs/revision/`.

## Current evidence chain

The implemented verification path is:

1. Discover the custom report advertisement through `/service-info`.
2. Generate a random 32-byte challenge and POST it to `/tee-report`.
3. Validate the SNP report signature through the fetched AMD certificate chain.
4. Authenticate the HCL variable-data digest through SNP report data.
5. Recover the vTPM attestation public key from that authenticated HCL metadata.
6. Verify the vTPM quote signature, signed PCR selection/digest and challenge binding.
7. Compare the supplied IMA entries and boot aggregate/PCR 10 with the selected trusted reference.
8. Configure HTTPS trust using the returned certificate and proceed in the client.

The quote challenge binds `SHA256(nonce || certificate_DER || SHA256(serialized_IMA_entries))`. The certificate is bound through the quote, whose key is linked to the SNP report. A freshly generated quote is distinct from a freshly generated hardware SNP report.

The post-appraisal HTTP client disables ordinary public roots and rejects redirects/plain HTTP. The bootstrap client deliberately accepts the self-signed endpoint certificate; it must remain restricted to unauthenticated discovery/evidence.

Sources: [evidence.rs](/mnt/confido/lib/src/evidence.rs:62), [quote.rs](/mnt/confido/lib/src/quote.rs:12), [atls.rs](/mnt/confido/lib/src/atls.rs:85).

## Findings that should drive the revision

| Priority | Observation | Consequence / recommended revision |
|---|---|---|
| Before demo | Live IMA contained 47 entries: one boot aggregate and 46 kernel modules. No application, proxy, model or container paths appeared. Reading the live IMA policy was denied. | State precisely which measurements matched. Do not infer full workload coverage or enforcement policy from this log. Produce a measured/unmeasured coverage table. |
| Before demo | `llama-default` routes through Flint to an Azure-hosted inference endpoint. | The app demonstrates client gating before use of a gateway. This evidence does not attest the downstream model's execution or its prompt-processing boundary. |
| Before demo | Both public names share one VM, quote producer, workload and certificate; the negative reference is selected through the IP-based registry lookup. | Present a controlled reference-mismatch test using two endpoints. Keep deployment topology accurate in the architecture documentation; it does not need a console caption or a place in the main walkthrough. |
| Before demo | Chat admission is enforced by the cooperating client. Nginx's application authentication is separate. | Demonstrate that this client sends zero inference requests on rejection. Do not claim that Confido imposes a server-side capability gate or prevents a caller from bypassing this client. |
| Before demo | Docker installs the published `confido-atls==0.2.0`; the chat README records that it still uses retired `/aTLS`. Local development has newer code under the same version. | Build an immutable compatible wheel/image, record digests, give it an unambiguous version, and make the documented one-command path work. |
| Before demo | Chat README still claims verification of the entire software stack, GPU evidence and a CPU-only trust anchor. | Reconcile README, terminal output and diagram with implemented checks and actual deployment. GPU collection is not client verification. Trust also includes reference policy, AMD endorsements and their retrieval, and declared platform assumptions. |
| Security profile | TRS is a GitHub contents request without an immutable `ref`; selection uses a fresh DNS-to-IP resolution and localhost may use ipify. | Add explicit verifier-controlled reference identity, revision and content digest. Keep any legacy IP lookup explicit. The service must not choose the verifier's trust policy. |
| Security profile | Upstream certificate validation checks chain signatures; AMD roots are obtained over authenticated KDS HTTPS. The implementation does not independently pin the AMD root or apply a full X.509 validation policy. KDS product path is fixed to Milan. | Declare the supported platform and root distribution assumptions. Review root identity, endorsement validity/extension checks and product selection as explicit validation work. |
| Security profile | SNP validation verifies the signature and reported-versus-committed TCB equality; no explicit minimum TCB, guest debug/migration policy or launch-measurement acceptance policy is present. | Define and implement a bounded platform policy with authoritative test vectors. Never treat signature validity as complete platform acceptance. |
| Protocol | A fresh nonce/certificate/log binding exists; TLS connection binding and re-attestation do not. | Advertise unsupported session binding and describe the certificate linkage accurately. Preserve the future transport boundary. |
| API | Python returns certificate bytes, while the CLI reports an established connection after constructing a client. Failure strings combine multiple stages. | Return a structured appraisal result with stable reason codes, reference/evidence identifiers and a safe HTTP integration. Make CLI claims correspond to actual operations. |
| Reproducibility | Cargo locks are ignored; stable toolchains and floating container/dependency inputs are used. Flint is unversioned locally. | Freeze the complete demo dependency closure and configuration hashes. A source SHA alone is insufficient. |
| Deployment | Checked-in systemd samples use port 8080 while Nginx report templates use 8001; one sample omits required arguments. A Nginx sample lacks `ssl` on `listen 443`. | Consolidate tested deployment examples with certificate paths, sidecar instances and loopback backends. Existing working live configuration is not proof that repository templates work. |
| Maintainability | Python/TPM/unused WASM dependencies are mixed into one library; WASM source is unwired. TPM and optional subprocess collection run synchronously in an async HTTP handler. | Simplify supported features; bound resource use, parsing, collection concurrency and snapshot consistency. Keep platform expansion as separate work. |
| Publication | No Confido root licence was found in the reviewed tree; RPM specs say Proprietary. | Record the licensing/ownership decision needed before an open release. Preserve upstream notices; do not assign a new licence without owner authority. |

The current test sources already exercise several useful failure paths: mutated nonce/certificate/IMA entries, changed PCR values and selection metadata, malformed HCL data, TRS comparison/replay, TLS hostname/certificate rejection, KDS retry/cache behaviour and the Python discovery boundary. Preserve those tests while adding tests for the remaining claims. They do not constitute a full live end-to-end or independent reproduction suite.

## Demonstration design

A 10–12 minute walkthrough is sufficient:

1. Show exact revisions, image/wheel/reference digests and the measured-state coverage. Keep deployment topology in the accompanying technical architecture documentation.
2. Show both ServiceInfo identities, the report advertisement, configured reference link and unsupported session binding.
3. Run the matching case using the published instructions. Retain the full attestation trace, show the authenticated SNP–HCL–vTPM chain and the accepted measurement policy, then submit a harmless synthetic prompt.
4. Run the mismatching case using exactly the same verifier path. Show the precise failed reference comparison and evidence that no inference request was submitted by the demo client.
5. Show selected retained negative-test results and how another evaluator can replay a recorded decision. Recorded replay must be labelled as historical/offline verification.
6. Close with the technical roadmap: connection binding and re-attestation; governed reference updates; Epoch/Capability Authority; protected operation; fresh restoration and independent reproduction.

A second matching request after a failed case is another admission test. Lifecycle restoration requires new epoch/authority and invalidation of old authority.

## Standards wording

GA4GH specifies `GET /service-info` and service metadata; `teeReport` and `/tee-report` are this integration's documented extension. Keep `type.group: network.genxt.demo` and the separate service IDs. [GA4GH schema](https://github.com/ga4gh/ga4gh-service-info/blob/develop/service-info.yaml).

RFC 9261 already standardizes Exported Authenticators. Their use for remote attestation is ongoing draft work listed by SEAT. The current Confido demo implements neither connection binding nor the planned BoringSSL profile. [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261.html), [SEAT documents](https://datatracker.ietf.org/wg/seat/documents/).

## Suggested completion criterion

An evaluator can obtain one immutable demo package, observe both outcomes with retained logs, identify exactly what was measured and trusted, independently reproduce the frozen decision, and distinguish demonstrated behavior from planned capabilities.

The accompanying revision prompt turns this recommendation into an implementation brief.
