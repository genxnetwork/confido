# Confido 0.2 revision in JAN

The working branch is `revision/attestation-update` in JAN DIGITRUST. The target
is a reproducible portable evidence verifier, with a compatible native collector
at a shared checkpoint before extracting Attestor. Version 0.2.0 is a development
target; it has not been released or validated for production deployment.

## Scope and sequence

1. Continue the published revision history and merge the Apache-licensed JAN base.
2. Integrate the preserved local portable-verifier review series, resolve obsolete
   client/collector code, and align current package versions at 0.2.0.
3. Validate the core, collector, CLI, installed Python wheel, WASM worker and
   package attribution against this combined tree. Record current results below.
4. Fix the common checkpoint by commit identity. Create JAN Attestor with the same
   history, then give Confido and Attestor separate active source trees, build
   graphs, release workflows and acceptance checks.
5. Propose the substantive verifier changes upstream to GENXT from JAN. Attestor
   development continues in JAN. The historical research baseline stays fixed.

One integration branch holds this revision. Keep changes as reviewable thematic
commits. A tracking issue should state the problem, scope and acceptance criteria;
the linked PR should describe the final behavior and evidence. Creating either
on GitHub is a later publication step.

## Inputs and provenance

| Input | Commit | Treatment |
|---|---|---|
| Published attestation revision | `28471a04c4af23a4765c4584757685ba56245664` | Direct ancestor of this branch |
| Licensed JAN/GENXT master | `1faf101bc5595699e2ad37828cad1692a2ae7d71` | Merged with licence packaging retained |
| Local review series | `4406996`, `0c33604`, `f8a9b2f`, `e0061e0`, `1b33d6e` | Merged with original commit identities |
| Earlier local rebase | `523b7ff` | Audited against this tree; obsolete ServiceInfo/legacy API changes were not merged. Its historical results are already reachable at `9ecade8` and earlier ancestors. Local branch pointers removed. |
| Original research baseline | `2112b49ed248ac40dcdb819b63ea9739d055d138` | Published `origin/archive/research-baseline`; local pointer removed |

The two pre-consolidation stashes were audited: one contains provisional version
and README edits, the other unfinished dmesg changes. Neither applies to this
revision; both local stashes were removed. The separate `confido.drafts`
checkout remains a source snapshot.

Earlier 0.3/0.4 identifiers occur in development manifests, historical test
reports and deployed demo artifacts. Preserve those records. Current package
numbers are 0.2.0; wire/binding v1 and policy/result/archive schema v2 have their
own compatibility rules.

## Component boundaries

| Component | Current responsibility | Destination |
|---|---|---|
| `lib/` | Deterministic bytes/policy/nonce/time verification | Confido, then GENXT upstream |
| `protocol/` | Shared evidence wire and binding types | Shared contract; packaging decided during extraction |
| `bindings/python/`, `bindings/wasm/` | Thin wrappers over the same verifier | Confido |
| `server/` | Native SNP/vTPM/IMA collection and report endpoint | JAN Attestor |
| `client/` | Evidence retrieval, offline verification and replay | Split caller/verification ownership during extraction |
| `extension/` | Browser caller with local WASM verification | Confido consumer |

The native chat transport belongs to `confidential-ai-example`. Flint retains
its own repository history. New integration results must identify
the actual revisions used; historical cross-repository reports are not current
acceptance evidence.

Old Docker inventory and dmesg implementations remain in Git history. They are
not authenticated evidence in the supported profile and are absent from the
current collector path. Any later Attestor diagnostic support needs an explicit
access policy and a separate claim boundary.

## Acceptance criteria

- Current core and wrapper versions agree; locked builds succeed.
- Core and WASM normal dependency graphs contain no TPM, network or TLS runtime.
- Native core checks cover signature/binding/PCR/reference rejection cases.
- Installed Python, CLI and browser callers return consistent evidence results.
- Collector tests cover bounded input, certificate configuration and safe launcher
  behavior using isolated resources.
- Binary packages retain Apache licensing and dependency attribution.
- Hardware replay/live acceptance and downstream transport integration are
  recorded separately from unit tests. Unavailable checks remain explicit.
- The extraction checkpoint is committed and reproducible before creating Attestor.

## Current validation

The live direct-endpoint code baseline is Confido
`402f252bf4a49da83c9bc91eaa12d6eb3a6c37fa` and application
`54813aca0047d780177eac5930223b030fd0d318` on kernel
`6.8.0-1071-azure-fde`. This is a local acceptance baseline, not extraction
checkpoint R. The full source/policy/artifact identifiers and limitations are in
the [Genoa direct-endpoint acceptance](revision/acceptance-genoa-direct-20261123.md).

| Check | Current result |
|---|---|
| Locked native core / collector tests | 15 / 7 passed |
| Collector launcher tests | 7 passed with isolated processes |
| Installed Python verifier API/schema tests | 7 passed |
| Core and WASM dependency guard | Passed; no TPM/network/TLS runtime |
| Current Genoa match/mismatch on direct endpoint | All 12 stages passed for match; negative reference rejected with zero application requests |
| Native transport | Shared-certificate cross-origin and wrong-host rejection passed; six evidence requests used zero application credentials |
| Current frozen container | Rebuilt image `sha256:e2fa324e…` passed match/mismatch through the direct endpoint; nine evidence requests carried zero application credentials |
| Current Genoa archive replay | 27 cases passed; 30 local appraisals p95 3.93 ms, excluding collection/network |
| CLI / Python / Chromium / Firefox parity | Identical results for seven cases in each runtime |
| Installed Chromium MV3 | Worker, CSP, replay and stale-asset checks passed |
| Downstream application/transport | 38 application and 2 transport tests passed |
| IMA enrollment | 45 entries: boot aggregate and 44 kernel modules; no application/model/GPU measurement |

The fresh run used isolated listeners and a synthetic downstream responder. It
did not modify public service configuration or exercise external inference.
The verifier wheel, server binary and local container image were recorded by
hash; Safari runtime, independent reproduction and public deployment promotion
remain open. The manual GENXT stage endorsement is explicitly pinned; normal
GENXT Actions OIDC publication remains blocked by its required CI job. Previous
Milan archives and the 1068-kernel checkpoint remain historical evidence in
Git history, not current live acceptance.

The old `revision/0.2`/`backup/pre-jan-consolidation-20261123` tip was audited
before removal. Its 14 unique commits hold an earlier API, discovery/ServiceInfo
flow and test harness; merging it would restore retired behavior. Its report,
review, run and checkpoint records already exist byte-for-byte at the current
line's `9ecade8` ancestor. Reusable SNP/HCL/quote/PCR/IMA and origin checks have
current equivalents in the verifier, replay suite and application transport.
The active replay harness was corrected to mutate actual v2 archive inputs;
the old top-level mutations were ineffective on current archives. Its v1
migration path also passed the same 27 cases on a v1-shaped copy of the fresh
Genoa bundle.

Before checkpoint R: review release packaging/attribution and obtain independent acceptance if
required for publication. Then record R and extract Attestor with shared
history. GitHub issue/PR, pushes, tags and package publication remain
outstanding. Historical reports under `docs/revision/` and `docs/design/`
retain their original version labels and do not certify this combined tree.

## Later execution trust work

Veraison, CoCo/Trustee and Keylime integration follows a defined evidence/result
contract with explicit trust boundaries. Formal execution contexts, capability
issuance/enforcement, invalidation and restoration belong to subsequent 0.x work.
The 1.0 milestone requires a stable execution-trust contract and a tested lifecycle
for declared profiles, including machine-enforced processing constraints within
the controlled system. The present verifier returns `evidence_only`.
