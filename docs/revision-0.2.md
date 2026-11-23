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
| Earlier local rebase | `523b7ff` | Audited against this tree; obsolete discovery and legacy API changes were not merged. Its historical results are already reachable at `9ecade8` and earlier ancestors. Local branch pointers removed. |
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
| `../evidence/protocol/` | Shared evidence wire and binding types | Teraveri Evidence repository |
| `../evidence/core/` | Shared bounded parsing and snapshot consistency checks | Teraveri Evidence repository |
| `bindings/python/`, `bindings/wasm/` | Thin wrappers over the same verifier | Confido |
| `server/` | Native SNP/vTPM/IMA collection and report endpoint | JAN Attestor |
| `client/` | Evidence retrieval, offline verification and replay | Split caller/verification ownership during extraction |
| `extension/` | Browser caller with local WASM verification | Confido consumer |

The native chat transport belongs to `confidential-ai-example`. Flint retains
its own repository history. New integration results must identify
the actual revisions used; historical cross-repository reports are not current
acceptance evidence.

The collector and verifier use the two crates from the sibling `../evidence/`
checkout. The collector does not depend on the full Confido verifier. CI pins
one Evidence commit for both crates; publishing that commit to Teraveri is
required before the remote checks can run. Keep the wire/binding contract tests
when Attestor is extracted.

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

## Dated validation

The pre-extraction local baseline is Confido
`402f252bf4a49da83c9bc91eaa12d6eb3a6c37fa` and
`confidential-ai-example` `54813aca0047d780177eac5930223b030fd0d318`
on kernel `6.8.0-1071-azure-fde`. The
[direct-endpoint acceptance](revision/acceptance-genoa-direct-20261123.md)
pins the source, policies, binaries, wheels and run artifacts; the earlier
[manual-reference acceptance](revision/acceptance-genoa-manual-20261123.md)
records the initial publisher path. These records validate their pinned
revisions, not later edits in this working tree.

The [shared evidence core acceptance](revision/acceptance-shared-core-genoa-20261123.md)
records a later isolated Genoa match/mismatch and 27-case replay after the
collector stopped depending on the full verifier. It validates the installed
wheel path, but does not repeat the earlier container or browser runs.

At that baseline, locked native and Python tests, dependency guards, CLI/Python
and Chromium/Firefox parity, native transport, and downstream application
tests passed. The live Genoa match passed all 12 verifier checks; the mismatched
reference was rejected before application traffic. The rebuilt local
container passed the same positive/negative route. The 27-case archive replay
and local timing are recorded in the direct-endpoint acceptance. The
[coverage matrix](revision/coverage.md) maps each claim to its test and limit.

The isolated run used a synthetic downstream responder. Its 45 IMA entries
cover a boot aggregate and 44 kernel modules, not application, model or GPU
state. Public deployment, external inference, Safari runtime and independent
reproduction remain untested. The manual GENXT stage endorsement is pinned;
the automated Actions OIDC path remains pending. See the
[reference registry record](revision/reference-registry-stage.md) and
[independent rerun checklist](revision/rerun.md).

The removed `revision/0.2` / `backup/pre-jan-consolidation-20261123` line was
audited before removal. Its 14 unique commits used an earlier API and
discovery flow; merging the line would restore retired behavior.
Its report, review and checkpoint records remain reachable at `9ecade8`.
Reusable SNP/HCL/quote/PCR/IMA and origin checks have current equivalents.
The active replay harness was corrected to mutate actual schema-v2 archive
inputs; its v1 adapter passed the same 27 cases on a v1-shaped Genoa bundle.

Before checkpoint R, review release packaging and attribution, and obtain
independent acceptance if required for publication. Then record R and extract
Attestor with shared history. GitHub issue/PR, pushes, tags and package
publication remain outstanding. Earlier design and validation records remain
in Git history at `1b33d6e`; their original version labels do not certify this
combined tree.

## Later execution trust work

Veraison, CoCo/Trustee and Keylime integration follows a defined evidence/result
contract with explicit trust boundaries. Formal execution contexts, capability
issuance/enforcement, invalidation and restoration belong to subsequent 0.x work.
The 1.0 milestone requires a stable execution-trust contract and a tested lifecycle
for declared profiles, including machine-enforced processing constraints within
the controlled system. The present verifier returns `evidence_only`.
