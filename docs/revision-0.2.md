# Confido 0.2 revision in JAN

The working branch is `revision/attestation-update` in JAN DIGITRUST. The target
is a reproducible portable evidence verifier, with a compatible native collector
at a shared checkpoint before extracting Attestor. Version 0.2.0 is a development
target; it has not been released or validated for production deployment.

## Scope and next checkpoint

The current tree combines the portable verifier, native collector and caller
revisions at 0.2.0. The core, collector, CLI, installed Python wheel, WASM worker
and package attribution need to agree at a reproducible checkpoint. The dated
validation below identifies what has already been exercised and at which source
revisions.

The pre-extraction checkpoint is now fixed by signed local commits: Confido
`075364083ac982be1f38945a30b615d61a475f67`, confidential-ai-example
`c174f34da57ca5823aa6b512c484dfd42d47d967`, and the published Evidence
dependency `900d420b0928c4693e1143aa33a33ab670147e3c`. Create JAN Attestor
from that Confido checkpoint with shared history. Confido and Attestor then need
separate active source trees, build graphs, release workflows and acceptance
checks. Propose the substantive verifier changes upstream to GENXT from JAN;
continue collector development in JAN. The published research baseline remains
fixed. The tracking issue and PR should state the final behavior, acceptance
evidence and remaining limits.

## Inputs and provenance

| Input | Commit | Treatment |
|---|---|---|
| Published attestation revision | `28471a04c4af23a4765c4584757685ba56245664` | Direct ancestor of this branch |
| Licensed JAN/GENXT master | `1faf101bc5595699e2ad37828cad1692a2ae7d71` | Merged with licence packaging retained |
| Local review series | `4406996`, `0c33604`, `f8a9b2f`, `e0061e0`, `1b33d6e` | Merged with original commit identities |
| Original research baseline | `2112b49ed248ac40dcdb819b63ea9739d055d138` | Published as `archive/research-baseline` |

Current packages target 0.2.0. Wire/binding v1 and policy/result/archive
schema v2 have separate compatibility rules; see the [migration guide](migration-0.2.md).

## Component boundaries

| Component | Current responsibility | Destination |
|---|---|---|
| `lib/` | Deterministic bytes/policy/nonce/time verification | Confido, then GENXT upstream |
| `evidence-protocol` Git crate | Shared evidence wire and binding types | Teraveri Evidence repository |
| `evidence-core` Git crate | Shared bounded parsing and snapshot consistency checks | Teraveri Evidence repository |
| `bindings/python/`, `bindings/wasm/` | Thin wrappers over the same verifier | Confido |
| `server/` | Native SNP/vTPM/IMA collection and report endpoint | JAN Attestor |
| `client/` | Evidence retrieval, offline verification and replay | Split caller/verification ownership during extraction |
| `extension/` | Browser caller with local WASM verification | Confido consumer |

The native chat transport belongs to `confidential-ai-example`. New integration
results must identify the actual revisions used; historical cross-repository
reports are not current acceptance evidence.

The collector and verifier use two Git crates pinned to one published Evidence
commit; no sibling checkout is required. The collector does not depend on the
full Confido verifier. Keep the wire/binding contract tests when Attestor is
extracted.

Docker inventory and dmesg are absent from the current collector path and are
not authenticated evidence in the supported profile. Any later Attestor
diagnostic support needs an explicit access policy and a separate claim boundary.

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

The [latest local review run](revision/acceptance-genoa-review-20261124.md)
repeated live Genoa match/mismatch against the published Evidence pin with
rebuilt 0.2.0 wheels and container. It also repeated the 27-case hardware
replay and seven-case CLI/Python/Chromium/Firefox parity. The source trees
still had uncommitted edits, so this is an artifact-identified local result,
not yet a signed, clean release checkpoint.

The isolated run used a synthetic downstream responder. Its 45 IMA entries
cover a boot aggregate and 44 kernel modules, not application, model or GPU
state. Public deployment, external inference, Safari runtime and independent
reproduction remain untested. The manual GENXT stage endorsement is pinned;
the automated Actions OIDC path remains pending. See the
[reference registry record](revision/reference-registry-stage.md) and
[independent rerun checklist](revision/rerun.md).

The signed checkpoint records the reviewed source and the Linux attribution
archives. RPM creation and independent acceptance still require their own
checks before publication. Extract Attestor with shared history from this
checkpoint; a release tag and package publication are separate steps. The dated
acceptance records identify the source fingerprints used in those runs and do
not certify later executable edits.

## Later execution trust work

Veraison, CoCo/Trustee and Keylime integration follows a defined evidence/result
contract with explicit trust boundaries. Formal execution contexts, capability
issuance/enforcement, invalidation and restoration belong to subsequent 0.x work.
The 1.0 milestone requires a stable execution-trust contract and a tested lifecycle
for declared profiles, including machine-enforced processing constraints within
the controlled system. The present verifier returns `evidence_only`.
