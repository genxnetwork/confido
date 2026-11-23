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
| Earlier local rebase | `523b7ff` | Retained on `backup/pre-jan-consolidation-20261123`; merge resolutions reviewed |
| Original research baseline | `2112b49ed248ac40dcdb819b63ea9739d055d138` | Existing `archive/research-baseline` |

The pre-consolidation README/INFO edits and provisional version edits are retained
in the local stash named `Before JAN consolidation`. They remain recoverable;
the active README now documents the portable API. The separate `confido.drafts`
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

The native chat transport belongs to `confidential-ai-example`. ServiceInfo and
Flint retain their own repository histories. New integration results must identify
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

The code checkpoint is `224b374783bc0301d2e8a118fb801ad7d5817eb5` (2026-11-23).
It is a local revision checkpoint, not the final extraction/release checkpoint R.
The [validation record](revision/validation-0.2-20261123.json) identifies source
fingerprints, artifact hashes, dependency versions and downstream dirty trees.
All five imported JAN remote branch tips, the local Docker/dmesg branch tips and
the preserved review series are ancestors. Ancestry preserves research history;
it does not include unsupported GPU/container/diagnostic claims in the verifier.

| Check | Current result |
|---|---|
| Locked native core / collector tests | 15 / 7 passed |
| Collector launcher tests | 7 passed with isolated processes |
| Installed Python 0.2 wheel API/schema tests | 6 passed |
| Core and WASM dependency guard | Passed; no TPM/network/TLS runtime |
| Real Milan archive, historical replay | 28 cases passed, including signature/binding/reference mutations |
| CLI / Python / Chromium / Firefox parity | Identical results for 7 cases in each comparison |
| Installed Chromium MV3 | Worker, CSP, replay, stale assets and source-identity rejection passed |
| Downstream application/transport | 28 tests passed with Confido 0.2 and transport 0.4 |
| Wheel attribution | Apache licence, notices and 79 third-party package records present |
| Fresh isolated collector on this VM | `/tee-report` returned 200; application rejected unsupported Genoa |
| Positive live Milan acceptance | Outstanding; this VM is Genoa |

Native binaries/Python wheel were built in the development profile; browser WASM
was built in release mode. The historical archive was collected on 2026-09-23 and
evaluated at its original time, `1790178810`; its hash is in the record. Thirty
local replays had p95 11.71 ms in this environment, excluding collection/network.
This is new validation of current code against preserved real inputs, not a claim
that historical evidence grants live access. Raw evidence and staging secrets
remain in ignored local artifacts.

The live run found and fixed two issues: nested collector failures lost their
diagnostic message, and the decoder did not accept SNP report v5. Versions 2, 3
and 5 now have signature/layout regression coverage; unknown versions fail.
The bounded Milan profile explicitly rejects other reported processors before
requesting a Milan VCEK. New v5 mitigation/TIO/page-swap fields are not appraised.
The live acceptance harness still exits unsuccessfully at its positive-match
expectation on Genoa; later live match/mismatch and transport cases were not run.

Commands used (the private archive path is supplied by its holder):

```sh
cargo test --locked --offline --manifest-path lib/Cargo.toml
cargo test --locked --offline --manifest-path server/Cargo.toml
cargo build --locked --offline --manifest-path client/Cargo.toml
python3 scripts/check_verifier_dependencies.py
python3 -m unittest discover -s server/tests -p test_launcher.py -v
make -C bindings/python install PROFILE=dev PYTHON="$VIRTUAL_ENV/bin/python"
python -m unittest discover -s lib/tests -v
python3 extension/build.py --browser chromium
python3 extension/build.py --browser firefox
python scripts/replay_checks.py "$PRIVATE_ARCHIVE" profiles/verifier-match.json \
  --at 1790178810 --output /private/replay-results.json --samples 30
python scripts/browser_checks.py --bundle "$PRIVATE_ARCHIVE" --at 1790178810
```

The application tests ran in `confidential-ai-example` with its pinned Python
dependencies and independently built native transport. Its source tree and the
sidecar tree were already dirty; their HEADs alone do not identify tested code.
The record includes fingerprints of the actual inputs. No downstream source
edits or public deployment were made during consolidation.

An `apt upgrade` completed during validation at 10:25:30 UTC. It updated libc and
Nginx and installed a newer Azure kernel. Final wrapper/replay/browser/live checks
ran afterward; core/collector/launcher tests were explicitly rerun. The running
kernel remains `6.8.0-1068-azure-fde`; `1071` is installed and a reboot is pending.
These results do not certify the post-reboot boot/PCR/IMA state. The trusted
reference was not changed to make the updated host pass.

Before checkpoint R: complete fresh match/mismatch and transport acceptance on an
enrolled Milan host, and review release artifact requirements. A release Python
wheel/container, Fedora RPM packaging and Safari runtime have not been accepted
by these checks. Then record R and extract Attestor while retaining shared
history. GitHub issue/PR, pushes, tags and package publication remain outstanding.
Historical reports under `docs/revision/` and `docs/design/` retain their original
version labels and do not certify this combined tree.

## Later execution trust work

Veraison, CoCo/Trustee and Keylime integration follows a defined evidence/result
contract with explicit trust boundaries. Formal execution contexts, capability
issuance/enforcement, invalidation and restoration belong to subsequent 0.x work.
The 1.0 milestone requires a stable execution-trust contract and a tested lifecycle
for declared profiles, including machine-enforced processing constraints within
the controlled system. The present verifier returns `evidence_only`.
