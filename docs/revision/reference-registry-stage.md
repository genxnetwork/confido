# Genoa stage reference enrollment

This records the 2026-11-23 Confido verifier stage and the remaining
publication path. The Genoa policies, issuer decision and enrollment tool are
owned by `confidential-ai-example`; its `docs/genoa-stage-reference.md` is
the source for current policy-generation and isolated-run commands. The
[direct-endpoint acceptance](acceptance-genoa-direct-20261123.md) exercised
credentialless TLS peer verification on local ports, not public deployment.

The public [Teraveri registry](https://github.com/teraveri/reference-value-registry)
holds the exact reference bytes and a manifest describing their scope. GENXT's
planned automated endorsement uses the
[`confido-trusted-repository`](https://github.com/genxnetwork/confido-trusted-repository)
workflow; the recorded stage uses the manual signature below. The application's
locally controlled issuer policy accepts a specific
publisher identity, then pins a full registry commit and reference hash in a v2
verifier policy. No code in the registry decides which issuer the application trusts.

The recorded Genoa entry is a **stage candidate** observed on the 1071 kernel.
It covers boot aggregate and kernel module IMA events only. Signing this
manifest means GENXT recognizes the manifest; it does not certify the VM image,
application, GPU, or model. Rebuilds and kernel changes need new measurements
and a new entry rather than changing a pinned reference.

## Manual stage path recorded on 2026-11-23

GENXT Actions could not start its required `test` job for this run. For the
stage, GENXT issued a one-use Ed25519 statement from the reviewed request
using `tools/sign_manual_endorsement.py`. The private key existed only in the
signing process. Its public key and signed statement are in the GENXT
`revision/reference-endorsement` branch at commit
`66521651cb2bd56739cb4717af8ff149e7e1ccc7`. The registry holds a copy at
`endorsements/genxt-manual.ed25519.json`. The application's local issuer policy
explicitly pins that key, this one manifest path and its SHA-256, and stage-candidate
status. This manual signature provides exact-file integrity under that
locally accepted key; it does not have the GitHub Actions OIDC provenance of
the normal path below. At the time of the run, the GENXT `master` rule still
required `test`.

The recorded stage policy
`confidential-ai-example/profiles/verifier-genoa-stage-registry.json`
pins the merged Teraveri `main` commit
`3fa7913d44a377806bd94126589be1feb362b6cb`. The live Genoa positive and
negative acceptance passed with this exact commit; see the
[`manual acceptance`](acceptance-genoa-manual-20261123.md) and later
[`direct-endpoint acceptance`](acceptance-genoa-direct-20261123.md). The
application's `docs/genoa-stage-reference.md` gives the command for
regenerating this policy from a clean checkout at the pinned commit. Python's
`cryptography` package verifies the Ed25519 signature. An OIDC bundle requires
a new issuer decision and application policy review.

## Planned OIDC publication sequence

1. The public registry `teraveri/reference-value-registry` is initialized at
   `fcf172f378225648d50a69028020b1798b90a0c9`. Keep that commit available:
   the GENXT request pins its manifest and reference bytes.
2. Review and merge the GENXT `revision/reference-endorsement` branch into
   `master`. At the time of this record, GENXT required a pull request and
   passing `test`; Teraveri `main` required a pull request and passing
   `validate`. Recheck branch rules before publication.
3. Run GENXT **Endorse reference manifest** on `master` with request ID
   `genoa-stage-1071`. Download the `genxt-reference-endorsement` artifact and
   copy its `genxt.sigstore.json` to the registry entry's `endorsements/`
   directory. Commit this through review; do not edit `manifest.json` or
   `reference.json`. Record the full resulting registry commit.
4. Generate the application's verifier policy by verifying the bundle and local
   issuer policy. A successful command writes the output; a failed signature or
   mismatch writes nothing:

   ```bash
   python3 ../confidential-ai-example/scripts/enroll_reference.py \
     --registry teraveri/reference-value-registry \
     --commit FULL_REGISTRY_COMMIT_WITH_BUNDLE \
     --entry entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage \
     --issuer-policy ../confidential-ai-example/profiles/reference-issuers-stage.json \
     --platform ../confidential-ai-example/profiles/platform-genoa-stage.json \
     --output ../confidential-ai-example/profiles/verifier-genoa-stage.json
   ```

   `gh` CLI must be on `PATH` for Sigstore verification. `--registry-dir`
   permits a clean local checkout at the exact selected commit. The issuer
   policy is `confidential-ai-example/profiles/reference-issuers-stage.json`,
   and the observed platform enrollment is
   `confidential-ai-example/profiles/platform-genoa-stage.json`.
   Revisit the platform values when the VM image or firmware changes.
   Other publishers use a separate locally approved issuer entry and
   `--issuer NAME`; the registry cannot add a trusted issuer by itself.
5. Run the [isolated hardware rerun](rerun.md), setting
   `--match-verifier-policy` to the newly generated positive policy. Keep
   the Genoa negative policy, which retains the same platform enrollment but
   an incompatible IMA reference. Save
   `acceptance.json` and the full hashes of Confido, application/transport
   wheels, registry commit and policies. The responder is synthetic; public
   service promotion is a separate deployment step.

The publisher signature, pinned commit, exact file hash, and platform
enrollment have distinct purposes. A signed stage candidate is still only a
stage candidate. Later revocation does not update an already pinned client;
operators must explicitly roll out a new policy.
