# Genoa stage reference enrollment

This document records the Confido verifier acceptance performed during the
revision. The active Genoa stage policies, issuer decision and enrollment tool
are owned by `confidential-ai-example`; see its
`docs/genoa-stage-reference.md` for current rerun instructions.
The earlier live result predates the direct endpoint flow and does not validate
the revised deployment routing or credentialless TLS peer probe.

The public [Teraveri registry](https://github.com/teraveri/reference-value-registry)
holds the exact reference bytes and a manifest describing their scope. GENXT
endorses the manifest from its own
[`confido-trusted-repository`](https://github.com/genxnetwork/confido-trusted-repository)
workflow. Confido's JAN-owned issuer policy accepts that specific workflow and
ref, then pins a full registry commit and reference hash in a v2 verifier policy.
No code in the registry decides which issuer JAN trusts.

The current Genoa entry is a **stage candidate** observed on the 1071 kernel.
It covers boot aggregate and kernel module IMA events only. Signing this
manifest means GENXT recognizes the manifest; it does not certify the VM image,
application, GPU, or model. Rebuilds and kernel changes need new measurements
and a new entry rather than changing a pinned reference.

## Temporary manual stage path

GENXT Actions cannot currently start its required `test` job. For the urgent
stage, GENXT has issued a one-use Ed25519 statement from the reviewed request
using `tools/sign_manual_endorsement.py`. The private key existed only in the
signing process. Its public key and signed statement are in the GENXT
`revision/reference-endorsement` branch at commit
`66521651cb2bd56739cb4717af8ff149e7e1ccc7`. The registry holds a copy at
`endorsements/genxt-manual.ed25519.json`. JAN's local issuer policy explicitly
pins that key, this one manifest path and its SHA-256, and stage-candidate
status. This manual signature provides exact-file integrity under that
locally accepted key; it does not have the GitHub Actions OIDC provenance of
the normal path below. The GENXT `master` rule still requires `test`.

The working stage policy
`confidential-ai-example/profiles/verifier-genoa-stage-registry.json`
pins the merged Teraveri `main` commit
`3fa7913d44a377806bd94126589be1feb362b6cb`. The live Genoa positive and
negative acceptance passed with this exact commit; see the
[`acceptance record`](acceptance-genoa-manual-20261123.md). To regenerate the
policy, use:

```bash
python3 ../confidential-ai-example/scripts/enroll_reference.py \
  --registry teraveri/reference-value-registry \
  --commit 3fa7913d44a377806bd94126589be1feb362b6cb \
  --entry entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage \
  --issuer GENXT-manual \
  --registry-dir ../reference-value-registry \
  --issuer-policy ../confidential-ai-example/profiles/reference-issuers-stage.json \
  --platform ../confidential-ai-example/profiles/platform-genoa-stage.json \
  --output ../confidential-ai-example/profiles/verifier-genoa-stage-registry.json
```

`--registry-dir` requires a clean checkout at that exact commit. Python's
`cryptography` package verifies the Ed25519 signature. When GENXT Actions
become available, follow the OIDC publication sequence below and replace the
manual issuer decision in a new JAN policy review.

## Publication sequence

1. The public registry `teraveri/reference-value-registry` is initialized at
   `fcf172f378225648d50a69028020b1798b90a0c9`. Keep that commit available:
   the GENXT request pins its manifest and reference bytes.
2. Review and merge the GENXT `revision/reference-endorsement` branch into
   `master`. Its branch rules require a pull request and the passing `test`
   check, but no approving review. The Teraveri `main` rules require a pull
   request and the passing `validate` check; there is currently only one
   collaborator, so they require no separate approval. Both branches reject
   force pushes and deletion.
3. Run GENXT **Endorse reference manifest** on `master` with request ID
   `genoa-stage-1071`. Download the `genxt-reference-endorsement` artifact and
   copy its `genxt.sigstore.json` to the registry entry's `endorsements/`
   directory. Commit this through review; do not edit `manifest.json` or
   `reference.json`. Record the full resulting registry commit.
4. Generate JAN's verifier policy by verifying the bundle and local issuer
   policy. A successful command writes the output; a failed signature or
   mismatch writes nothing:

   ```bash
   python3 ../confidential-ai-example/scripts/enroll_reference.py \
     --registry teraveri/reference-value-registry \
     --commit FULL_REGISTRY_COMMIT_WITH_BUNDLE \
     --entry entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage \
     --gh /mnt/tools/gh_2.105.0_linux_amd64/bin/gh \
     --issuer-policy ../confidential-ai-example/profiles/reference-issuers-stage.json \
     --platform ../confidential-ai-example/profiles/platform-genoa-stage.json \
     --output ../confidential-ai-example/profiles/verifier-genoa-stage.json
   ```

   `gh` CLI is required for Sigstore verification. `--registry-dir` permits a
   clean local checkout at the exact selected commit. The issuer policy is
   `confidential-ai-example/profiles/reference-issuers-stage.json`,
   and the observed platform enrollment is
   `confidential-ai-example/profiles/platform-genoa-stage.json`.
   Revisit the platform values when the VM image or firmware changes.
   Other publishers use a separate locally approved issuer entry and
   `--issuer NAME`; the registry cannot add a trusted issuer by itself.
5. Run the isolated hardware acceptance against the new positive policy and
   the Genoa negative policy, which keeps the same platform enrollment but
   references an older, incompatible IMA baseline:

   ```bash
   ../confidential-ai-example/.venv/bin/python ../confidential-ai-example/scripts/stage_demo.py \
     --out /private/new-genoa-stage-run \
     --match-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage.json \
     --mismatch-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage-mismatch.json
   ```

   Save `acceptance.json` and the full hashes of Confido, sidecar, app/wheel,
   registry commit, and policies. The stage responder is synthetic and does
   not evaluate external inference. Public service promotion is a separate
   deployment step.

The publisher signature, pinned commit, exact file hash, and platform
enrollment have distinct purposes. A signed stage candidate is still only a
stage candidate. Later revocation does not update an already pinned client;
operators must explicitly roll out a new policy.
