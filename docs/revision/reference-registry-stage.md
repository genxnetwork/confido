# Genoa stage reference enrollment

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

## Publication sequence

1. The public registry `teraveri/reference-value-registry` is initialized at
   `fcf172f378225648d50a69028020b1798b90a0c9`. Keep that commit available:
   the GENXT request pins its manifest and reference bytes.
2. Review and merge the GENXT `revision/reference-endorsement` branch into
   `master`. Its branch rules require a pull request, one approval from a
   collaborator other than the PR author, and the passing `test` check. The
   Teraveri `main` rules require a pull request and the passing `validate`
   check; there is currently only one collaborator, so they require no separate
   approval. Both branches reject force pushes and deletion.
3. Run GENXT **Endorse reference manifest** on `master` with request ID
   `genoa-stage-1071`. Download the `genxt-reference-endorsement` artifact and
   copy its `genxt.sigstore.json` to the registry entry's `endorsements/`
   directory. Commit this through review; do not edit `manifest.json` or
   `reference.json`. Record the full resulting registry commit.
4. Generate JAN's verifier policy by verifying the bundle and local issuer
   policy. A successful command writes the output; a failed signature or
   mismatch writes nothing:

   ```bash
   python3 scripts/enroll_reference.py \
     --registry teraveri/reference-value-registry \
     --commit FULL_REGISTRY_COMMIT_WITH_BUNDLE \
     --entry entries/azure-snp-vtpm-ima-1/azure-genoa-ubuntu2204-kernel-1071-stage \
     --gh /mnt/tools/gh_2.105.0_linux_amd64/bin/gh \
     --output profiles/verifier-genoa-stage.json
   ```

   `gh` CLI is required for Sigstore verification. `--registry-dir` permits a
   clean local checkout at the exact selected commit. The issuer policy is
   [`profiles/reference-issuers-stage.json`](../../profiles/reference-issuers-stage.json),
   and the observed platform enrollment is
   [`profiles/platform-genoa-stage.json`](../../profiles/platform-genoa-stage.json).
   Revisit the platform values when the VM image or firmware changes.
   Other publishers use a separate locally approved issuer entry and
   `--issuer NAME`; the registry cannot add a trusted issuer by itself.
5. Run the isolated hardware acceptance against the new positive policy and
   the Genoa negative policy, which keeps the same platform enrollment but
   references an older, incompatible IMA baseline:

   ```bash
   ../confidential-ai-example/.venv/bin/python scripts/stage_demo.py \
     --sidecar /tmp/ga4gh-service-info \
     --out /private/new-genoa-stage-run \
     --match-verifier-policy profiles/verifier-genoa-stage.json \
     --mismatch-verifier-policy profiles/verifier-genoa-stage-mismatch.json
   ```

   Save `acceptance.json` and the full hashes of Confido, sidecar, app/wheel,
   registry commit, and policies. The stage responder is synthetic and does
   not evaluate external inference. Public service promotion is a separate
   deployment step.

The publisher signature, pinned commit, exact file hash, and platform
enrollment have distinct purposes. A signed stage candidate is still only a
stage candidate. Later revocation does not update an already pinned client;
operators must explicitly roll out a new policy.
