# Independent rerun checklist

Reviewer identity: **pending**. Date/sign-off: **pending**. The implementation run is not an independent reproduction.

1. Check Confido and `confidential-ai-example` source revisions against the selected manifests. Confirm clean source trees and review local policy enrollment separately from the network endpoint.
2. Install the frozen Rust/Python target and native requirements. Run locked Rust tests/builds. Preserve complete logs and exit codes.
3. Build/install compatible verifier and application wheels. Run `lib/tests` and the chat example's `tests`. Run `../confidential-ai-example/scripts/preflight.py` with those installed wheels for synchronized deployment templates and runtime checks.
4. Build the chat container (`make build` in the sibling example). Preserve the wheel hash, requirements lock, base/application image identifiers, package list and generated build manifest. The container image is the frozen runtime artifact; rebuilding apt-installed runtime packages at another date may change the image. Retain/export the exact image for offline reproduction.
5. On a compatible Azure Milan or Genoa SNP/HCL/vTPM VM with the independently enrolled product-specific AMD root, launch measurement, TCB floor and IMA state, run the isolated harness. It requires root TPM access, Nginx, ports 18001/18443/18444/14000 free, and HTTPS access to AMD KDS and the pinned GitHub reference. KDS receives the hardware identifier and TCB versions to retrieve the public VCEK.

   ```sh
   ../confidential-ai-example/.venv/bin/python ../confidential-ai-example/scripts/stage_demo.py \
     --out /private/new-stage-run \
     --container confidential-ai-example:0.4.0
   ```

   The harness uses genuine hardware evidence and an explicitly synthetic downstream chat responder. It verifies the actual installed wheel/container, reference match/mismatch, no application traffic during appraisal, hostname mismatch and origin scoping. It never changes public listeners or uses production application credentials. Read `acceptance.json`; do not infer success from process startup.
6. Replay a retained matching bundle using `scripts/replay_checks.py BUNDLE POLICY --at EVALUATION_UNIX_TIME --output RESULT`. The policy is supplied independently. Inspect the negative cases and p95 local timing separately from collection/KDS/reference network time. Keep raw host evidence private.
7. For a public deployment promotion, review and install the aligned collector/Nginx files together. Confirm both SAN names and the same certificate served by Nginx and bound by the collector. Run online preflight with the match policy, then the interactive match and mismatch cases. Port 80 must redirect; `/aTLS` must return 404; backend ports must be private. Public promotion is a separate operator action from producing this revision.
8. Review the claim/coverage matrix, unresolved revocation/TCB/enrollment assumptions, third-party attribution, observed measurements and external inference boundary. Record deviations instead of substituting a new reference to force a pass.

Retain: run ID/time, source commits/tree hashes, toolchain and dependency locks, wheel/image/config/schema/profile identifiers, endpoint/reference/challenge/evidence/certificate identifiers, expected/observed decisions, timings and redacted logs. Never include tokens, private keys, application credentials or protected prompts. Check the topology in decision 001 when interpreting the two endpoint test.
