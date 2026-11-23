# Independent rerun checklist

Reviewer identity: **pending**. Date/sign-off: **pending**. The implementation
run is not an independent reproduction.

1. **Pin inputs.** Check Confido and `confidential-ai-example` source revisions
   against the selected manifests. Confirm clean source trees and review local
   policy enrollment separately from the network endpoint.

2. **Install and test.** Install the pinned Rust/Python toolchains and native
   requirements. Run locked Rust builds and tests; retain logs and exit codes.

3. **Build callers.** Build and install compatible verifier and application
   wheels. Run `lib/tests` and the chat example's `tests`. Run
   `../confidential-ai-example/scripts/preflight.py` with the installed wheels
   to check synchronized deployment templates and runtime configuration.

4. **Freeze the image.** Run `make build` in the sibling example. Preserve
   wheel hashes, the requirements lock, base/application image identifiers,
   package list and generated build manifest. Rebuilding apt-installed
   packages later may change the image; retain or export this exact image
   for offline reproduction.

5. **Run the live stage.** Use a compatible Azure Milan or Genoa SNP/HCL/vTPM
   VM with independently enrolled product-specific AMD root, launch
   measurement, TCB floor and IMA state. The harness needs root TPM access,
   Nginx, free ports 18001/18443/18444/14000, and HTTPS access to AMD KDS
   and the pinned GitHub reference. KDS receives the hardware identifier
   and TCB versions to retrieve the public VCEK.

   Replace `/private` below with an existing private, writable directory;
   the final output path must not already exist.

   ```sh
   ../confidential-ai-example/.venv/bin/python ../confidential-ai-example/scripts/stage_demo.py \
     --out /private/new-stage-run \
     --match-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage-registry.json \
     --mismatch-verifier-policy ../confidential-ai-example/profiles/verifier-genoa-stage-mismatch.json \
     --container confidential-ai-example:0.2.0
   ```

   This selects the Genoa stage policies explicitly; the script defaults to
   the separate Milan demo pair. It uses genuine hardware evidence and a
   synthetic downstream chat responder. Check installed wheel/container
   behavior, reference match/mismatch, withheld application traffic,
   hostname mismatch and origin scoping. It changes no public listeners and
   uses no production application credentials. Read `acceptance.json`; process
   startup alone does not establish success.

6. **Replay.** Run
   `python3 scripts/replay_checks.py BUNDLE POLICY --at EVALUATION_UNIX_TIME --output RESULT`
   with an independently supplied policy. Inspect negative cases and p95
   local timing separately from collection/KDS/reference network time.
   Keep raw host evidence private.

7. **Promote only after review.** For public deployment, review and install
   aligned collector/Nginx files together. Confirm both SAN names and the
   same certificate served by Nginx and bound by the collector. Run online
   preflight with the match policy, then interactive match and mismatch.
   Port 80 must redirect, `/aTLS` must return 404, and backend ports must
   be private. Public promotion is a separate operator action.

8. **Record limits.** Review the [coverage matrix](coverage.md),
   revocation/TCB/enrollment assumptions, third-party attribution,
   observed measurements and external inference boundary. Record deviations
   rather than replacing a reference merely to force a pass.

Retain run ID/time, source commits/tree hashes, toolchain and dependency
locks, wheel/image/config/schema/profile identifiers,
endpoint/reference/challenge/evidence/certificate identifiers, decisions,
timings and redacted logs. Exclude tokens, private keys, application
credentials and protected prompts. Use [decision 001](decisions/001-bounded-profile.md)
to interpret the two-endpoint topology.
