# Technical walkthrough (10–12 minutes)

This is the planned interactive demonstration narrative. For a reproducible
local Genoa run with a synthetic downstream responder, use the
[rerun checklist](rerun.md) and keep its limitations visible.

1. **0:00–2:00 — Scope.** Show the policy and [coverage matrix](coverage.md):
   SNP/HCL authenticity, recovered vTPM AK, signed quote/PCRs, boot aggregate
   and exact enrolled IMA state. Explain that the log covers kernel modules;
   external inference is outside the measured boundary.

2. **2:00–3:00 — Local policy.** Show the selected HTTPS origin, direct report
   endpoint, exact pinned reference URL/digest and unsupported session binding.

3. **3:00–6:00 — Match.** Choose the match endpoint and accept `[Y/n]`. Keep
   detailed logs visible. Follow endorsements, platform policy, HCL AK,
   quote binding, reference/PCR/IMA and HTTPS hostname/certificate confirmation.
   Open chat only after those checks. Explain where inference runs before
   submitting a prompt.

4. **6:00–8:00 — Mismatch.** Choose the other endpoint and use the same
   verification code. Show completed cryptographic stages and the incompatible
   reference at `measurement_mismatch`. Confirm that application requests and
   credentials are withheld.

5. **8:00–10:00 — Retained evidence.** Show the run result, immutable reference
   and artifact hashes. Replay the frozen bundle offline at the recorded
   evaluation time, then change a challenge or reference digest and show
   rejection. Label replay as historical, not fresh admission.

6. **10:00–12:00 — Boundaries and next work.** Show point-in-time client
   enforcement, unsupported TLS session binding, and planned BoringSSL/SEAT
   integration, governed references, epochs and capabilities. Invite
   independent reproduction using the checklist.

Use only synthetic prompts. Recorded prototype output is not evidence of the
current deployment. In isolated tests, label the downstream responder as
synthetic rather than inference validation. Technical topology and residual
trust assumptions are in [decision 001](decisions/001-bounded-profile.md).
