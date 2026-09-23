# Revision results — 2026-09-23

## Delivered and observed

Local checkpoint branches and `revision/attestation-update` exist in all four repositories. The bounded 0.3.0 revision is committed; no remote publication was performed.

The final isolated acceptance run completed from **2026-09-23T15:53:26.093689+00:00** to **2026-09-23T15:53:58.571546+00:00** and exited successfully. It used real SNP/HCL/vTPM evidence, the installed wheel, actual OpenAI SDK/HTTPX transport and the saved container image. The downstream responder was explicitly synthetic; these tests demonstrate admission and withholding, not inference validation.

| Check | Observed result |
|---|---|
| Installed wheel — match | admitted; one synthetic application request |
| Installed wheel — mismatch | `measurement_mismatch`; zero application requests |
| Container — match/mismatch | one / zero application requests respectively |
| Another origin using the shared certificate | three targets rejected before request |
| Wrong TLS hostname | rejected; zero application requests |
| Changed critical ServiceInfo | rejected; zero application requests |
| Credentials during discovery/report collection | zero across 18 requests |
| Temporary service cleanup | all isolated listeners stopped |

Validation: **25 Rust library tests, 6 server tests, 12 installed-wheel tests, 5 chat tests**, sidecar Go tests, both GA4GH/extension advertisements, seven result-schema records and **21 hardware-evidence replay cases** passed. RSA fixture tests, policy-unit tests and real hardware runs are identified separately in the [coverage matrix](coverage.md).

## Performance

Release wheel, 30 historical appraisals of one retained matching bundle, with all required inputs local: **p95 2.32 ms**, against the provisional 3000 ms target. Workload: a SNP/HCL report, RSA quote, 24 SHA-256 PCRs and 47 enrolled IMA entries. Collection/HTTPS/KDS/reference network time is recorded separately for each live decision.

Test host description: `{"Architecture": "x86_64", "CPU(s)": "2", "Hypervisor vendor": "Microsoft", "Model name": "19/01"}`. This small repeated-bundle workload does not establish throughput or general platform performance.

## Frozen artifacts

- Wheel: `confido_atls-0.3.0-cp310-cp310-manylinux_2_34_x86_64.whl`
- Wheel SHA-256: `04714cbe05615b5d2c5c052be35125dace146689060452856d34fec529582930`
- Container image: `sha256:15f2bc0adb8349478713ddb89ead7a1945a6e1230e647ed3baca5e76fd71722d`
- Private local package: `/mnt/confido/.artifacts/revision-20260923/`
- Public-safe provenance: [run record](run-20260923.json)
- Private package index: `SHA256SUMS.json`; exact OCI image, source snapshots, binaries, wheel, policies, raw evidence and full/redacted logs retained.

The package was assembled from an explicit allowlist: no private keys, tokens, application credentials or protected prompts. Raw host evidence remains private (directory 0700; files 0600). The Go artifact was built before its source commit; its exact tested binary is retained and rebuilding from the committed tree changes VCS build metadata. Runtime apt package versions are retained; the saved OCI image is the exact runtime artifact.

## Deployment and outstanding work

Public services remain at the checkpoint version: configuration/binary hashes were unchanged, both HTTP endpoints still redirected with 308, and both `/aTLS` routes returned 404. **The new 0.3.0 client requires promotion of the revised report server and sidecars before it can use those public endpoints.** Staging acceptance is complete; public promotion is a separate operator step using the reviewed templates and preflight.

Independent reviewer identity/sign-off and the Confido licence decision remain pending. TLS session binding, application/model/GPU appraisal, automated AMD revocation/advisory policy, governed reference promotion and server-side capabilities remain outside the implemented profile. No adversarial live PCR/IMA mutation was injected into the production VM; cryptographic mutation tests and collector consistency checks cover rejected inconsistent evidence.

Earlier successful acceptance checks exposed cleanup/PID ownership problems in the harness; these were corrected before the final clean run. See the [rerun checklist](rerun.md), [walkthrough](walkthrough.md) and [roadmap](roadmap.md).
