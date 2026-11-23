# Genoa direct-endpoint acceptance, 2026-11-23

An isolated live run on kernel `6.8.0-1071-azure-fde` exercised the direct
`POST /tee-report` and credentialless `HEAD /tee-report` contract. Confido source
was clean at `402f252bf4a49da83c9bc91eaa12d6eb3a6c37fa`; the
`confidential-ai-example` source was clean at
`54813aca0047d780177eac5930223b030fd0d318`. The server was rebuilt from
that Confido tree immediately before the run. No public listener was changed.

The positive verifier policy SHA-256 was
`7d3cf06255a691ecec351bfbeaa147317eb2de272a96969d437b051e8aceb3c1`.
It pins Teraveri registry commit
`3fa7913d44a377806bd94126589be1feb362b6cb`, reference SHA-256
`31d1655c424507116f1f39adbbab5d02b35524756fb7c95eb5fce4ca7672086b`,
and the locally approved one-use GENXT manual publisher. The negative policy
SHA-256 was `2933581a0995279e872e78b2bb2e06eb6365777e13aa256905364f5d7920453e`;
it uses the same Genoa platform enrollment and an incompatible historical
reference.

| Check | Observed result |
|---|---|
| Positive, installed Python verifier and transport wheels | All 12 verifier stages passed; one synthetic application request after peer authentication |
| Negative reference | `measurement_mismatch`; zero application requests |
| Shared certificate at another origin | Three targets rejected before application traffic |
| Wrong TLS hostname | Rejected before application traffic |
| Report collection | Six `/tee-report` requests, none with application credentials |
| IMA coverage | 45 entries: one boot aggregate and 44 kernel modules; no application, model or GPU measurement |

The run lasted from `2026-11-23T18:36:17.558441+00:00` to
`2026-11-23T18:36:20.876018+00:00`. The private `acceptance.json` SHA-256 is
`3cdc76cd1b6a2c3e01e4025a36ca3086901f721daa175aeb21f3693d0ac68310`;
the positive and negative raw archives remain private and are not committed.
The rebuilt server binary SHA-256 was
`2c571bb33cbfc172a424617d9786315165530002a32577ca33976ff2564dd3e3`.
The application runtime manifest identified verifier wheel SHA-256
`e63f52866c89b6e23da64444450ed1533f25d80b213432ad36b9110c403bd6bb`
and transport wheel SHA-256
`c560ae9eb304ffa196c8b5dbeae860552f41f3efa07466d7b91531abd821bff3`;
`make dev-info` accepted both loaded binaries and pipeline revision 2.

The positive archive then passed 27 hardware-evidence replay cases, including
negative mutations, and 30 local appraisals had p95 `3.93 ms` with all inputs
already local. The private replay record SHA-256 is
`8ef9b2fabbd984d6e547948b03eb918b635ff485d9b54a310c467a06095fd0fe`.
Python, CLI, Chromium and Firefox returned identical results for seven cases;
the Chromium MV3 worker, CSP, replay and stale-asset rejection checks passed.

This is a local, synthetic downstream acceptance. It does not evaluate external
inference, public deployment, independent review, TLS
session binding, or application/model/GPU state. The GENXT publisher path remains
the explicitly pinned manual stage statement, not a completed Actions OIDC
endorsement.

## Current container rerun

After the direct-endpoint code and documentation commits, the application at
`b752fc6d1daad467dea67a32bc4622d6049bb74e` rebuilt both wheels and the
`confidential-ai-example:0.4.0` image. The image digest is
`sha256:e2fa324ecbd841fbbf9aaa24a5ce1109e363a76e53acc1446b858dfabc9c0528`.
The local build manifest SHA-256 is
`c0e72b8e364b234e1420d1d289178d639f53bcb5bab479d9dbd6e514660042a4`;
it records a clean application source tree, locked Python dependencies and
the embedded source fingerprints. The rebuilt verifier and transport wheel
SHA-256 values are respectively
`f95812ed06249a77fb8a0551cfb4cb790ebd26a334e9245455cc92eb599ebb36`
and `cb270dba03be6d4295822f623ce2455c8e6a3afba68f6476c55627b814885518`.
These are distinct package artifacts from the first run; their native binary
hashes and source fingerprints matched the earlier runtime manifest.

The isolated rerun completed from `2026-11-23T18:41:44.140457+00:00` to
`2026-11-23T18:42:03.071128+00:00`. The installed-wheel and container match
cases each made one synthetic application request; both mismatch cases made
zero. Shared-certificate cross-origin and wrong-host rejections still passed.
All nine `/tee-report` requests used zero application credentials. The private
container-run `acceptance.json` SHA-256 is
`0b042c1baa82a47fe967296beb01f9f25947c4f92abcf7ac95bb67e7415e910c`.
The exact image is held locally; no registry image was published.
