# Post-split Genoa acceptance, 2026-11-24

An isolated run on the current Azure Genoa VM exercised the separate JAN
Attestor collector, JAN Confido verifier, and client-only Confidential AI
example. It ran from 08:22:45 to 08:22:48 UTC (12:22 Asia/Yerevan).
Attestor used a temporary localhost leaf certificate on `127.0.0.1:18001`.
The existing listener on `127.0.0.1:8001` was not changed; temporary
listeners were closed. The downstream responder was synthetic.

| Source | Tested commit |
| --- | --- |
| JAN Confido | `f081d4d0785d2c044344f0f25e67627cee1e20e9` |
| JAN Attestor | `75b1dd755ed5c18e7ddebb7915da09d43ce2a94b` |
| Confidential AI example | `479cd511440a0d9a7e2ccf637ac010437f296e48` (local) |
| Teraveri Evidence | `900d420b0928c4693e1143aa33a33ab670147e3c` (pinned dependency) |

The Confido and Attestor commits were published to JAN review branches with
GitHub Verified SSH signatures. The example commit was signed locally; its
branch was not published. The example's installed wheels were rebuilt with
`make dev-update` before the successful run. The Attestor debug binary SHA-256
was `3eaa4a48032b460c71ef965cb6b92f752fc46d7b1c3eb70a5bf1125788c23cf4`.

The positive Genoa policy SHA-256 was
`7d3cf06255a691ecec351bfbeaa147317eb2de272a96969d437b051e8aceb3c1`;
the negative policy SHA-256 was
`2933581a0995279e872e78b2bb2e06eb6365777e13aa256905364f5d7920453e`.
The positive policy pinned Teraveri reference commit
`3fa7913d44a377806bd94126589be1feb362b6cb` and reference content SHA-256
`31d1655c424507116f1f39adbbab5d02b35524756fb7c95eb5fce4ca7672086b`.

| Check | Observed result |
| --- | --- |
| Matching reference through installed client wheels | Admitted one synthetic application request. |
| Deliberately incompatible reference | Rejected; zero application requests. |
| Same certificate at another origin | Three targets rejected; zero application requests. |
| Wrong TLS hostname | HTTPS authentication failed; zero application requests. |
| Report collection | Six `/tee-report` requests; none carried application credentials. |

After the split, locked Confido Rust tests (8), installed Python API tests (7),
repository checks (3), Attestor Rust tests (7), launcher tests (8), Attestor
repository checks (4), example application tests (40), and native transport
tests (2) passed. The private acceptance record is retained outside Git at
`/mnt/.artifacts/confido/post-split-genoa-20261124-082245Z/acceptance.json`;
its SHA-256 is
`6facc8a8d091e858e925b25b45f128d440327d72d41d7b6697b210178ab227ef`.

This run did not repeat container or browser acceptance after the split, test
external inference, promote the public deployment, or constitute independent
reproduction. The enrolled reference covers boot aggregate and kernel modules,
not application, model, or GPU state. See the [earlier full local review](acceptance-genoa-review-20261124.md)
for container, replay, and browser checks against its own recorded source state.
