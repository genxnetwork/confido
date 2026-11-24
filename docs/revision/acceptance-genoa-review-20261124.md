# Local Genoa review run, 2026-11-24 (Asia/Yerevan)

An isolated run on the current Azure Genoa VM exercised the direct attestation
endpoint, installed verifier and transport wheels, and a rebuilt local container.
The host ran kernel `6.8.0-1071-azure-fde`. The run started at
`2026-11-23T23:04:24Z` and ended at `2026-11-23T23:04:43Z` (the following day
in Asia/Yerevan). The downstream chat responder was synthetic. No public listener
was promoted and no external inference was evaluated.

The source worktrees were **not committed at this checkpoint**. Confido HEAD was
`92a1d8fda0cb15c5abf14612cdd9dddd7b74a212`; the example HEAD was
`1f950d06cc0dabfa0f7981d1004fd6090d73359c`. The runtime and browser
packages identify the tested source by these fingerprints:

| Source scope | SHA-256 |
| --- | --- |
| Confido core, including the Evidence Git pin | `d0f72ee3826eaad07524539053e263a3cea930fb82ce50e351c4fe0ae779d316` |
| Confido Python wrapper | `b63d877f50948a1c9bbd9ae95851c1fad0683f96e70396baa5a34d56863f7b9c` |
| Example native transport | `e4e756de34200bc4c07ada75ee19b778d6d7bd88a0f4e1d2887cfdfd1cf97c78` |
| Example application | `27f43924fb644c6e6ab8892c6dca0d75d17317ee359b3caa04d60c8b5bd87199` |
| Browser WASM wrapper | `d054fc36f6c7709216859f224f8404f40f1f35f4128f279fd14fb3ef801d65e6` |
| Browser caller assets | `d3b18ec0f0c51eed5e043e5a037a1a422e838b9e3080d07f50bf6427e3774b3c` |

The Confido verifier and native collector builds used the published Teraveri
Evidence commit `900d420b0928c4693e1143aa33a33ab670147e3c`. The positive
policy SHA-256 was `7d3cf06255a691ecec351bfbeaa147317eb2de272a96969d437b051e8aceb3c1`;
the negative policy SHA-256 was
`2933581a0995279e872e78b2bb2e06eb6365777e13aa256905364f5d7920453e`.
The positive policy was reproduced byte for byte from the clean Teraveri
registry at commit `3fa7913d44a377806bd94126589be1feb362b6cb`, using the
locally pinned one-use GENXT manual publisher statement.

| Check | Observed result |
| --- | --- |
| Fresh hardware evidence with matching reference | 12 verifier checks passed; installed-wheel client admitted one synthetic application request |
| Deliberately incompatible reference | Rejected; zero application requests |
| Same certificate at another origin | Three targets rejected before application traffic |
| Wrong TLS hostname | Rejected before application traffic |
| Rebuilt local container | Match sent one synthetic request; mismatch sent zero |
| Report collection | Nine `/tee-report` requests; none carried application credentials |
| Measurement coverage | 45 IMA entries: one boot aggregate and 44 kernel modules |

The private positive archive then passed 27 negative and consistency replay
cases. Thirty local appraisals had p95 `2.85 ms`; collection, KDS, registry and
network time are excluded. Seven current-hardware cases produced identical
results in the CLI, installed Python package, Chromium WASM and Firefox WASM.
The installed Chromium extension passed worker, CSP, replay and stale-asset
rejection checks.

Locked tests passed for Evidence (10), the Confido verifier (8), collector (7),
installed Python API (7), collector launcher (7), Confido repository build
checks (3), example application (40), and native transport (2). The reference
registry (5) and GENXT publisher tooling (6) tests passed. The current verifier
and transport wheels contain their project licence, notices and locked
dependency attribution. Local CLI and collector attribution archives were
generated from their Linux dependency graphs. Actual RPM creation was not
tested on this VM because `rpmbuild` is unavailable.

The rebuilt image was
`sha256:9899a2c84fc8a251b59935296e53bf5a41408caaede3ce3b18ecb177ec5eb478`.
The verifier wheel SHA-256 was
`38844b106884da46db91dd43e21518ad1134f7c13a4c7499f2620b6dc8d8da1b`;
the transport wheel SHA-256 was
`faef8fa94a39b4d0334dcaca8fed463d6fd90e1d38bc4792833eb5e81be93073`.
The private acceptance record SHA-256 is
`40d46672e9f248159102abc04771b24e7b2ff83f04431be53c827b4346b0a56d`;
the replay record SHA-256 is
`60c88f82cdd2300b8def1561ca47a138a369efccf4129f49492454b43bf6c838`.
Raw archives, certificates and logs remain outside Git.

This run establishes local behavior for the identified artifacts. A signed,
clean commit, independent reproduction, public deployment, automated publisher
OIDC path, TLS session binding, and application/model/GPU or external inference
measurement remain separate work. A release or grant review should cite the
final committed source identity and rerun affected checks if executable source
changes after this record.
