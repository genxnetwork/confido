# Genoa manual-reference stage acceptance, 2026-11-23

The isolated live VM run passed with the JAN verifier policy pinned to the
public Teraveri PR #1 head commit
`1653e184df49bcbe1e5b6438069860757a2619c3`. The recorded result is
[`acceptance-genoa-manual-20261123.json`](acceptance-genoa-manual-20261123.json)
(SHA-256 `1e55c4df53f36b9c7b7c263b830b312f4f8c19dac62452882cf1980a302795e0`).
The positive Genoa SNP/TPM/IMA case admitted one request to the synthetic
responder. The mismatched reference denied the request. Cross-origin, wrong TLS
hostname, changed service identity and credential-free appraisal checks also
passed. This test does not evaluate inference, application/model measurement,
or a public deployment.

The run used GENXT publisher commit
`66521651cb2bd56739cb4717af8ff149e7e1ccc7` and JAN policy commit
`5907c7f25ef02522f6e64609a5cfe7818113a2ef`. The manifest SHA-256 was
`9e894415cd892a01a99b679cbac311ea6ba8648fc010c0bf5ffe854d735234e0`;
the reference SHA-256 was
`31d1655c424507116f1f39adbbab5d02b35524756fb7c95eb5fce4ca7672086b`.

| Tested artifact | SHA-256 |
| --- | --- |
| JAN verifier policy | `588f262f5cee781835ea8f7b6727c45dfad0e990c9106ab41d9e6b28016ddb26` |
| JAN issuer policy | `0a4e3c920d44703ac050ea1cd27d8d5665b10a59f5a2706bc408e3898c7cfeb7` |
| GENXT manual bundle in Teraveri | `7ff61612ec617407dc3df51fee79a3a975fabc4654c7021075d6b8288a9cb92b` |
| Stage sidecar binary | `8e72cd61114ca40c1a6847b1430330299a9ccdab263b35d095d589263631b7f9` |
| Confido report server binary | `4c74a37eb829c5eaa22ee3ea43d1b524e9e638126369cd09cd51b3e11c6fd367` |
| Confido verifier wheel | `447dd2df0679a468e60b1f89048e6772e43b965e5d9dede0612264a2bd176a3b` |
| Client transport wheel | `6f26cce1e811dcc9fdc3b9d34901001c82b491e9956850513f2acb64574305b8` |

The client and sidecar source checkouts had uncommitted prior revision work.
The client runtime manifest recorded source fingerprints for core
`deb49eda214bf4cdaf9a7b5345d37a42a13745c5eb87c18bcd7916c5f3121628`,
Python wrapper `9a9f546cea952d82fb722a3b929792d9b25507e29d6faa5af60e95df3dcb4458`,
transport `f35394681a5d2b29fd2c95709b1618a48f073730d2d281b42689c57852c1122a`,
and application `bf0e27c9327cc2594eae4dde5f2ba9341096782299f8f0ee24555a6dd037bff9`.
After Teraveri PR #1 merges, regenerate the policy against the resulting
`main` commit and repeat the live test before claiming that specific revision
as accepted.
