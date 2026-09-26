# Public demo promotion — 2026-09-23

The public match and mismatch hosts were promoted after the isolated revision run.
Both names continue to use HTTPS 443 through Nginx, with HTTP 80 returning 308.
`/service-info` routes to separate sidecars; `/tee-report` routes to one Confido
collector. `/aTLS` returns 404 on both names.

| Component | Source or artifact |
| --- | --- |
| Confido collector | `c1dcd99`; `/usr/local/bin/confido-server` SHA-256 `bac2497a166ba78eda041111030a83d7865ad79495645a8af125bc106889ce93` |
| Service Info sidecar | `f3db79d`; `/usr/local/bin/ga4gh-service-info` SHA-256 `8e72cd61114ca40c1a6847b1430330299a9ccdab263b35d095d589263631b7f9` |
| Chat client | `958a1c0`; installed wheel SHA-256 `d679557e1fa14ab41413180b473565e6d923d574f8a02828618687f3dbf46327` |
| Chat image | `confidential-ai-example:0.3.0`, image ID `sha256:fdc81dacb4776c54f7fedab834ce08c274d483fb8b8cc2ca72be76a13b6cb5f2` |

Both public Service Info responses advertise `azure-snp-vtpm-ima/1`,
`wireVersion: 1`, `POST /tee-report`, and `sessionBinding.supported: false`.
Their top-level software version is `0.3.0`; chat API `type.version` remains
`0.2.0`.

A public CA-issued leaf certificate could not be used as a local root CA by
the initial 0.3.0 client. Commit `c1dcd99` pins the exact attested leaf on every
TLS connection and checks the hostname and certificate validity. The TLS
handshake signature is still verified by rustls. This fix accepts the public
CA-issued certificate without widening the attestation trust boundary.

Read-only online preflight completed with `reference_match` and HTTPS peer
authentication on the match host. Direct local and container checks returned
`reference_match` with application admission for match, and
`measurement_mismatch` with no application admission for mismatch. These checks
did not send application credentials or inference requests. The corrected
verifier also has a focused test for certificate substitution, wrong hostname,
and expiration. All four service units (collector, both sidecars, Nginx) were
active after promotion.

The operator backup of the previous sidecar binary, metadata files and
collector unit is root-only under `/tmp/confido-public-upgrade-20260923`.
