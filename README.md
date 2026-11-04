# Confido

Confido is an attested TLS research prototype developed by [GENXT](https://www.genxt.network/). The current implementation combines server-side evidence collection with client-side verification.

## Status

Active development of the original prototype ended in May 2025. The work raised questions about binding attestation evidence to the TLS peer, appraising a remote system's state end to end, and providing post-attestation state assurance. Subsequent research informs the proposed rework. The background and licensing rationale are set out in [issue #8](https://github.com/genxnetwork/confido/issues/8).

## Planned direction

The proposed rework separates server-side attestation (the [RATS Attester](https://www.rfc-editor.org/rfc/rfc9334.html#section-7.2)) from verification (the [RATS Verifier](https://www.rfc-editor.org/rfc/rfc9334.html#section-7.4)). Confido is intended to focus on the Verifier role and appraise evidence using extended execution-trust models, including post-attestation state assurance. Trust reconstruction and capability authority are planned as separate, complementary modules. This architecture is not yet implemented in the prototype.

[JAN DIGITRUST](https://www.jandigitrust.org/) plans to develop the verifier downstream and contribute changes back to this repository. Related work on formal security analysis and programmatic trust management is underway through the [GA4GH GIF TRE Open Suite](https://www.ga4gh.org/gif_project/19991/).

## Repository layout

- `lib/` — library code
- `server/` — server-side prototype
- `client/` — client-side prototype

Build requirements and commands for the current prototype are in [BUILDING.md](BUILDING.md).

## Open development

A verifier informs decisions about whether to trust an attested system. Its appraisal logic should therefore be inspectable. The verifier core is intended to remain open as shared trust infrastructure, while products and services can build on it.

## Licence

Unless otherwise indicated, project-authored files in this repository are licensed under the [Apache License, Version 2.0](LICENSE). Third-party components and dependencies retain their own licences.
