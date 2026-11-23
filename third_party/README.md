# Preserved third-party attribution

This directory holds licence material needed to document upstream code and
resolved dependencies. It is not a vendored source tree.

| Path | Purpose |
| --- | --- |
| [`azure-cvm-tooling-LICENSE`](azure-cvm-tooling-LICENSE) | Preserved MIT terms for the collector's upstream Azure SNP/vTPM material. |
| [`asn1-rs-impl-0.2.0/`](asn1-rs-impl-0.2.0/) | Preserved upstream licences and pinned provenance for dependency attribution. |
| [`alloc-stdlib-0.2.4/`](alloc-stdlib-0.2.4/), [`impl-more-0.3.5/`](impl-more-0.3.5/), [`yasna-0.4.0/`](yasna-0.4.0/) | Licence files omitted from the published crates, preserved from their recorded upstream commits for collector packaging. |

[`scripts/collect_licenses.py`](../scripts/collect_licenses.py) verifies the
recorded hashes when it uses supplemental licence files. The release-level
attribution and its limits are described in the
[third-party notices](../THIRD_PARTY_NOTICES.md).
