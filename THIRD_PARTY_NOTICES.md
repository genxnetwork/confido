# Third-party notices and licence decisions

- `azure-cvm-tooling` / `az-snp-vtpm`, pinned commit `9c6bff6c959994da280f8b3b5bad62a1600063d0`: Microsoft/Kinvolk, MIT licence. `lib/src/vtpm.rs` retains the Microsoft copyright/MIT notice; Confido modifications add multi-bank collection and expose the quote data used by the verifier. [Preserved upstream licence](third_party/azure-cvm-tooling-LICENSE).
- GA4GH Service Info schema v1.0.0: Apache 2.0, as declared in the preserved schema. Exact source and SHA-256 are recorded in `schemas/provenance.json`; its licence is preserved in `schemas/GA4GH-LICENSE`.
- The sibling Service Info sidecar and chat example retain their own existing licence files. They are separate components; reuse does not assign their licence to Confido.
- Cargo lockfiles identify additional Rust dependencies and the wheel bundles TPM2-TSS marshaling support when required by its Linux ABI. Dependency licences remain their authors' terms. Python requirements identify SDK/transport dependencies separately.

## Pending owner decision

Confido has no repository-wide licence file and its existing RPM recipes label it proprietary. A software owner must decide the intended repository/package licence before publication or a claim of open licensing. No new licence is inferred or granted by this revision. Existing historical notices are preserved; no package or image is published by this work.
