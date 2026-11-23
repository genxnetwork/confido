# Third-party material

The root LICENSE applies to Confido's project-authored material. It does not
replace the licences, copyright notices, or attribution requirements of dependencies.

No separately vendored third-party source or existing NOTICE file was identified
in this repository during the licensing review. Dependencies are obtained through
Cargo and the separately cloned `genxnetwork/azure-cvm-tooling` repository.

## Dependencies included in binary releases

- `azure-cvm-tooling`, including `az-snp-vtpm` and `az-cvm-vtpm`, carries the MIT
  licence and Microsoft copyright notices. Its original terms must be retained.
- `ring` includes material derived from BoringSSL, OpenSSL, and other contributors.
  Its complete LICENSE and nested third-party licence files must be retained;
  Confido's Apache-2.0 declaration does not replace them.
- The `openssl` dependency enables `vendored`, so OpenSSL can be compiled into
  distributed binaries. Both the Rust crates' terms and the bundled OpenSSL
  licence files must accompany those releases.
- Other Rust dependencies keep their own terms, including applicable MIT, BSD,
  ISC, Apache, and other licences. The examples above are not a complete inventory.

The RPM workflow creates a separate third-party licence archive for each binary
from its locked Cargo metadata after compilation. It includes the resolved package
inventory and verbatim licence, copyright, author, and notice files found in those
packages, including nested bundled components. For path dependencies, repository
root attribution files are also included. The inventory conservatively includes
resolved build and target-specific dependencies as well as runtime dependencies;
it is not a claim that every listed dependency is linked into the binary.

Each RPM installs this document, the root LICENSE, and that archive's contents
under `/usr/share/licenses/confido-client/` or
`/usr/share/licenses/confido-server/`. Upstream NOTICE files, when present, are
preserved in the corresponding dependency directory. No project-level NOTICE
file is added because the inspected Confido sources establish no requirement
for one.

## Release review

The collector preserves identified files; it does not establish ownership or
licence compatibility. Before publishing a release, review the resolved inventory
and any file-specific terms, confirm the provenance and licensing of changes in
the external Azure tooling fork, and check the aggregate RPM licence expression
against the code actually included. The workflow currently resolves dependency
versions and the external fork anew, so this review must use the release's own
inventory rather than a historical list. Python wheels and other binary formats
also require their own third-party attribution packaging review before publication.
