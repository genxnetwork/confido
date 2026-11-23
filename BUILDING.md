# Building Confido 0.2

Use the pinned Rust toolchain in `rust-toolchain.toml`. Cargo fetches
`evidence-core` and `evidence-protocol` 0.2.0 from the Teraveri Git commit
pinned in the Confido manifests and lockfiles. No sibling Evidence checkout is
needed. Run commands from the Confido repository root.

```sh
cargo test --locked --manifest-path lib/Cargo.toml
cargo build --locked --manifest-path client/Cargo.toml
cargo test --locked --manifest-path server/Cargo.toml
```

The collector needs TPM2-TSS and the native development packages listed in the
[README](README.md#build-and-test). Unit tests do not require TPM hardware.

For a Python wheel, install maturin 1.15.0 and use the Makefile so that project and
dependency attribution are included:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin==1.15.0' jsonschema
make -C bindings/python install PYTHON=python
python -m unittest discover -s lib/tests -v
python -m unittest discover -s tests -v
python -m unittest discover -s server/tests -v
```

Attribution uses the locked dependency graph for the build target. The helper
defaults to `CARGO_BUILD_TARGET` or the Rust host; `--target` overrides it for
cross-target packaging. The browser build explicitly selects
`wasm32-unknown-unknown`. The example application's `make dev-update` runs the
same helper separately with each project's own licence before building its wheels.

Rust tests that need private functions live in the owning module: short tests
stay inline, while larger suites use a `tests.rs` child module. Installed-wheel
API tests and fixtures live in `lib/tests`; evidence parser and quote tests live
in the [Evidence core repository](https://github.com/teraveri/evidence/blob/900d420b0928c4693e1143aa33a33ab670147e3c/core/src/formats/tests.rs),
while launcher tests live in `server/tests`. Repository-wide build checks live
in `tests`. Browser and replay checks are explicit integration commands under
`scripts`.

`PROFILE=dev` selects a development wheel. Release builds use `PROFILE=release`.
Browser packaging instructions are in [extension/README.md](extension/README.md).
The collector and CLI remain here until the common revision is validated and
Attestor is extracted; see the [revision plan](docs/revision-0.2.md).
