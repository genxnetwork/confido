# Building Confido 0.2

Use the pinned Rust toolchain in `rust-toolchain.toml`. Each package has its own
Cargo manifest and lockfile. Run commands from the repository root.

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
```

`PROFILE=dev` selects a development wheel. Release builds use `PROFILE=release`.
Browser packaging instructions are in [extension/README.md](extension/README.md).
The collector and CLI remain here until the common revision is validated and
Attestor is extracted; see the [revision plan](docs/revision-0.2.md).
