# Confido CLI

This crate is a caller-side utility for collecting evidence, verifying supplied
inputs, and replaying saved archives. The verifier remains in [`lib/`](../lib/);
this CLI does not make an application admission or authenticate a later
application connection.

| File | Role |
| --- | --- |
| [`src/main.rs`](src/main.rs) | Implements `collect`, `appraise`, `verify`, `replay`, and `migrate-archive`; handles bounded HTTP input and local archives. |
| [`build.rs`](build.rs) | Stamps build metadata and the CLI source fingerprint. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock` | Crate dependencies and the locked build graph. |
| [`specs/confido-cli.spec`](specs/confido-cli.spec) | RPM packaging recipe. |

Build from the repository root with
`cargo build --locked --manifest-path client/Cargo.toml`. The
[root CLI guide](../README.md#cli) lists each command and its arguments.
Application and verifier policies for the demo are owned by
`confidential-ai-example/profiles/`, not by this crate.
