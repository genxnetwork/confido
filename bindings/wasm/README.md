# WebAssembly verifier binding

This crate adapts the same portable verifier for `wasm-bindgen`. It accepts
caller-supplied evidence, policy, nonce, and evaluation time, then returns a
serialized result. It does not perform network collection or application
admission.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Browser-callable verification, requirement inspection, and build metadata. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock` | WASM crate dependencies and the locked build graph. |
| [`build.rs`](build.rs) | Stamps wrapper source identity and build metadata. |

The [browser extension build](../../extension/README.md#build) compiles this
crate, runs `wasm-bindgen`, and packages its output with the local Worker.
Browser behavior is checked by `scripts/browser_checks.py` from the
repository root.
