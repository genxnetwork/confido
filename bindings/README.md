# Verifier language bindings

Both bindings call the same portable [Confido verifier](../lib/). They expose
evidence verification and build metadata; collection, TLS peer authentication,
and application admission remain with callers.

| Directory | Purpose |
| --- | --- |
| [`python/`](python/) | PyO3 wheel published as `confido-verifier`. |
| [`wasm/`](wasm/) | `wasm-bindgen` interface packaged by the browser extension. |

The serialized inputs and results are described in the
[schema catalog](../schemas/README.md).
