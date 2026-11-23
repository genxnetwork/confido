# Python verifier binding

This PyO3 crate builds the `confido-verifier` wheel. It converts Python byte
inputs and explicit verification context into the portable Rust verifier's
types. It does not collect evidence or open application connections.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | `verify`, `inspect_requirements`, and `build_info` Python functions. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock`, [`pyproject.toml`](pyproject.toml) | Native dependencies, locked graph, and wheel metadata. |
| [`build.rs`](build.rs) | Stamps the wrapper's source fingerprint and build metadata. |
| [`Makefile`](Makefile) | Prepares attribution files, builds the wheel, and optionally installs it. |
| `licenses/`, `dist/` | Generated attribution files and wheel output; both are ignored by Git. |

Follow the [repository build guide](../../BUILDING.md) to build and test the
installed wheel. The public Python API is exercised by
[`lib/tests/test_verifier_api.py`](../../lib/tests/test_verifier_api.py).
