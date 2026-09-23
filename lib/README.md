# confido-atls 0.3.0

Rust/Python execution-environment evidence verification and reference appraisal.
Distribution: `confido-atls`; import: `confido`. Frozen wheel target: Linux
x86_64 / CPython 3.10. Build with `make wheel`; no PyPI publication is required.

Use `discover_py(policy_json)` for bootstrap metadata, then
`connect_py(policy_json, preview_json, optional_new_bundle_path)` for live
appraisal and HTTPS authentication. The returned `AttestedSession.result_json`
contains stages, stable reasons, fingerprints, reference identity, bindings,
coverage and timings. Only admitted sessions can issue origin-scoped requests.

`appraise_offline_py(bundle_json, policy_json, evaluation_unix_time)` returns a
historical result and cannot authorize a new application connection.

The bounded profile covers AMD Milan SNP/HCL/vTPM evidence and enrolled IMA
state. TLS session binding, GPU appraisal and continuous/server-side capability
enforcement are unsupported. The current demonstration log covers a boot
aggregate and kernel modules; external inference is outside its scope.

The old `aTLS_connect_py(host, trs_registry=None)` function remains a legacy
mutable-reference compatibility API returning DER certificate bytes. It does
not enforce the full 0.3.0 profile or origin-scoped admission. New integrations
should use the typed API. See the repository README for build and deployment.

Confido licence metadata awaits an owner decision before an open release.
