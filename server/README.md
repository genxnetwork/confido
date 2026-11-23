# Confido evidence collector

This native component reads AMD SEV-SNP, vTPM, and IMA evidence on a compatible
host. `POST /tee-report` accepts a challenge and returns collected evidence;
`HEAD /tee-report` is the credentialless endpoint used by callers to probe the
appraised TLS peer. Before returning evidence, the collector calls
[`evidence-core/`](../evidence-core/README.md) to reject inconsistent snapshots.
Evidence appraisal belongs to [`lib/`](../lib/).

| File | Role |
| --- | --- |
| [`src/main.rs`](src/main.rs) | HTTP routes, challenge-bound collection, certificate handling, and server startup. |
| [`src/collector.rs`](src/collector.rs) | Host SNP/vTPM collection, including the multi-bank TPM quote path. |
| [`src/tests.rs`](src/tests.rs), [`tests/test_launcher.py`](tests/test_launcher.py) | Internal collector tests and launcher behavior tests. |
| [`run.sh`](run.sh), [`stop_existing.py`](stop_existing.py) | Local launcher and replacement of a conflicting Confido listener. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock`, [`specs/confido-server.spec`](specs/confido-server.spec) | Locked native build and RPM packaging. |

From the repository root, run
`cargo test --locked --manifest-path server/Cargo.toml` and
`python3 -m unittest discover -s server/tests -v`.
The [build guide](../BUILDING.md) lists native prerequisites.
`server/run.sh` builds the collector, validates its certificate configuration,
then stops a conflicting Confido listener and starts the new process with
`sudo`. Review its target address and certificate directory before use.
