# Confido

Confido obtains a TLS certificate through an attestation exchange and verifies
the AMD SEV-SNP report, TPM quote, boot aggregate, and IMA measurements against
a trusted repository.

## Build

Install stable Rust, Python 3, a C toolchain, OpenSSL build dependencies, and
TPM2-TSS development headers. On Ubuntu:

```sh
sudo apt-get install build-essential pkg-config perl libssl-dev clang libclang-dev libtss2-dev python3-dev python3-venv
```

The Rust manifests fetch `az-snp-vtpm` from the original
[Kinvolk azure-cvm-tooling repository](https://github.com/kinvolk/azure-cvm-tooling)
at the pinned `v0.6.0` revision
`9c6bff6c959994da280f8b3b5bad62a1600063d0`. Confido keeps its SHA-1 and
multi-bank TPM quote support in `lib/src/vtpm.rs`. No sibling checkout is needed:

```sh
cargo build --manifest-path server/Cargo.toml
cargo build --manifest-path client/Cargo.toml
```

## Server and client

Run the server on an Azure SEV-SNP VM with access to its vTPM and IMA log:

```sh
sudo env RUST_LOG=info server/target/debug/confido_server 127.0.0.1:8001 /tmp/confido sha256
# Expose GET /service-info and POST /tee-report on HTTPS port 443.
RUST_LOG=info client/target/debug/confido_client https://your-hostname
```

`server/run.sh [host:port] [certificate-directory] [PCR-bank] [TLS-hostname]`
builds and starts the private report server. Its default address is
`127.0.0.1:8001`. Nginx proxies public `POST /tee-report` to private Confido
`POST http://127.0.0.1:8001/tee-report`. The Go service-info process
advertises this path in `GET /service-info`; clients send a fresh base64 nonce
in a JSON request body over HTTPS port 443. For a
public HTTPS endpoint, pass its DNS name as the fourth argument, for example:

```sh
server/run.sh 127.0.0.1:8001 /tmp/confido sha256 match.demo.genxt.network
```

New certificates include that name in a subject alternative name. If a key and
certificate already exist, the server checks that they match and that the
certificate covers the requested name; provision a replacement pair if it does
not. The certificate must also be served by the HTTPS application. The server
creates private keys with owner-only permissions, restricts an existing key to
owner-only access, and rejects incomplete or mismatched certificate/key pairs. Rust `ATLS` requests retain hostname
verification, trust only the attested certificate as their trust anchor,
require HTTPS, and do not follow redirects. Certificates must cover the
application hostname.

## Python wheel

From the repository root, create and activate a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin>=1.6,<2' patchelf
make -C lib install PYTHON=python
```

`make install` builds the wheel and installs it into the active environment. Use
`make -C lib wheel PYTHON=python` to build without installing. `MATURIN`, `CARGO`,
`PYTHON`, and `MATURIN_FLAGS` can be overridden; the default flags require a
PyPI-compatible wheel. The wheel is written to `lib/target/wheels/`. The
`confido-atls` distribution installs the `confido` module. The example
repository pins version 0.2.0 for its end-user Docker image.

```python
import confido

# Optional; both debug aliases are supported and safe to call repeatedly.
confido.atls_debug()
certificate_der = confido.aTLS_connect_py("https://attestation-host")
# Alternatively, select an explicit trusted repository:
certificate_der = confido.aTLS_connect_py(
    "https://attestation-host", trs_registry="owner/trusted-repository"
)
```

The function returns DER certificate bytes only after verification succeeds and
raises `RuntimeError` on failure. It releases the Python GIL during verification.
Callers must bind their subsequent HTTPS connection to this attested identity;
adding the returned certificate to a general system trust store is insufficient.

## Trusted records and compatibility

The default repository is `genxnetwork/confido-trusted-repository`. Records are
fetched as `bb-attest-<IP>.json`, resolving DNS names to an IP address. For
`localhost` or `127.0.0.1`, the public IP is obtained from ipify. If a hostname has
multiple addresses, the selected address must have the corresponding trusted
record. An optional GitHub token is read from `~/.confido/trs.token`; public
repositories can be used without one.

Each trusted record contains `ima_measurements`. The client requires an exact
match, including order, duplicates, count, filenames, and digest metadata.
Supported templates are `ima-ng` and `ima-sig`; measurements must target PCR 10.
The boot aggregate's `filedata_alg` selects SHA-1 or SHA-256, and that bank must
be present in the signed quote.

PCR 10 is either replayed from trusted template hashes of the selected bank's
digest length, or compared with an explicitly enrolled `pcr10_sha256` value
(64 hexadecimal characters). A SHA-1 template digest cannot be replayed into
the SHA-256 bank. In that case, enroll the expected SHA-256 PCR 10 from a trusted
machine. IMA signatures are covered by their template digest; the verifier does
not reconstruct an `ima-sig` entry with an assumed empty signature.

This update changes the evidence format and quote challenge. The challenge is
`SHA256(nonce || certificate_DER || SHA256(serialized_IMA_measurements))`.
Upgrade the server and all clients together. Old clients or old evidence that
omits `ima_measurements` are incompatible; there is no fallback to unbound data.
The accepted quote layout is a contiguous PCR selection starting at PCR 0 and
including PCR 10, with bank labels and digest lengths checked against the signed
selection. The server currently quotes PCRs 0–23.

GPU evidence is collected when available, but this verifier does not validate
GPU evidence. The upstream dependency verifies the SNP report signature and
requires its reported TCB to equal its committed TCB; additional SNP guest-policy
and minimum TCB acceptance rules are outside this change. The current HCL
parser's panic-prone metadata access is contained at the input boundary under
Rust's default unwind panic strategy.

## Publish the Python wheel to PyPI

The `Publish Python wheel to PyPI` workflow runs when a `pypi-v<version>` tag is
pushed. It checks that the tag, `lib/pyproject.toml`, and `lib/Cargo.toml` have the
same version, builds and tests a Linux CPython 3.10 wheel, then uploads it with
a PyPI API token. The existing `v*` tags remain reserved for RPM releases.

In the GitHub repository, open **Settings → Environments → pypi** (create the
`pypi` environment if needed). Under **Environment secrets**, add a secret named
`PYPI_API_TOKEN` containing the complete PyPI token, including its `pypi-`
prefix. Prefer a token scoped to the `confido-atls` project. If environment
secrets are unavailable for the repository's GitHub plan, add the same name
under **Settings → Secrets and variables → Actions → Repository secrets**.
The workflow reads either location through `secrets.PYPI_API_TOKEN`; do not
commit the token to this repository. The GitHub `pypi` environment is a place
for secrets and deployment rules; it does not configure PyPI Trusted
Publishing. Restrict deployments to `master` and `pypi-v*` tags, and configure
required reviewers if available.

Once the workflow is on the default branch, use its **Run workflow** button on
`master` to check that GitHub received the secret and PyPI accepts the token.
The manual check sends no package and cannot create a release. It does not
confirm the token's permission to upload to `confido-atls`. Before approving
the publish job, run the live release check described below against both the
enrolled and mismatching endpoints. After the release commit is on `master`,
create and push a `pypi-v<version>` tag pointing to that commit to start the
publish workflow.

## Validation

```sh
cargo test --manifest-path lib/Cargo.toml
cargo test --manifest-path server/Cargo.toml
cargo build --manifest-path client/Cargo.toml
python -m unittest discover -s lib/tests -p 'test_*.py' -v
git diff --check
```

Run the Python tests after installing the new wheel into the active environment.
Rust TLS tests and Python tests use localhost sockets. Other regression tests
use synthetic signed TPM quotes and independent PCR vectors; they do not
substitute for a live Azure SEV-SNP attestation check. A live release check must
accept the enrolled endpoint and reject the mismatching endpoint before any
application request.
