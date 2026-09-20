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

The Rust manifests expect the
[GENXT azure-cvm-tooling fork](https://github.com/genxnetwork/azure-cvm-tooling)
in a sibling directory. The tested revision is
`64c4ef852132642c0da6a6c8918c51dfafa87ddb`:

```sh
git clone https://github.com/genxnetwork/azure-cvm-tooling ../azure-cvm-tooling
git -C ../azure-cvm-tooling checkout 64c4ef852132642c0da6a6c8918c51dfafa87ddb
cargo build --manifest-path server/Cargo.toml
cargo build --manifest-path client/Cargo.toml
```

## Server and client

Run the server on an Azure SEV-SNP VM with access to its vTPM and IMA log:

```sh
sudo env RUST_LOG=info server/target/debug/confido_server 127.0.0.1:8000 /tmp/confido sha256
RUST_LOG=info client/target/debug/confido_client http://127.0.0.1:8000
```

`server/run.sh [host:port] [certificate-directory] [PCR-bank]` builds and starts
the server, using the same defaults. The certificate must also be served by the
HTTPS application. Rust `ATLS` requests retain hostname verification, trust only
the attested certificate as their trust anchor, require HTTPS, and do not follow
redirects. Certificates must cover the application hostname.

## Python wheel

From the repository root, create and activate a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin>=1.6,<2' patchelf
make -C lib wheel PYTHON=python
make -C lib install PYTHON=python
```

`MATURIN`, `PYTHON`, and `MATURIN_FLAGS` can be overridden. The wheel is written
to `lib/target/wheels/`; it installs the `confido` module. This local distribution
is distinct from the example repository's existing `confido-atls` PyPI pin.
Install the built wheel explicitly when testing these changes.

```python
import confido

# Optional; both debug aliases are supported and safe to call repeatedly.
confido.atls_debug()
certificate_der = confido.aTLS_connect_py("http://attestation-host:8000")
# Alternatively, select an explicit trusted repository:
certificate_der = confido.aTLS_connect_py(
    "http://attestation-host:8000", trs_registry="owner/trusted-repository"
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
GPU evidence. The dependency verifies the SNP report signature; additional SNP
guest-policy and TCB acceptance rules are outside this change. The current HCL
parser's panic-prone metadata access is contained at the input boundary under
Rust's default unwind panic strategy.

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
