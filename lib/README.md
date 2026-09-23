# confido-atls

Python bindings for [Confido](https://github.com/genxnetwork/confido), an attested
TLS client. The distribution is named `confido-atls`; the Python module is named
`confido`.

```sh
python -m pip install confido-atls
```

The release workflow currently builds a Linux x86_64 wheel for CPython 3.10.

```python
import confido

certificate_der = confido.aTLS_connect_py(
    "https://attestation-host",
    trs_registry="owner/trusted-repository",
)
```

`aTLS_connect_py` returns DER certificate bytes after verification succeeds and
raises `RuntimeError` if verification fails. Bind the subsequent HTTPS connection
to the verified certificate. See the [project documentation](https://github.com/genxnetwork/confido)
for setup and the expected evidence format.
