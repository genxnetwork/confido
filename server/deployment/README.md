# Public routing and installation contract

The canonical demo Nginx configuration is `flint/nginx/flint.conf` in the sibling Flint repository. `nginx-confido.conf` and `../conf/nginx.conf` are synchronized copies for packaging; the preflight checks equality. `systemd-confido.service` is similarly mirrored under `../conf/`.

| Component | Listener | Public route |
|---|---|---|
| Nginx TLS terminator | 443 | `/service-info`, `/tee-report`, `/v1/...` |
| Nginx redirect | 80 | 308 to same-host HTTPS |
| Confido | 127.0.0.1:8001 | POST `/tee-report` |
| Match sidecar | 127.0.0.1:8082 | GET `/service-info` |
| Mismatch sidecar | 127.0.0.1:8083 | GET `/service-info` |
| Flint | 127.0.0.1:4000 | application API |

Both names must appear in `/etc/confido/certificate.pem` SANs. The matching private key is `/etc/confido/private_key.pem`, mode 0600. The collector checks key correspondence and its configured hostname at startup. A newly generated certificate has only the explicitly supplied hostname: provision a two-SAN certificate before starting the public two-name deployment. Keep metrics loopback-only as configured in sidecar `deploy/systemd/*.env.example`.

Install the reviewed binary as `/usr/local/bin/confido-server`; the unit never runs a build-directory binary. Install sidecar 0.3.0 advertisement support and both config files together. Copy the canonical Nginx file after generating the local Basic Auth and gateway-key includes using the Flint operator instructions. Do not commit those secret files. `/aTLS` returns 404; no service listens publicly on 8000/8001/8082/8083.

Run `scripts/preflight.py` before promotion and preserve its output. Stage and test the revised versions on isolated ports first. Review the changed certificate and policy identities before replacing a running installation. Retained baseline identifiers are in `docs/revision/checkpoint.json`.
