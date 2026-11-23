#!/usr/bin/env python3
"""Read-only deployment preflight; never sends credentials or inference requests."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--flint", type=Path, default=ROOT.parent / "flint")
    args = parser.parse_args()
    import confido_verifier
    if getattr(confido_verifier, "__version__", None) != "0.2.0":
        raise SystemExit("FAIL: stale wheel; expected Confido 0.2.0")
    print("PASS: installed Confido 0.2.0")
    fixture = ROOT / "protocol/fixtures/tee-report-advertisement-v1.json"
    sidecar_fixture = ROOT.parent / "ga4gh_service_info_sidecar_gsoc_2026/internal/handler/testdata/tee-report-advertisement-v1.json"
    if sidecar_fixture.exists() and fixture.read_bytes() != sidecar_fixture.read_bytes():
        raise SystemExit("FAIL: sidecar/protocol wire fixture drift")
    canonical = (args.flint / "nginx/flint.conf").read_bytes()
    for relative in ["server/conf/nginx.conf", "server/deployment/nginx-confido.conf"]:
        if (ROOT / relative).read_bytes() != canonical:
            raise SystemExit(f"FAIL: routing template drift: {relative}")
    print("PASS: synchronized Nginx routing; sha256=" + hashlib.sha256(canonical).hexdigest())
    if (ROOT / "server/conf/systemd.service").read_bytes() != (ROOT / "server/deployment/systemd-confido.service").read_bytes():
        raise SystemExit("FAIL: systemd template drift")
    print("PASS: synchronized collector unit")
    if args.online:
        if not args.policy:
            parser.error("--online requires --policy")
        import sys
        sys.path.insert(0, str(ROOT.parent / "confidential-ai-example"))
        from demo import collection, admission
        policy = collection.load_policy(args.policy)
        preview = collection.discover(policy)
        result, _ = collection.collect_and_verify(policy, preview)
        session = admission.authenticate(policy, preview, result)
        print(json.dumps(result, indent=2))
        for path, expected in [("/aTLS", 404)]:
            status, _, _ = session.request("GET", policy["origin"] + path, [], b"")
            if status != expected:
                raise SystemExit(f"FAIL: retired route {path}: HTTP {status}")
        print("PASS: compatible report, intended HTTPS peer and retired /aTLS route")
    print("Preflight complete; no application credential or inference request sent.")


if __name__ == "__main__":
    main()
