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
    import confido
    if getattr(confido, "__version__", None) != "0.3.0":
        raise SystemExit("FAIL: stale wheel; expected Confido 0.3.0")
    print("PASS: installed Confido 0.3.0")
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
        policy = json.loads(args.policy.read_text())
        preview = confido.discover_py(json.dumps(policy))
        # This also authenticates the exact hostname and critical metadata.
        session = confido.connect_py(json.dumps(policy), preview)
        result = json.loads(session.result_json)
        print(json.dumps(result, indent=2))
        if not result["application_admitted"]:
            raise SystemExit("FAIL: appraisal/HTTPS preflight withheld admission")
        for path, expected in [("/aTLS", 404)]:
            status, _, _ = session.request("GET", policy["origin"] + path, [], b"")
            if status != expected:
                raise SystemExit(f"FAIL: retired route {path}: HTTP {status}")
        print("PASS: compatible report, intended HTTPS peer and retired /aTLS route")
    print("Preflight complete; no application credential or inference request sent.")


if __name__ == "__main__":
    main()
