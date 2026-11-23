#!/usr/bin/env python3
"""Package WASM locally; an optional caller config selects live service hosts."""
import argparse
import json
import hashlib
import re
import sys
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit
root = Path(__file__).resolve().parent
p = argparse.ArgumentParser(); p.add_argument('--browser', choices=['chromium', 'firefox', 'safari'], default='chromium'); p.add_argument('--wasm-bindgen', default='wasm-bindgen'); p.add_argument('--services-config', type=Path, help='JSON file with locally approved live origins and service IDs'); args = p.parse_args()
config_bytes = args.services_config.read_bytes() if args.services_config else None
config = json.loads(config_bytes) if config_bytes is not None else {'services': []}
if not isinstance(config, dict) or set(config) != {'services'} or not isinstance(config['services'], list) or len(config['services']) > 16:
    raise SystemExit('Invalid services configuration')
services = config['services']
origins = set()
for service in services:
    if not isinstance(service, dict) or set(service) != {'origin', 'service_id'}:
        raise SystemExit('Invalid service entry')
    origin, service_id = service['origin'], service['service_id']
    if not isinstance(origin, str) or not isinstance(service_id, str):
        raise SystemExit('Invalid service entry fields')
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SystemExit('Service origin must be a bare HTTPS DNS origin') from exc
    valid_host = host is not None and all(
        re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
        for label in host.split('.')
    )
    if (parsed.scheme != 'https' or not valid_host or port is not None or
            parsed.username or parsed.password or parsed.path or parsed.query or
            parsed.fragment or origin != f'https://{parsed.netloc}'):
        raise SystemExit('Service origin must be a bare HTTPS DNS origin')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,255}', service_id) or origin in origins:
        raise SystemExit('Invalid or duplicate service identity')
    origins.add(origin)
sys.path.insert(0, str(root.parent/'scripts'))
from source_fingerprint import fingerprint
from prepare_attribution import prepare
before = {"core_source_sha256": fingerprint(root.parent, "core"),
          "wrapper_source_sha256": fingerprint(root.parent, "wasm")}
source_files = [root/'build.py', *sorted((root/'src').glob('*'))]
def caller_fingerprint():
    digest = hashlib.sha256()
    for path in source_files:
        digest.update(path.relative_to(root).as_posix().encode() + b'\0' + path.read_bytes())
    return digest.hexdigest()
caller_before = caller_fingerprint()
subprocess.run(['cargo', 'build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--manifest-path', str(root.parent/'bindings/wasm/Cargo.toml')], check=True)
out = root/'dist'/args.browser; out.mkdir(parents=True, exist_ok=True)
prepare(root.parent/'bindings/wasm/Cargo.toml', out/'licenses')
shutil.copytree(root/'src', out, dirs_exist_ok=True)
(out/'config.js').write_text('export const SERVICES = ' + json.dumps(services, separators=(',', ':')) + ';\n')
subprocess.run([args.wasm_bindgen, str(root.parent/'bindings/wasm/target/wasm32-unknown-unknown/release/confido_wasm.wasm'), '--target', 'web', '--out-dir', str(out/'wasm'), '--out-name', 'confido_verifier'], check=True)
manifest = {'manifest_version': 3, 'name': 'Confido Evidence Verifier', 'version': '0.2.0', 'description': 'Local evidence verification against your selected policy.', 'action': {'default_title': 'Verify evidence'}, 'optional_host_permissions': [*[origin + '/*' for origin in sorted(origins)], 'https://kdsintf.amd.com/*', 'https://api.github.com/*'], 'content_security_policy': {'extension_pages': "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"}}
manifest['background'] = {'service_worker': 'background.js'} if args.browser == 'chromium' else {'scripts': ['background.js']}
if args.browser == 'firefox': manifest['browser_specific_settings'] = {'gecko': {'id': 'confido-verifier@genxt.network', 'strict_min_version': '128.0'}}
(out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n'); print(out)

after = {"core_source_sha256": fingerprint(root.parent, "core"),
         "wrapper_source_sha256": fingerprint(root.parent, "wasm")}
if before != after or caller_before != caller_fingerprint() or (args.services_config and args.services_config.read_bytes() != config_bytes):
    raise SystemExit("Sources changed during extension build; rebuild required")
assets = {path.relative_to(out).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
          for path in [out/'worker.js', out/'ui.js', out/'collection.js', out/'config.js', out/'wasm/confido_verifier.js', out/'wasm/confido_verifier_bg.wasm']}
(out/'runtime-manifest.json').write_text(json.dumps({"pipeline_revision": 2, **before,
    "caller_source_sha256": caller_before, "assets": assets}, indent=2)+'\n')
