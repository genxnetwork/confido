"""Deterministic fingerprints of explicit native build inputs (never credentials)."""
import hashlib
from pathlib import Path
import sys


def files(root, scope):
    scopes = {'core': ['lib', 'protocol'], 'python': ['bindings/python'],
              'wasm': ['bindings/wasm'], 'cli': ['client']}
    paths = {root / 'scripts/source_fingerprint.py', root / 'build_support.rs'}
    directories = []
    for relative in scopes[scope]:
        base = root / relative
        directories.append(base / 'src')
        paths.update((base / 'src').rglob('*.rs'))
        paths.update(base / name for name in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'pyproject.toml', 'Makefile') if (base / name).is_file())
    return sorted(paths), directories


def fingerprint(root, scope):
    digest = hashlib.sha256()
    for path in files(root, scope)[0]:
        name = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        digest.update(len(name).to_bytes(8, 'big') + name + len(data).to_bytes(8, 'big') + data)
    return digest.hexdigest()


if __name__ == '__main__':
    root, scope = Path(sys.argv[1]).resolve(), sys.argv[2]
    print(fingerprint(root, scope))
    for path in [*files(root, scope)[0], *files(root, scope)[1]]:
        print(path)
