"""Deterministic fingerprints of explicit native build inputs (never credentials)."""

import hashlib
import os
import sys
from pathlib import Path


def files(root, scope):
    evidence = root.parent / "evidence"
    scopes = {
        "core": [root / "lib", evidence / "protocol", evidence / "core"],
        "python": [root / "bindings/python"],
        "wasm": [root / "bindings/wasm"],
        "cli": [root / "client"],
    }
    paths = {
        root / "scripts/source_fingerprint.py",
        root / "build_support.rs",
        evidence / "Cargo.toml",
        evidence / "Cargo.lock",
    }
    directories = []
    for base in scopes[scope]:
        directories.append(base / "src")
        paths.update((base / "src").rglob("*.rs"))
        paths.update(
            base / name
            for name in (
                "Cargo.toml",
                "Cargo.lock",
                "build.rs",
                "pyproject.toml",
                "Makefile",
            )
            # Workspace members share ../evidence/Cargo.lock. A transient lockfile
            # created by a standalone member command is not a build input.
            if not (base.is_relative_to(evidence) and name == "Cargo.lock")
            if (base / name).is_file()
        )
    return sorted(paths), directories


def fingerprint(root, scope):
    digest = hashlib.sha256()
    for path in files(root, scope)[0]:
        # Relative labels keep the digest independent of the checkout's
        # absolute location, including the adjacent evidence repository.
        name = os.path.relpath(path, root).replace(os.sep, "/").encode()
        data = path.read_bytes()
        digest.update(
            len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data
        )
    return digest.hexdigest()


if __name__ == "__main__":
    root, scope = Path(sys.argv[1]).resolve(), sys.argv[2]
    print(fingerprint(root, scope))
    for path in [*files(root, scope)[0], *files(root, scope)[1]]:
        print(path)
