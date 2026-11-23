"""Prepare project and resolved dependency attribution for a binary package."""

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from collect_licenses import collect

ROOT = Path(__file__).resolve().parents[1]


def prepare(manifest, destination):
    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
                str(manifest),
            ],
            text=True,
        )
    )
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(ROOT / name, destination / name)
    collect(metadata, destination / "third-party-licenses.tar.gz")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    prepare(args.manifest.resolve(), args.destination.resolve())
