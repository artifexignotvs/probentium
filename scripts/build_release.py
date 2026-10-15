#!/usr/bin/env python3
"""Fasciculi sine nominibus loci et sine tempore variabili parantur."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 315532800


def main():
    parser = argparse.ArgumentParser(description="Build local candidates with normalized archive owner and time metadata. Requires the build package.")
    parser.add_argument("--output", type=Path, required=True, help="New destination directory")
    args = parser.parse_args()
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="testifex-build-") as temporary:
        staging = Path(temporary)
        subprocess.run([sys.executable, "-m", "build", "--sdist", "--wheel", "--no-isolation", "--outdir", str(staging)],
                       cwd=ROOT, env=dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH)), check=True)
        for path in sorted(staging.iterdir()):
            target = destination / path.name
            if path.name.endswith(".tar.gz"):
                with tarfile.open(path, "r:gz") as source:
                    with target.open("xb") as output:
                        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=EPOCH) as compressed:
                            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                                for member in source.getmembers():
                                    member.uid = member.gid = 0
                                    member.uname = member.gname = ""
                                    member.mtime = EPOCH
                                    member.pax_headers = {}
                                    content = source.extractfile(member) if member.isfile() else None
                                    archive.addfile(member, content)
                                    if content is not None:
                                        content.close()
            else:
                with target.open("xb") as output:
                    output.write(path.read_bytes())
    lines = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name
             for path in sorted(destination.iterdir()) if path.is_file()]
    (destination / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
