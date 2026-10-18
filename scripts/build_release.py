#!/usr/bin/env python3
"""Fasciculi sine nominibus loci et sine tempore variabili parantur."""
import argparse
import copy
import gzip
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 315532800


def _member_mode(mode, directory):
    """Modus archivarius a persona aedificantis non pendet."""
    expected = stat.S_IFDIR if directory else stat.S_IFREG
    if stat.S_IFMT(mode) not in (0, expected):
        raise ValueError("unsupported_archive_member_type")
    permissions = 0o755 if directory or mode & 0o111 else 0o644
    return expected | permissions


def normalize_wheel(path, target):
    """Permissa interna ordinantur; permissa fontium intacta manent."""
    with zipfile.ZipFile(path) as source, target.open("xb") as output:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for original in source.infolist():
                member = copy.copy(original)
                directory = member.is_dir()
                mode = _member_mode(member.external_attr >> 16, directory)
                member.create_system = 3
                member.external_attr = (mode << 16) | (0x10 if directory else 0)
                archive.writestr(member, source.read(original), compresslevel=9)


def normalize_sdist(path, target):
    """Nomina dominorum, tempora et permissa in fasciculo figuntur."""
    with tarfile.open(path, "r:gz") as source, target.open("xb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for original in source.getmembers():
                    if not (original.isdir() or original.isfile()):
                        raise ValueError("unsupported_archive_member_type")
                    member = copy.copy(original)
                    member.mode = _member_mode(member.mode, member.isdir()) & 0o777
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = EPOCH
                    member.pax_headers = {}
                    content = source.extractfile(original) if member.isfile() else None
                    try:
                        archive.addfile(member, content)
                    finally:
                        if content is not None:
                            content.close()


def main():
    parser = argparse.ArgumentParser(description="Build local candidates with normalized archive owner, time, and permission metadata. Requires the build package.")
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
                normalize_sdist(path, target)
            elif path.suffix == ".whl":
                normalize_wheel(path, target)
            else:
                with target.open("xb") as output:
                    output.write(path.read_bytes())
    lines = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name
             for path in sorted(destination.iterdir()) if path.is_file()]
    (destination / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
