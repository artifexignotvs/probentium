#!/usr/bin/env python3
"""Rotae iam acquisitae sine rete ordinantur et digeruntur."""
import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile

RUNTIME = {"rfc8785": "0.1.4", "cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.11"}
BUILD = {"build": "1.3.0", "setuptools": "80.9.0", "wheel": "0.45.1",
         "packaging": "26.3", "pyproject-hooks": "1.3.3"}
MAX_WHEEL = 64 * 1024 ** 2
MAX_TOTAL = 512 * 1024 ** 2
MAX_FILES = 128


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def digest(path):
    value = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_WHEEL:
                raise ValueError("file_hash_size_limit")
            value.update(block)
    return value.hexdigest()


def inspect_wheel(path):
    """Metadatum legitur; nullum membrum extrahitur aut exsequitur."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WHEEL:
        raise ValueError("wheel_file_or_size_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.+\-]+\.whl", path.name):
        raise ValueError("wheel_filename_invalid")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 100000 or len({member.filename for member in members}) != len(members):
            raise ValueError("wheel_member_limit_or_duplicate")
        metadata = [member for member in members if re.fullmatch(r"[^/]+\.dist-info/METADATA", member.filename)]
        wheel = [member for member in members if re.fullmatch(r"[^/]+\.dist-info/WHEEL", member.filename)]
        if len(metadata) != 1 or len(wheel) != 1 or metadata[0].file_size > 1024 ** 2 or wheel[0].file_size > 65536:
            raise ValueError("wheel_metadata_invalid")
        message = BytesParser().parsebytes(archive.read(metadata[0]))
        wheel_data = BytesParser().parsebytes(archive.read(wheel[0]))
        for field in ("Name", "Version"):
            if len(message.get_all(field, [])) != 1:
                raise ValueError("wheel_identity_invalid")
        name, version = normalized(message["Name"]), message["Version"]
        if name not in RUNTIME | BUILD or version != (RUNTIME | BUILD)[name]:
            raise ValueError("wheel_not_in_pinned_set")
        parts = path.name[:-4].split("-")
        if len(parts) not in (5, 6) or normalized(parts[0]) != name or parts[1] != version:
            raise ValueError("wheel_filename_identity_mismatch")
        expected_prefix = parts[0] + "-" + version + ".dist-info/"
        if metadata[0].filename != expected_prefix + "METADATA" or wheel[0].filename != expected_prefix + "WHEEL":
            raise ValueError("wheel_metadata_identity_mismatch")
        licenses = sorted(member.filename for member in members
                          if member.filename.startswith(expected_prefix)
                          and ("license" in member.filename.lower() or "copying" in member.filename.lower()))
        return {"name": name, "version": version, "filename": path.name,
                "sha256": digest(path), "size": info.st_size,
                "groups": [group for group, pins in (("runtime", RUNTIME), ("build", BUILD)) if name in pins],
                "purl": "pkg:pypi/" + name + "@" + version,
                "wheel_tags": sorted(wheel_data.get_all("Tag", [])),
                "requires_python": message.get("Requires-Python"),
                "requires_dist": sorted(message.get_all("Requires-Dist", [])),
                "license_expression": message.get("License-Expression"),
                "license_files": licenses}


def prepare(source, destination):
    if source.is_symlink() or not source.is_dir():
        raise ValueError("wheel_directory_invalid")
    files = []
    for child in source.iterdir():
        if child.name.endswith(".whl"):
            files.append(child)
            if len(files) > MAX_FILES:
                raise ValueError("wheel_count_limit")
    rows, total = [], 0
    for path in sorted(files):
        total += path.lstat().st_size
        if total > MAX_TOTAL:
            raise ValueError("wheel_total_limit")
        rows.append(inspect_wheel(path))
    if {row["name"] for row in rows} != set(RUNTIME | BUILD):
        raise ValueError("complete_pinned_wheel_set_required")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        wheels = destination / "wheelhouse"
        wheels.mkdir(mode=0o700)
        for row in rows:
            source_file = source / row["filename"]
            # Exemplum privatum iterum digeritur ante usum metadatae.
            fd = os.open(source_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream, (wheels / row["filename"]).open("xb") as output:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("wheel_source_changed")
                copied = 0
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    copied += len(block)
                    if copied > row["size"]:
                        raise ValueError("wheel_source_changed")
                    output.write(block)
            if copied != row["size"] or digest(wheels / row["filename"]) != row["sha256"]:
                raise ValueError("wheel_source_changed")
            os.chmod(wheels / row["filename"], 0o600)
        for group, pins in (("runtime", RUNTIME), ("build", BUILD), ("all", RUNTIME | BUILD)):
            lines = []
            for name, version in sorted(pins.items()):
                hashes = sorted({row["sha256"] for row in rows if row["name"] == name})
                lines.append(name + "==" + version + " " + " ".join("--hash=sha256:" + value for value in hashes))
            (destination / ("requirements-" + group + ".txt")).write_text("\n".join(lines) + "\n", encoding="utf-8")
        inventory = {"schema": "probentium.offline-inventory.v1", "components": rows,
                     "metadata_origin": "supplied wheel METADATA and WHEEL entries",
                     "network_used_by_preparer": False, "upstream_signature_verified": False,
                     "scope": "Python wheel inventory only; not a complete native or transitive source SBOM",
                     "limitations": ["Hashes bind these acquired bytes; they do not authenticate upstream ownership.",
                                     "Platform support is determined by wheel tags and installation tests.",
                                     "Native age executables and the project distribution are prepared separately.",
                                     "Embedded upstream licenses and native dependency SBOMs are preserved unchanged."]}
        (destination / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        members = sorted(path for path in destination.rglob("*") if path.is_file())
        (destination / "SHA256SUMS").write_text("".join(digest(path) + "  " + path.relative_to(destination).as_posix() + "\n" for path in members), encoding="ascii")
        for path in destination.iterdir():
            if path.is_file():
                os.chmod(path, 0o600)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {"schema": "probentium.offline-preparation.v1", "wheel_count": len(rows),
            "component_count": len(RUNTIME | BUILD), "wheel_bytes": total,
            "network_requests": 0, "upstream_signature_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare a hash-locked offline wheelhouse and metadata inventory from already downloaded pinned wheels. Does not access the network.")
    parser.add_argument("--print-pins", choices=("runtime", "build", "all"), help="Print exact preparation pins without reading wheels")
    parser.add_argument("--wheels", type=Path, help="Existing wheel directory; obtain wheels in a separate explicit network step")
    parser.add_argument("--output", type=Path, help="New destination directory; its parent must already exist")
    args = parser.parse_args(argv)
    if args.print_pins:
        if args.wheels or args.output:
            parser.error("--print-pins cannot be combined with --wheels or --output")
        pins = {"runtime": RUNTIME, "build": BUILD, "all": RUNTIME | BUILD}[args.print_pins]
        print("\n".join(name + "==" + version for name, version in sorted(pins.items())))
        return 0
    if not args.wheels or not args.output:
        parser.error("--wheels and --output are required")
    try:
        print(json.dumps(prepare(args.wheels, args.output), sort_keys=True))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        print('{"error":"offline_preparation_failed"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
