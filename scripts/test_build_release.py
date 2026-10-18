"""Fasciculi sub diversis larvis permissionum eadem forma manent."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("build_release.py")
SPEC = importlib.util.spec_from_file_location("release_builder", SCRIPT)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BuildReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_real_builds_are_byte_identical_across_umasks_and_preserve_source_modes(self):
        project = self.root / "project"
        (project / "scripts").mkdir(parents=True)
        (project / "synthetic_package").mkdir()
        (project / "bin").mkdir()
        shutil.copyfile(SCRIPT, project / "scripts/build_release.py")
        files = {
            "pyproject.toml": '[build-system]\nrequires = ["setuptools", "wheel"]\nbuild-backend = "setuptools.build_meta"\n',
            "setup.py": 'from setuptools import setup\nsetup(name="synthetic-release-fixture", version="1.0.0", packages=["synthetic_package"], scripts=["bin/synthetic-tool"])\n',
            "README.md": "Synthetic packaging fixture.\n",
            "synthetic_package/__init__.py": 'VALUE = "synthetic"\n',
            "bin/synthetic-tool": '#!/usr/bin/env python3\nprint("synthetic")\n',
        }
        for name, content in files.items():
            path = project / name
            path.write_text(content)
            path.chmod(0o775 if name.startswith("bin/") else 0o664)
        before = {name: (digest(project / name), stat.S_IMODE((project / name).stat().st_mode)) for name in files}
        outputs = []
        for mask in (0o022, 0o077):
            output = self.root / ("build-" + oct(mask))
            result = subprocess.run(
                [sys.executable, "-c", "import os,runpy,sys; os.umask(int(sys.argv[1])); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name='__main__')",
                 str(mask), str(project / "scripts/build_release.py"), "--output", str(output)],
                cwd=project, env=dict(os.environ, PIP_NO_INDEX="1", PYTHONPATH=""),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
            outputs.append({path.name: path.read_bytes() for path in output.iterdir()})
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(len(outputs[0]), 3)
        after = {name: (digest(project / name), stat.S_IMODE((project / name).stat().st_mode)) for name in files}
        self.assertEqual(before, after)
        for name, raw in outputs[0].items():
            if name.endswith(".whl"):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    executable = [item for item in archive.infolist() if item.filename.endswith("/scripts/synthetic-tool")]
                    self.assertEqual(len(executable), 1)
                    self.assertEqual(stat.S_IMODE(executable[0].external_attr >> 16), 0o755)
                    for member in archive.infolist():
                        expected = 0o755 if member in executable or member.is_dir() else 0o644
                        self.assertEqual(stat.S_IMODE(member.external_attr >> 16), expected, member.filename)
            elif name.endswith(".tar.gz"):
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                    for member in archive.getmembers():
                        expected = 0o755 if member.isdir() or member.name.endswith("/bin/synthetic-tool") else 0o644
                        self.assertEqual(member.mode, expected, member.name)

    def test_wheel_modes_strip_special_bits_and_normalize_directories_without_changing_input(self):
        source, target = self.root / "source.whl", self.root / "normalized.whl"
        modes = {"package/": stat.S_IFDIR | 0o2700,
                 "package/data": stat.S_IFREG | 0o2600,
                 "package/tool": stat.S_IFREG | 0o6750}
        with zipfile.ZipFile(source, "w") as archive:
            for name, mode in modes.items():
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = mode << 16
                archive.writestr(member, b"" if name.endswith("/") else b"synthetic")
        original = digest(source)
        BUILDER.normalize_wheel(source, target)
        self.assertEqual(digest(source), original)
        with zipfile.ZipFile(target) as archive:
            self.assertEqual({i.filename: stat.S_IMODE(i.external_attr >> 16) for i in archive.infolist()},
                             {"package/": 0o755, "package/data": 0o644, "package/tool": 0o755})
            self.assertTrue(all(i.create_system == 3 for i in archive.infolist()))
            self.assertEqual(archive.getinfo("package/").external_attr & 0xFFFF, 0x10)
            self.assertEqual(archive.read("package/tool"), b"synthetic")

    def test_source_archive_normalizes_permissions_owners_and_times_without_changing_input(self):
        source, target = self.root / "source.tar.gz", self.root / "normalized.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            for name, mode, directory in (("package", 0o2700, True), ("package/data", 0o2600, False),
                                          ("package/tool", 0o6750, False)):
                member = tarfile.TarInfo(name)
                member.mode = mode
                member.uid = member.gid = 1234
                member.uname = member.gname = "synthetic"
                member.mtime = 42
                member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                member.size = 0 if directory else len(b"synthetic")
                archive.addfile(member, None if directory else io.BytesIO(b"synthetic"))
        original = digest(source)
        BUILDER.normalize_sdist(source, target)
        self.assertEqual(digest(source), original)
        with tarfile.open(target, "r:gz") as archive:
            self.assertEqual({m.name: m.mode for m in archive.getmembers()},
                             {"package": 0o755, "package/data": 0o644, "package/tool": 0o755})
            for member in archive.getmembers():
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                                 (0, 0, "", "", BUILDER.EPOCH))
                self.assertEqual(member.pax_headers, {})
            self.assertEqual(archive.extractfile("package/tool").read(), b"synthetic")

    def test_symbolic_links_are_rejected_instead_of_converted_to_regular_files(self):
        wheel = self.root / "link.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            member = zipfile.ZipInfo("package/link")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, b"target")
        with self.assertRaisesRegex(ValueError, "unsupported_archive_member_type"):
            BUILDER.normalize_wheel(wheel, self.root / "rejected.whl")
        source = self.root / "link.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            member = tarfile.TarInfo("package/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "unsupported_archive_member_type"):
            BUILDER.normalize_sdist(source, self.root / "rejected.tar.gz")

    def test_existing_output_is_never_overwritten(self):
        wheel, target = self.root / "source.whl", self.root / "existing.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("package/data", b"synthetic")
        target.write_bytes(b"preserved")
        with self.assertRaises(FileExistsError):
            BUILDER.normalize_wheel(wheel, target)
        self.assertEqual(target.read_bytes(), b"preserved")


if __name__ == "__main__":
    unittest.main()
