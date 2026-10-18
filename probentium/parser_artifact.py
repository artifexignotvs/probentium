"""Distributio certa probatur; approbatio hominis separatim servatur."""
import base64
import csv
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import io
import os
import platform
import re
import stat
import struct
import sys
import sysconfig
import zipfile
from email.parser import BytesParser
from pathlib import Path

from testifex.model import CaseError
from testifex.safeio import regular_reader
from .contracts import ProbentiumError, canonical_bytes, object_digest, text_field

DEPENDENCIES = {"rfc8785": "0.1.4", "cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.11"}
SCHEMA = "probentium.parser-distribution-manifest.v1"
APPROVAL_SCHEMA = "probentium.parser-approval.v1"
DOMAIN = "TESTIFEX-PARSER-ARTIFACT-V2"
MAX_WHEEL = 64 * 1024 ** 2
MAX_MEMBER = 32 * 1024 ** 2
MAX_EXPANDED = 256 * 1024 ** 2
MAX_MEMBERS = 8192
MAX_MANIFEST = 4 * 1024 ** 2
EXCEPTIONS = ["dist-info/INSTALLER", "dist-info/RECORD", "dist-info/REQUESTED", "dist-info/direct_url.json", "source_bytecode_not_used_by_parser_worker"]
LIMITATIONS = ["operator_attestation_not_publisher_authentication", "interpreter_and_standard_library_not_attested", "loaded_memory_and_concurrent_replacement_not_attested", "generated_console_launchers_not_attested"]
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_PATH = re.compile(r"[A-Za-z0-9_.+/-]{1,256}\Z")
_ROOTS = {"probentium": {"probentium", "testifex"}, "rfc8785": {"rfc8785"}, "cryptography": {"cryptography"}, "cffi": {"cffi"}, "pycparser": {"pycparser"}}
_GENERATED = {"INSTALLER", "RECORD", "REQUESTED", "direct_url.json"}


def _fail(code, exit_code=4):
    raise ProbentiumError(code, exit_code)


def _hex(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _path(value):
    return (isinstance(value, str) and _PATH.fullmatch(value) is not None and not value.startswith("/")
            and all(part not in ("", ".", "..") for part in value.split("/")))


def _identity():
    libc, release = platform.libc_ver()
    return {"implementation": sys.implementation.name, "python": platform.python_version(), "cache_tag": sys.implementation.cache_tag,
            "system": sys.platform, "machine": platform.machine(), "bits": struct.calcsize("P") * 8,
            "byteorder": sys.byteorder, "soabi": sysconfig.get_config_var("SOABI") or "", "libc": libc, "libc_version": release}


def _compatible(tag):
    """Formae permissae clausae sunt; ignotae numquam probantur."""
    if not isinstance(tag, str) or len(tag) > 160:
        return False
    parts = tag.split("-")
    if len(parts) != 3:
        return False
    python, abi, target = parts
    if target == "any":
        return abi == "none" and python in ("py3", "py" + str(sys.version_info.major) + str(sys.version_info.minor))
    match = re.fullmatch(r"cp(3)([0-9]{1,2})", python)
    if not match or sys.implementation.name != "cpython" or sys.version_info.major != 3:
        return False
    minor = int(match[2])
    if not ((abi == python and minor == sys.version_info.minor) or (abi == "abi3" and 2 <= minor <= sys.version_info.minor)):
        return False
    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        return False
    machine = platform.machine()
    if sys.platform.startswith("linux"):
        old = {"manylinux2014": (2, 17), "manylinux2010": (2, 12), "manylinux1": (2, 5)}
        minimum = None
        for prefix, value in old.items():
            if target == prefix + "_" + machine:
                minimum = value
        match = re.fullmatch(r"manylinux_([0-9]+)_([0-9]+)_" + re.escape(machine), target)
        if match:
            minimum = (int(match[1]), int(match[2]))
        libc, release = platform.libc_ver()
        return minimum is not None and libc == "glibc" and re.fullmatch(r"[0-9]+\.[0-9]+", release) is not None and tuple(map(int, release.split("."))) >= minimum
    return False


def _target(name, distribution, version):
    info = distribution + "-" + version + ".dist-info"
    parts = name.split("/")
    if parts[0] == distribution + "-" + version + ".data":
        if distribution != "probentium" or parts[1:4] != ["data", "share", "probentium"] or len(parts) != 6 or parts[4] != "schemas" or parts[5] not in ("events-v2.schema.json", "control-observation.v1.schema.json", "deadline-plan.v1.schema.json"):
            _fail("parser_wheel_relocation_unsupported", 7)
        return "prefix", "/".join(parts[2:])
    allowed = parts[0] in _ROOTS[distribution] or parts[0] == info
    if distribution == "cffi" and len(parts) == 1 and re.fullmatch(r"_cffi_backend\.[A-Za-z0-9_.-]+\.so", name):
        allowed = True
    if not allowed or name.endswith((".pth", ".pyc", ".pyo")) or "__pycache__" in parts:
        _fail("parser_wheel_member_unsupported", 7)
    return "site", name


def _hash_stream(stream, limit):
    result, size = hashlib.sha256(), 0
    while True:
        chunk = stream.read(min(1024 * 1024, limit + 1 - size))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            _fail("parser_artifact_size_limit", 6)
        result.update(chunk)
    return result.hexdigest(), size


def _zip_bounds(stream, size):
    """Tabula centralis ante bibliothecae allocationem finitur."""
    if size < 22:
        _fail("invalid_parser_wheel")
    stream.seek(size - 22)
    footer = stream.read(22)
    if footer[:4] != b"PK\x05\x06":
        _fail("parser_wheel_trailing_data")
    _, disk, start, entries_disk, entries, length, offset, comment = struct.unpack("<4s4H2LH", footer)
    if disk or start or entries != entries_disk or comment or not 1 <= entries <= MAX_MEMBERS or length > 4 * 1024 ** 2:
        _fail("parser_wheel_directory_limit", 6)
    if offset + length != size - 22:
        _fail("invalid_parser_wheel_directory")
    stream.seek(offset)
    consumed, actual = 0, 0
    while consumed < length:
        if length - consumed < 46 or actual >= MAX_MEMBERS:
            _fail("parser_wheel_directory_limit", 6)
        header = stream.read(46)
        if len(header) != 46:
            _fail("invalid_parser_wheel_directory")
        fields = struct.unpack("<4s6H3I5H2I", header)
        name_length, extra_length, comment_length = fields[10:13]
        record_length = 46 + name_length + extra_length + comment_length
        if (fields[0] != b"PK\x01\x02" or fields[13] or fields[16] >= offset or not 1 <= name_length <= 257
                or extra_length > 4096 or comment_length > 1024 or record_length > length - consumed):
            _fail("invalid_parser_wheel_directory")
        stream.seek(record_length - 46, os.SEEK_CUR)
        consumed += record_length
        actual += 1
    if actual != entries:
        _fail("invalid_parser_wheel_directory")
    stream.seek(0)
    if stream.read(4) != b"PK\x03\x04":
        _fail("parser_wheel_preamble_unsupported", 7)
    stream.seek(0)


def _metadata(raw):
    if len(raw) > 1024 * 1024 or b"\x00" in raw:
        _fail("parser_wheel_metadata_limit", 6)
    value = BytesParser().parsebytes(raw)
    if value.defects:
        _fail("invalid_parser_wheel_metadata")
    return value


def _one(headers, name):
    values = headers.get_all(name, [])
    if len(values) != 1:
        _fail("invalid_parser_wheel_metadata")
    return str(values[0])


def _requirements(metadata, distribution):
    """Dependentiae activae clausae sunt; additamenta non petuntur."""
    expected = {"probentium": {"rfc8785==0.1.4", "cryptography==50.0.2"}, "rfc8785": set(),
                "cryptography": {"cffi>=2.0.0"}, "cffi": {"pycparser"}, "pycparser": set()}
    active = set()
    values = metadata.get_all("Requires-Dist", [])
    if len(values) > 128:
        _fail("parser_dependency_inventory_mismatch")
    for raw in values:
        value = re.sub(r"\s+", "", str(raw)).replace('"', "'")
        parts = value.split(";")
        if len(parts) > 2 or len(value) > 256:
            _fail("parser_dependency_inventory_mismatch")
        if len(parts) == 2:
            marker = parts[1]
            if re.fullmatch(r"extra=='[A-Za-z0-9_-]+'", marker):
                continue
            if marker == "python_full_version<'3.11'" and parts[0] == "typing-extensions>=4.13.2" and sys.version_info >= (3, 11):
                continue
            if marker not in ("platform_python_implementation!='PyPy'", "implementation_name!='PyPy'") or sys.implementation.name != "cpython":
                _fail("parser_dependency_marker_unsupported", 7)
        if parts[0] in active:
            _fail("parser_dependency_inventory_mismatch")
        active.add(parts[0])
    if active != expected[distribution]:
        _fail("parser_dependency_inventory_mismatch")
    python = _one(metadata, "Requires-Python")
    clauses = python.replace(" ", "").split(",")
    match = re.fullmatch(r">=3\.([0-9]{1,2})(?:\.0)?", clauses[0])
    excluded = []
    for clause in clauses[1:]:
        exclusion = re.fullmatch(r"!=3\.([0-9]{1,2})\.([0-9]{1,3})", clause)
        if not exclusion or len(clauses) > 16:
            _fail("parser_python_requirement_unsupported", 7)
        excluded.append((3, int(exclusion[1]), int(exclusion[2])))
    if not match or sys.version_info.major != 3 or sys.version_info.minor < max(11, int(match[1])) or sys.version_info[:3] in excluded:
        _fail("parser_python_requirement_unsupported", 7)


def _wheel(path, expected_sha256, distribution):
    if not _hex(expected_sha256):
        _fail("invalid_parser_artifact_digest", 2)
    if not isinstance(path, (str, Path)) or not 1 <= len(str(path)) <= 4096 or "\x00" in str(path):
        _fail("invalid_parser_artifact_path", 2)
    try:
        with regular_reader(path, MAX_WHEEL) as (stream, before):
            digest, size = _hash_stream(stream, MAX_WHEEL)
            if digest != expected_sha256:
                _fail("parser_wheel_digest_mismatch")
            _zip_bounds(stream, size)
            with zipfile.ZipFile(stream) as archive:
                members, directories, total, names = {}, [], 0, set()
                for entry in archive.infolist():
                    mode = entry.external_attr >> 16
                    logical = entry.filename[:-1] if entry.is_dir() else entry.filename
                    if (not _path(logical) or logical in names
                            or (stat.S_IFMT(mode) not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG)) or entry.flag_bits & ~0x808
                            or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                        _fail("invalid_parser_wheel_member")
                    names.add(logical)
                    if entry.is_dir():
                        if entry.file_size:
                            _fail("invalid_parser_wheel_member")
                        directories.append(entry.filename)
                        continue
                    total += entry.file_size
                    if entry.file_size > MAX_MEMBER or total > MAX_EXPANDED or len(members) >= MAX_MEMBERS or entry.compress_size > MAX_WHEEL:
                        _fail("parser_wheel_expansion_limit", 6)
                    members[entry.filename] = entry
                if any(not any(name.startswith(directory) for name in members) for directory in directories):
                    _fail("invalid_parser_wheel_member")
                metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
                if len(metadata_names) != 1:
                    _fail("invalid_parser_wheel_metadata")
                info = metadata_names[0].split("/")[0]
                if members[metadata_names[0]].file_size > 1024 * 1024:
                    _fail("parser_wheel_metadata_limit", 6)
                metadata = _metadata(archive.read(metadata_names[0]))
                _requirements(metadata, distribution)
                version = _one(metadata, "Version")
                if (_one(metadata, "Name") != distribution or re.fullmatch(r"[0-9][A-Za-z0-9.]{0,63}", version) is None
                        or info != distribution + "-" + version + ".dist-info"
                        or (distribution != "probentium" and version != DEPENDENCIES[distribution])):
                    _fail("parser_dependency_inventory_mismatch")
                wheel_name, record_name = info + "/WHEEL", info + "/RECORD"
                if wheel_name not in members or record_name not in members or members[wheel_name].file_size > 16384 or members[record_name].file_size > 2 * 1024 ** 2:
                    _fail("invalid_parser_wheel_record")
                wheel = _metadata(archive.read(wheel_name))
                tags = sorted(set(str(tag) for tag in wheel.get_all("Tag", [])))
                if _one(wheel, "Wheel-Version") != "1.0" or not 1 <= len(tags) <= 16 or not any(_compatible(tag) for tag in tags):
                    _fail("parser_wheel_platform_unsupported", 7)
                if _one(wheel, "Root-Is-Purelib") not in ("true", "false"):
                    _fail("invalid_parser_wheel_metadata")
                records = {}
                for row in csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"), newline="")):
                    if len(row) != 3 or row[0] in records or row[0] not in members or len(records) >= MAX_MEMBERS:
                        _fail("invalid_parser_wheel_record")
                    records[row[0]] = row[1:]
                if set(records) != set(members) or records[record_name] != ["", ""]:
                    _fail("invalid_parser_wheel_record")
                files = []
                for name in sorted(members):
                    area, target = _target(name, distribution, version)
                    entry = members[name]
                    with archive.open(entry) as member:
                        hashed, count = _hash_stream(member, entry.file_size)
                    if count != entry.file_size:
                        _fail("parser_wheel_size_mismatch")
                    if name == record_name:
                        continue
                    encoded = "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(hashed)).decode("ascii").rstrip("=")
                    if records[name] != [encoded, str(count)]:
                        _fail("parser_wheel_record_mismatch")
                    files.append({"path": name, "area": area, "target": target, "sha256": hashed, "size": count})
                stream.seek(0)
                if _hash_stream(stream, MAX_WHEEL) != (digest, size):
                    _fail("parser_wheel_changed")
                return {"name": distribution, "version": version, "wheel_sha256": digest, "wheel_size": size, "tags": tags, "files": files}
    except CaseError:
        _fail("parser_artifact_access_failed")
    except (OSError, UnicodeError, csv.Error, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        if isinstance(exc, ProbentiumError):
            raise
        _fail("invalid_parser_wheel")


def _layout():
    site = Path(sysconfig.get_path("purelib"))
    if site != Path(sysconfig.get_path("platlib")) or not site.is_relative_to(Path(sys.prefix)):
        _fail("parser_install_layout_unsupported", 7)
    return {"site": site, "prefix": Path(sys.prefix)}


def _file_digest(path, maximum):
    try:
        with regular_reader(path, maximum) as (stream, _):
            return _hash_stream(stream, maximum)
    except CaseError:
        _fail("parser_installed_file_unavailable")


def _check_bytecode_name(path, source):
    """Forma compilata a processu parseri separatur; hic numquam legitur."""
    match = re.fullmatch(re.escape(source.stem) + r"\." + re.escape(sys.implementation.cache_tag) + r"(?:\.opt-([12]))?\.pyc", path.name)
    if not match:
        _fail("parser_unrecognized_bytecode")


def _installed(distributions):
    roots = _layout()
    expected, owned = {}, set()
    for distribution in distributions:
        for item in distribution["files"]:
            path = roots[item["area"]] / item["target"]
            if path in expected:
                _fail("parser_install_collision")
            expected[path] = item
        for root in _ROOTS[distribution["name"]]:
            owned.add(roots["site"] / root)
        owned.add(roots["site"] / (distribution["name"] + "-" + distribution["version"] + ".dist-info"))
        try:
            metadata = importlib.metadata.distribution(distribution["name"])
            if metadata.version != distribution["version"] or Path(metadata.locate_file("")) != roots["site"]:
                _fail("parser_installed_distribution_mismatch")
        except importlib.metadata.PackageNotFoundError:
            _fail("parser_installed_distribution_missing")
    for path, item in expected.items():
        if _file_digest(path, item["size"]) != (item["sha256"], item["size"]):
            _fail("parser_installed_bytes_mismatch")
    seen = 0
    for root in sorted(owned):
        pending = [root]
        while pending:
            directory = pending.pop()
            try:
                if not stat.S_ISDIR(directory.lstat().st_mode):
                    _fail("parser_installed_path_invalid")
                with os.scandir(directory) as entries:
                    for entry in entries:
                        seen += 1
                        if seen > MAX_MEMBERS * 3:
                            _fail("parser_installed_member_limit", 6)
                        path = directory / entry.name
                        if entry.is_symlink():
                            _fail("parser_installed_path_invalid")
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            _fail("parser_installed_path_invalid")
                        if path in expected:
                            continue
                        if directory == root and root.name.endswith(".dist-info") and entry.name in _GENERATED:
                            if entry.stat(follow_symlinks=False).st_size > 2 * 1024 ** 2:
                                _fail("parser_generated_metadata_limit", 6)
                            continue
                        if directory.name == "__pycache__":
                            source = directory.parent / (entry.name.split(".")[0] + ".py")
                            if source not in expected:
                                _fail("parser_unexpected_installed_file")
                            _check_bytecode_name(path, source)
                            if entry.stat(follow_symlinks=False).st_size > MAX_MEMBER:
                                _fail("parser_bytecode_size_limit", 6)
                            continue
                        _fail("parser_unexpected_installed_file")
            except OSError:
                _fail("parser_installed_file_unavailable")
    _import_origins(expected)
    return len(expected)


def _import_origins(expected):
    """Nomen importatum ad idem exemplar spectat, non ad exemplar editabile."""
    for name in ("probentium", "testifex", "rfc8785", "cryptography", "cffi", "pycparser", "_cffi_backend"):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None or Path(spec.origin) not in expected:
            _fail("parser_import_origin_mismatch")
        module = sys.modules.get(name)
        if module is not None and Path(getattr(module, "__file__", "")) != Path(spec.origin):
            _fail("parser_import_origin_mismatch")
    for name, module in tuple(sys.modules.items()):
        if name.split(".")[0] in set().union(*_ROOTS.values()) and getattr(module, "__file__", None):
            if Path(module.__file__) not in expected:
                _fail("parser_import_origin_mismatch")


def validate_manifest(manifest):
    """Structura probatur sine fide, sine lectione codicis alieni."""
    fields = {"schema", "distributions", "runtime", "installation_exceptions", "limitations"}
    if not isinstance(manifest, dict) or set(manifest) != fields or manifest["schema"] != SCHEMA:
        _fail("invalid_parser_distribution_manifest")
    if manifest["installation_exceptions"] != EXCEPTIONS or manifest["limitations"] != LIMITATIONS or not isinstance(manifest["runtime"], dict) or set(manifest["runtime"]) != set(_identity()):
        _fail("invalid_parser_distribution_manifest")
    for key, value in manifest["runtime"].items():
        if key == "bits":
            if type(value) is not int or value not in (32, 64):
                _fail("invalid_parser_runtime")
        elif not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_.+-]*", value):
            _fail("invalid_parser_runtime")
    distributions = manifest["distributions"]
    if not isinstance(distributions, list) or len(distributions) != 5:
        _fail("parser_dependency_inventory_mismatch")
    names, members, total, budget = [], 0, 0, 32768
    for distribution in distributions:
        if not isinstance(distribution, dict) or set(distribution) != {"name", "version", "wheel_sha256", "wheel_size", "tags", "files"}:
            _fail("invalid_parser_distribution_manifest")
        name, version = distribution["name"], distribution["version"]
        if (not isinstance(name, str) or name not in _ROOTS or name in names or not isinstance(version, str) or re.fullmatch(r"[0-9][A-Za-z0-9.]{0,63}", version) is None
                or (name != "probentium" and version != DEPENDENCIES[name]) or not _hex(distribution["wheel_sha256"])
                or type(distribution["wheel_size"]) is not int or not 1 <= distribution["wheel_size"] <= MAX_WHEEL):
            _fail("parser_dependency_inventory_mismatch")
        names.append(name)
        tags = distribution["tags"]
        if not isinstance(tags, list) or not 1 <= len(tags) <= 16 or any(not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", tag) for tag in tags) or tags != sorted(set(tags)):
            _fail("invalid_parser_wheel_tags")
        if not isinstance(distribution["files"], list) or not 1 <= len(distribution["files"]) <= MAX_MEMBERS:
            _fail("parser_artifact_member_limit", 6)
        paths = []
        for item in distribution["files"]:
            if (not isinstance(item, dict) or set(item) != {"path", "area", "target", "sha256", "size"} or not _path(item["path"])
                    or not _hex(item["sha256"]) or type(item["size"]) is not int or not 0 <= item["size"] <= MAX_MEMBER):
                _fail("invalid_parser_distribution_member")
            if (item["area"], item["target"]) != _target(item["path"], name, version):
                _fail("invalid_parser_distribution_member")
            paths.append(item["path"])
            members += 1
            total += item["size"]
            budget += 200 + len(item["path"]) + len(item["target"])
            if budget > MAX_MANIFEST:
                _fail("parser_artifact_manifest_limit", 6)
        if paths != sorted(set(paths)) or not {name + "-" + version + ".dist-info/METADATA", name + "-" + version + ".dist-info/WHEEL"}.issubset(paths):
            _fail("invalid_parser_distribution_member")
    if names != sorted(_ROOTS) or members > MAX_MEMBERS or total > MAX_EXPANDED:
        _fail("parser_artifact_manifest_limit", 6)
    return manifest


def verify_manifest(manifest):
    validate_manifest(manifest)
    if manifest["runtime"] != _identity() or any(not any(_compatible(tag) for tag in item["tags"]) for item in manifest["distributions"]):
        _fail("parser_runtime_mismatch", 7)
    count = _installed(manifest["distributions"])
    return {"schema": "probentium.parser-byte-verification.v1", "manifest_digest": object_digest(manifest, DOMAIN),
            "installed_bytes": "verified", "files_verified": count, "approval": "not_inferred",
            "wheel_archives": "checked_at_registration_not_reopened", "limitations": list(LIMITATIONS)}


def prepare_manifest(product_wheel, product_sha256, dependency_wheels):
    """Quinque distributa finita leguntur; nihil installatur aut exsequitur."""
    if not isinstance(dependency_wheels, list) or len(dependency_wheels) != 4:
        _fail("parser_dependency_inventory_mismatch", 2)
    dependencies = {}
    for item in dependency_wheels:
        if not isinstance(item, dict) or set(item) != {"name", "path", "sha256"} or not isinstance(item["name"], str) or item["name"] not in DEPENDENCIES or item["name"] in dependencies:
            _fail("parser_dependency_inventory_mismatch", 2)
        dependencies[item["name"]] = item
    distributions = [_wheel(product_wheel, product_sha256, "probentium")]
    distributions.extend(_wheel(item["path"], item["sha256"], name) for name, item in sorted(dependencies.items()))
    manifest = {"schema": SCHEMA, "distributions": sorted(distributions, key=lambda item: item["name"]), "runtime": _identity(),
                "installation_exceptions": list(EXCEPTIONS), "limitations": list(LIMITATIONS)}
    verify_manifest(manifest)
    return manifest


def validate_approval(data):
    if not isinstance(data, dict) or set(data) != {"schema", "manifest", "manifest_digest", "approved_by", "reason", "statement"} or data["schema"] != APPROVAL_SCHEMA or data["statement"] != "operator_approved_for_explicit_selection":
        _fail("invalid_parser_approval")
    validate_manifest(data["manifest"])
    if data["manifest_digest"] != object_digest(data["manifest"], DOMAIN):
        _fail("parser_approval_digest_mismatch")
    text_field(data["approved_by"], 128)
    text_field(data["reason"], 1024)
    return data


def register(case, product_wheel, product_sha256, dependency_wheels, *, approved_by, reason, expected_revision=None):
    text_field(approved_by, 128)
    text_field(reason, 1024)
    manifest = prepare_manifest(product_wheel, product_sha256, dependency_wheels)
    return case.put_object("parser_approval", {"schema": APPROVAL_SCHEMA, "manifest": manifest, "manifest_digest": object_digest(manifest, DOMAIN),
                           "approved_by": approved_by, "reason": reason, "statement": "operator_approved_for_explicit_selection"}, expected_revision=expected_revision)


def resolve_approval(case, identity):
    """Electio expressa requiritur; importatio sola fidem non creat."""
    wrapper = case.get_object(identity)
    if wrapper["kind"] != "parser_approval":
        _fail("parser_approval_required", 2)
    data = validate_approval(wrapper["data"])
    verify_manifest(data["manifest"])
    return data["manifest"]
