"""Fontes leguntur; originalia non mutantur."""
import hashlib
import os
import re
import secrets
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .model import CaseError, MAX_SOURCE


@contextmanager
def _parent_directory(path):
    """Parens per descriptores aperitur, nexus symbolici recusantur."""
    path = Path(os.path.abspath(path))
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise CaseError("safe_file_open_requires_posix")
    directory = None
    try:
        try:
            directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in path.parts[1:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = nxt
        except OSError as exc:
            raise CaseError("safe_file_access_failed") from exc
        yield path, directory
    finally:
        if directory is not None:
            os.close(directory)


@contextmanager
def regular_reader(path, max_bytes):
    """Omnis pars viae sine nexu symbolico aperitur."""
    with _parent_directory(path) as (path, directory):
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise CaseError("regular_file_required")
            if before.st_size > max_bytes:
                raise CaseError("input_size_limit")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                yield stream, before
                after = os.fstat(stream.fileno())
                current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if signature(before) != signature(after) or signature(after) != signature(current):
                    raise CaseError("input_changed_during_read")
        except OSError as exc:
            raise CaseError("safe_file_access_failed") from exc
        finally:
            if fd is not None:
                os.close(fd)


@contextmanager
def verified_reader(path, expected_sha256, max_bytes=MAX_SOURCE):
    """Eadem descriptio et summam et lectionem continet."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise CaseError("invalid_evidence_digest")
    with regular_reader(path, max_bytes) as (stream, info):
        if _stream_hash(stream, max_bytes)[0] != expected_sha256:
            raise CaseError("evidence_digest_mismatch")
        stream.seek(0)
        yield stream, info
        # Memoria intermedia ante secundam probationem vacuatur.
        stream.seek(0, os.SEEK_END)
        stream.seek(0)
        if _stream_hash(stream, max_bytes)[0] != expected_sha256:
            raise CaseError("input_changed_during_read")


def _stream_hash(stream, max_bytes):
    """Summa ex octetis finitis computatur."""
    h, size = hashlib.sha256(), 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(chunk)
        if size > max_bytes:
            raise CaseError("input_size_limit")
        h.update(chunk)
    return h.hexdigest(), size


def bounded_read(path, max_bytes):
    with regular_reader(path, max_bytes) as (stream, _):
        value = stream.read(max_bytes + 1)
        if len(value) > max_bytes:
            raise CaseError("input_size_limit")
        return value


def file_hash(path, max_bytes):
    with regular_reader(path, max_bytes) as (stream, _):
        return _stream_hash(stream, max_bytes)


def acquire(path, directory, max_bytes):
    """Exemplar privatum ante analysim custoditur."""
    fd, temp = tempfile.mkstemp(prefix=".acquire-", dir=directory)
    h, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as output:
            with regular_reader(path, max_bytes) as (stream, info):
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(chunk)
                    if size > max_bytes:
                        raise CaseError("input_size_limit")
                    h.update(chunk)
                    output.write(chunk)
                metadata = {"original_name": Path(path).name, "acquisition": "copied-regular-file", "size": size,
                            "mtime_ns": info.st_mtime_ns, "mode": stat.S_IMODE(info.st_mode)}
            output.flush()
            os.fsync(output.fileno())
        sha = h.hexdigest()
        target = directory / (sha + ".bin")
        try:
            os.link(temp, target)
        except FileExistsError:
            if file_hash(target, max_bytes) != (sha, size):
                raise CaseError("existing_evidence_copy_invalid")
        return sha, size, metadata
    finally:
        Path(temp).unlink(missing_ok=True)


def write_new(path, data):
    """Exitus integer simul apparet; vetus numquam deletur."""
    with _parent_directory(path) as (path, directory):
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise CaseError("output_symlink_refused")
            raise FileExistsError("output_exists")
        temporary = None
        fd = None
        try:
            for _ in range(16):
                candidate = ".output-" + secrets.token_hex(16)
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
                except FileExistsError:
                    continue
                temporary = candidate
                break
            if fd is None:
                raise CaseError("output_temporary_collision")
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                original = os.fstat(stream.fileno())
                # Nexus durus nomen finale sine superpositione constituit.
                os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                published = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                if (published.st_dev, published.st_ino) != (original.st_dev, original.st_ino):
                    os.unlink(path.name, dir_fd=directory)
                    raise CaseError("output_temporary_changed")
            os.unlink(temporary, dir_fd=directory)
            temporary = None
            os.fsync(directory)
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass


def read_key(path):
    with regular_reader(path, 4096) as (stream, info):
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise CaseError("key_file_must_be_owner_only")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CaseError("key_file_owner_mismatch")
        key = stream.read(4097)
        if len(key) != 32:
            raise CaseError("key_length_must_be_32_bytes")
        return key
