"""Signum octetos ligat; fiducia separatim decernitur."""
import base64
import hashlib
import os
import re
import stat
from pathlib import Path

from testifex.model import CaseError
from testifex.safeio import regular_reader, write_new, _parent_directory
from .contracts import ProbentiumError, canonical_bytes, strict_json, text_field

MAX_ENVELOPE = 4096
_HEX = re.compile(r"[a-f0-9]{64}\Z")
CONTEXTS = {
    "testifex.packet.v1": ("testifex.packet-signature.v1", "TESTIFEX-PACKET-V1", "manifest_sha256"),
    "probentium.packet.v1": ("probentium.packet-signature.v1", "PROBENTIUM-PACKET-V1", "manifest_sha256"),
    "testifex.review.v1": ("testifex.review-signature.v1", "TESTIFEX-REVIEW-V1", "decision_sha256"),
}


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        return Ed25519PrivateKey, Ed25519PublicKey, serialization, InvalidSignature
    except ImportError:
        raise ProbentiumError("cryptography_backend_unavailable", 7) from None


def fingerprint(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ProbentiumError("invalid_public_key")
    return hashlib.sha256(public_key).hexdigest()


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value, size):
    if not isinstance(value, str) or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ProbentiumError("invalid_signature_encoding", 4)
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise ProbentiumError("invalid_signature_encoding", 4) from None
    if len(raw) != size or _b64(raw) != value:
        raise ProbentiumError("invalid_signature_encoding", 4)
    return raw


def _private_parent(path):
    try:
        with _parent_directory(path) as (_, directory):
            info = os.fstat(directory)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
                raise ProbentiumError("private_directory_required")
    except CaseError:
        raise ProbentiumError("safe_key_access_failed") from None


def read_private_key(path):
    _private_parent(path)
    try:
        with regular_reader(path, 32) as (stream, info):
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ProbentiumError("private_key_permissions")
            raw = stream.read(33)
            if len(raw) != 32:
                raise ProbentiumError("private_key_length")
            return raw
    except CaseError:
        raise ProbentiumError("safe_key_access_failed") from None


def generate_key(path):
    _private_parent(path)
    private_type, _, serialization, _ = _crypto()
    private = private_type.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        write_new(Path(path), seed)
    except (CaseError, OSError):
        raise ProbentiumError("key_output_exists_or_unsafe") from None
    return {"algorithm": "Ed25519", "key_id": fingerprint(public), "public_key": _b64(public)}


def _canonical(value, maximum):
    if isinstance(value, bytes):
        parsed = strict_json(value, maximum)
        if canonical_bytes(parsed) != value:
            raise ProbentiumError("noncanonical_signed_content", 4)
    else:
        parsed = value
    raw = canonical_bytes(parsed)
    if len(raw) > maximum:
        raise ProbentiumError("signed_content_limit", 6)
    if not isinstance(parsed, dict):
        raise ProbentiumError("signed_object_required")
    return parsed, raw


def sign_document(document, key_path):
    value, raw = _canonical(document, 64 * 1024 ** 2)
    if value.get("schema") not in CONTEXTS:
        raise ProbentiumError("unsupported_signature_context", 7)
    schema, context, digest_field = CONTEXTS[value["schema"]]
    private_type, _, serialization, _ = _crypto()
    private = private_type.from_private_bytes(read_private_key(key_path))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signature = private.sign(context.encode("ascii") + b"\0" + raw)
    return {"schema": schema, "algorithm": "Ed25519", "context": context,
            digest_field: hashlib.sha256(raw).hexdigest(), "key_id": fingerprint(public),
            "public_key": _b64(public), "signature": _b64(signature)}


def validate_trust_store(value):
    value, raw = _canonical(value, 1024 * 1024)
    if set(value) != {"schema", "keys"} or value["schema"] != "probentium.trust.v1" or not isinstance(value["keys"], list) or len(value["keys"]) > 1000:
        raise ProbentiumError("invalid_trust_store")
    seen = set()
    for item in value["keys"]:
        if (not isinstance(item, dict) or set(item) != {"key_id", "alias", "status", "reason"}
                or not isinstance(item["key_id"], str) or not _HEX.fullmatch(item["key_id"])
                or item["key_id"] in seen or item["status"] not in ("active", "revoked")):
            raise ProbentiumError("invalid_trust_store")
        text_field(item["alias"])
        if item["reason"] is not None:
            text_field(item["reason"], 4096)
        if item["status"] == "revoked" and not item["reason"]:
            raise ProbentiumError("revocation_reason_required")
        seen.add(item["key_id"])
    if [row["key_id"] for row in value["keys"]] != sorted(seen):
        raise ProbentiumError("trust_store_order_invalid")
    return value


def load_trust_store(path):
    try:
        with regular_reader(path, 1024 * 1024) as (stream, _):
            return validate_trust_store(stream.read(1024 * 1024 + 1))
    except CaseError:
        raise ProbentiumError("safe_trust_store_access_failed") from None


def verify_document_signature(document, envelope, trust_store=None):
    value, raw = _canonical(document, 64 * 1024 ** 2)
    if value.get("schema") not in CONTEXTS:
        raise ProbentiumError("unsupported_signature_context", 7)
    schema, context, digest_field = CONTEXTS[value["schema"]]
    env, _ = _canonical(envelope, MAX_ENVELOPE)
    if set(env) != {"schema", "algorithm", "context", digest_field, "key_id", "public_key", "signature"}:
        raise ProbentiumError("invalid_signature_envelope", 4)
    if env["schema"] != schema or env["algorithm"] != "Ed25519" or env["context"] != context:
        raise ProbentiumError("signature_context_mismatch", 4)
    public, signature = _unb64(env["public_key"], 32), _unb64(env["signature"], 64)
    if env["key_id"] != fingerprint(public) or env[digest_field] != hashlib.sha256(raw).hexdigest():
        raise ProbentiumError("signature_digest_mismatch", 4)
    _, public_type, _, invalid_signature = _crypto()
    try:
        public_type.from_public_bytes(public).verify(signature, context.encode("ascii") + b"\0" + raw)
    except (invalid_signature, ValueError):
        raise ProbentiumError("signature_invalid", 4) from None
    trust = validate_trust_store(trust_store) if trust_store is not None else {"schema": "probentium.trust.v1", "keys": []}
    matching = next((row for row in trust["keys"] if row["key_id"] == env["key_id"]), None)
    return {"signature_status": "valid", "key_trust": "unknown" if matching is None else "trusted" if matching["status"] == "active" else "revoked",
            "key_id": env["key_id"], "trust_store_digest": hashlib.sha256(canonical_bytes(trust)).hexdigest(),
            "limitations": ["signature_authenticates_bytes_not_factual_truth", "offline_trust_may_not_include_later_revocations"]}


sign_manifest = sign_document
verify_manifest_signature = verify_document_signature
