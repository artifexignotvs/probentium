"""Iudicium revisioni alligatur; absentia relationum consensum prohibet."""
import hashlib
import re

from .contracts import ProbentiumError, canonical_bytes, object_digest, strict_json
from .signatures import sign_document, verify_document_signature

DISPOSITIONS = ("approve", "reject", "request_changes", "abstain")
_HEX = re.compile(r"[a-f0-9]{64}\Z")


def _validate(decision):
    if isinstance(decision, bytes):
        parsed = strict_json(decision, 4096)
        if canonical_bytes(parsed) != decision:
            raise ProbentiumError("noncanonical_review", 4)
        decision = parsed
    fields = {"schema", "claim_id", "claim_revision", "evaluation_digest", "snapshot_digest", "reviewer_key_id", "disposition", "rationale_digest", "previous_decision_id"}
    if not isinstance(decision, dict) or set(decision) != fields or decision["schema"] != "testifex.review.v1":
        raise ProbentiumError("invalid_review_schema")
    for key in ("claim_id", "evaluation_digest", "snapshot_digest", "reviewer_key_id", "rationale_digest"):
        if not isinstance(decision[key], str) or not _HEX.fullmatch(decision[key]):
            raise ProbentiumError("invalid_review_reference")
    if decision["previous_decision_id"] is not None and (not isinstance(decision["previous_decision_id"], str) or not _HEX.fullmatch(decision["previous_decision_id"])):
        raise ProbentiumError("invalid_review_reference")
    if type(decision["claim_revision"]) is not int or not 0 <= decision["claim_revision"] <= 9007199254740991 or decision["disposition"] not in DISPOSITIONS:
        raise ProbentiumError("invalid_review_decision")
    return decision


def create_decision(claim_id, claim_revision, evaluation_digest, snapshot_digest, reviewer_key_id, disposition,
                    rationale_digest, previous_decision_id=None):
    return _validate({"schema": "testifex.review.v1", "claim_id": claim_id, "claim_revision": claim_revision,
                      "evaluation_digest": evaluation_digest, "snapshot_digest": snapshot_digest,
                      "reviewer_key_id": reviewer_key_id, "disposition": disposition,
                      "rationale_digest": rationale_digest, "previous_decision_id": previous_decision_id})


def rationale_digest(text):
    if not isinstance(text, str):
        raise ProbentiumError("invalid_review_rationale")
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        raise ProbentiumError("invalid_review_rationale") from None
    if not raw or len(raw) > 65536:
        raise ProbentiumError("review_rationale_limit", 6)
    return hashlib.sha256(raw).hexdigest()


def sign_review(decision, key_path):
    value = _validate(decision)
    envelope = sign_document(value, key_path)
    if envelope["key_id"] != value["reviewer_key_id"]:
        raise ProbentiumError("reviewer_key_mismatch", 4)
    return envelope


def verify_review(decision, envelope, trust_store=None):
    value = _validate(decision)
    receipt = verify_document_signature(value, envelope, trust_store)
    if receipt["key_id"] != value["reviewer_key_id"]:
        raise ProbentiumError("reviewer_key_mismatch", 4)
    return {**receipt, "decision_id": object_digest(value, "TESTIFEX-REVIEW-V1"),
            "revision_binding": "unchecked", "approval_effect": "none_until_references_and_revision_verified"}


def validate_stored(data):
    """Fiducia relata non est fiducia huius lectoris."""
    if not isinstance(data, dict) or set(data) != {"decision", "signature", "verification", "binding", "approval_effect"}:
        raise ProbentiumError("invalid_stored_review", 4)
    fresh = verify_review(data["decision"], data["signature"])
    old, binding = data["verification"], data["binding"]
    if (not isinstance(old, dict) or set(old) != set(fresh)
            or old["key_trust"] not in ("unknown", "trusted", "revoked")
            or not isinstance(old["trust_store_digest"], str) or not _HEX.fullmatch(old["trust_store_digest"])
            or any(old[key] != fresh[key] for key in ("signature_status", "key_id", "limitations", "decision_id", "approval_effect"))
            or not isinstance(binding, dict) or set(binding) != {"status", "missing"}
            or binding["status"] not in ("current", "historical", "pending_references")
            or not isinstance(binding["missing"], list) or len(binding["missing"]) > 64
            or any(not isinstance(item, str) or not re.fullmatch(r"[a-z_]{1,64}", item) for item in binding["missing"])
            or binding["status"] != "pending_references" and binding["missing"]
            or old["revision_binding"] != binding["status"]):
        raise ProbentiumError("invalid_stored_review_receipt", 4)
    effect = "eligible_for_current_review" if binding["status"] == "current" and old["key_trust"] == "trusted" else "none"
    if data["approval_effect"] != effect:
        raise ProbentiumError("invalid_stored_review_effect", 4)
    return fresh


def import_review(case, decision, envelope, *, trust_store=None, expected_revision=None, reference_resolver=None):
    """Resolver fidus plenam relationem probat; nomen solum non sufficit."""
    value = _validate(decision)
    receipt = verify_review(value, envelope, trust_store)
    if isinstance(envelope, bytes):
        envelope = strict_json(envelope, 4096)
    integrity = case.verify()
    if not integrity["ok"]:
        raise ProbentiumError("review_case_integrity_failed", 4)
    if expected_revision is not None and expected_revision != case.revision:
        raise ProbentiumError("revision_conflict", 5)
    if reference_resolver is None:
        binding = {"status": "pending_references", "missing": ["claim_revision", "evaluation_digest", "snapshot_digest", "rationale_digest"]}
    else:
        binding = reference_resolver(case, value)
        if (not isinstance(binding, dict) or set(binding) != {"status", "missing"}
                or binding["status"] not in ("current", "historical", "pending_references")
                or not isinstance(binding["missing"], list) or len(binding["missing"]) > 64
                or any(not isinstance(item, str) or not re.fullmatch(r"[a-z_]{1,64}", item) for item in binding["missing"])
                or binding["status"] != "pending_references" and binding["missing"]):
            raise ProbentiumError("invalid_review_binding_receipt", 4)
    if binding["status"] == "current" and (integrity.get("completeness") == "partial" or integrity.get("authorized_unavailable")):
        binding = {"status": "pending_references", "missing": ["raw_evidence"]}
    status = binding["status"]
    receipt["revision_binding"] = status
    effect = "eligible_for_current_review" if status == "current" and receipt["key_trust"] == "trusted" else "none"
    stored = case.put_object("review_decision", {"decision": value, "signature": envelope, "verification": receipt,
                                               "binding": binding, "approval_effect": effect}, expected_revision=case.revision)
    return {"status": status, "stored": stored, "verification": receipt, "binding": binding, "approval_effect": effect,
            "limitations": ["valid_signature_does_not_imply_reviewer_identity", "historical_approval_does_not_apply_to_new_revision"]}


def review_applicability(decision, claim_revision, evaluation_digest, snapshot_digest):
    value = _validate(decision)
    current = all(value[key] == item for key, item in (("claim_revision", claim_revision), ("evaluation_digest", evaluation_digest), ("snapshot_digest", snapshot_digest)))
    return {"applies_to_current_revision": current, "signature_bytes_unchanged": True,
            "state": "current" if current else "historical_only"}
