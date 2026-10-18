"""Plures loci unum testimonium sustinent; ordo non fingitur."""
import re

from .contracts import ProbentiumError, object_digest

MAX_RECORD_REFS = 32
MAX_COMPOSITE_BYTES = 8 * 1024 ** 2
MAX_OUTPUT_INDEX = 9_999_999
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def event_records(event, lookup):
    """Omnes fines ante primam allocationem octetorum probantur."""
    refs = event.get("record_refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_RECORD_REFS:
        raise ProbentiumError("event_record_count_invalid", 4)
    if any(not isinstance(ref, str) or not _HEX.fullmatch(ref) for ref in refs):
        raise ProbentiumError("event_record_reference_invalid", 4)
    if len(set(refs)) != len(refs) or event.get("primary_record_ref") not in refs:
        raise ProbentiumError("event_record_mismatch", 4)
    if type(event.get("output_index")) is not int or not 0 <= event["output_index"] <= MAX_OUTPUT_INDEX:
        raise ProbentiumError("event_output_index_invalid", 4)
    records, end, total, primary = [], -1, 0, None
    for ref in refs:
        record = lookup(ref)
        if not isinstance(record, dict) or record.get("id") != ref or record.get("artifact_id") != event.get("artifact_id"):
            raise ProbentiumError("event_record_mismatch", 4)
        offset, length = record.get("offset"), record.get("length")
        if type(offset) is not int or type(length) is not int or length <= 0 or offset < 0 or offset < end:
            raise ProbentiumError("event_record_order_invalid", 4)
        end = offset + length
        total += length
        if total > MAX_COMPOSITE_BYTES:
            raise ProbentiumError("event_record_byte_limit", 6)
        if ref == event["primary_record_ref"]:
            primary = record
        records.append(record)
    if any(event.get(key) != primary.get(key) for key in ("artifact_id", "ordinal", "offset", "length", "raw_digest")):
        raise ProbentiumError("event_record_mismatch", 4)
    return records


def observation_key(event):
    """Index ad eosdem locos pertinet, non ad contentum interpretatum."""
    return bytes.fromhex(object_digest({key: event[key] for key in ("parse_run_id", "record_refs", "output_index")},
                                      "PROBENTIUM-OUTPUT-KEY-V1"))
