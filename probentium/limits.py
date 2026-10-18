"""Limites expressi finiuntur; ambitus processus eos non mutat."""
from .contracts import ProbentiumError, object_digest

SCHEMA = "probentium.resource-policy.v1"
DEFAULTS = {"max_source_bytes": 1024 ** 3, "max_case_bytes": 20 * 1024 ** 3,
            "max_import_records": 1_000_000, "max_case_events": 1_000_000, "max_packet_bytes": 8 * 1024 ** 3}
HARD_CAPS = {"max_source_bytes": 4 * 1024 ** 3, "max_case_bytes": 100 * 1024 ** 3,
             "max_import_records": 10_000_000, "max_case_events": 10_000_000, "max_packet_bytes": 100 * 1024 ** 3}
FIXED = {"max_message_bytes": 1024 ** 2, "max_json_depth": 32, "max_blob_bytes": 4 * 1024 ** 3, "max_packet_members": 20_000}


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != {"schema", *DEFAULTS, *FIXED} or policy["schema"] != SCHEMA:
        raise ProbentiumError("invalid_resource_policy", 2)
    for key, maximum in HARD_CAPS.items():
        value = policy[key]
        if type(value) is not int or not 1 <= value <= maximum:
            raise ProbentiumError("resource_policy_out_of_range", 6)
    for key, value in FIXED.items():
        if type(policy[key]) is not int or policy[key] != value:
            raise ProbentiumError("fixed_resource_limit_changed", 6)
    if policy["max_source_bytes"] > policy["max_case_bytes"]:
        raise ProbentiumError("resource_policy_inconsistent", 2)
    return dict(policy)


def resolve(policy=None, *, defaults=None):
    if policy is not None:
        return validate(policy)
    values = dict(DEFAULTS)
    if defaults is not None:
        if not isinstance(defaults, dict) or not set(defaults) <= set(DEFAULTS):
            raise ProbentiumError("invalid_resource_defaults", 2)
        values.update(defaults)
    return validate({"schema": SCHEMA, **values, **FIXED})


def configured(**overrides):
    if not set(overrides) <= set(DEFAULTS):
        raise ProbentiumError("invalid_resource_policy", 2)
    return resolve(defaults=overrides)


def digest(policy):
    return object_digest(validate(policy), "PROBENTIUM-RESOURCE-POLICY-V1")


def parse_config(config):
    fields = {"format", "max_records", "max_line_bytes"}
    if not isinstance(config, dict) or set(config) not in (fields, fields | {"resource_policy"}):
        raise ProbentiumError("invalid_snapshot_parse_config", 4)
    if not isinstance(config["format"], str) or len(config["format"]) > 64:
        raise ProbentiumError("invalid_snapshot_parse_config", 4)
    if (type(config["max_records"]) is not int or not 1 <= config["max_records"] <= HARD_CAPS["max_import_records"]
            or type(config["max_line_bytes"]) is not int or not 1 <= config["max_line_bytes"] <= FIXED["max_message_bytes"]):
        raise ProbentiumError("invalid_snapshot_parse_config", 4)
    if "resource_policy" in config:
        policy = validate(config["resource_policy"])
        if config["max_records"] != policy["max_import_records"] or config["max_line_bytes"] != policy["max_message_bytes"]:
            raise ProbentiumError("parse_resource_policy_mismatch", 4)
        return policy
    if config["max_records"] > 1048576:
        raise ProbentiumError("legacy_resource_config_out_of_range", 4)
    return None
