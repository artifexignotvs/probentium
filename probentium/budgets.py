"""Fines declarati ante opus; processus parens numquam restringitur."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .contracts import ProbentiumError, canonical_bytes, strict_json

SCHEMA = "probentium.analysis-limits.v1"
DEFAULTS = {
    "max_events": 100000, "max_claims": 1000, "max_findings": 20000,
    "max_support_refs": 250000, "max_relations": 250000, "max_dependency_edges": 250000,
    "max_time_variables": 32, "max_scenarios": 64, "max_report_bytes": 64 * 1024 ** 2,
    "max_memberships": 1000000, "max_memory_bytes": 1024 ** 3, "max_wall_seconds": 900,
}
HARD_CAPS = {**DEFAULTS, "max_claims": 10000, "max_memberships": 10000000}
_ERROR_EXITS = {
    **dict.fromkeys(("invalid_analysis_limits", "analysis_operation_invalid", "analysis_arguments_invalid",
                     "invalid_persist_flag", "investigation_object_kind_mismatch", "invalid_analysis_data",
                     "scenario_clock_must_widen", "dependency_reference_missing", "correlation_templates_required",
                     "duplicate_correlation_template"), 2),
    **dict.fromkeys(("analysis_resource_receipt_invalid", "analysis_pagination_incomplete", "invalid_investigation_object"), 4),
    "revision_conflict": 5,
    **dict.fromkeys(("analysis_event_limit", "analysis_data_size_limit", "claim_count_limit", "analysis_membership_limit",
                     "analysis_relation_limit", "analysis_support_limit", "analysis_finding_limit", "analysis_time_variable_limit",
                     "analysis_report_limit", "analysis_memory_limit", "analysis_timeout", "analysis_process_failed",
                     "correlation_candidate_limit", "correlation_scan_limit", "correlation_template_limit",
                     "dependency_closure_limit", "dependency_edge_limit", "sensitivity_membership_limit",
                     "explicit_sensitivity_plan_required"), 6),
    **dict.fromkeys(("strict_resource_mode_unsupported", "analysis_monitor_unavailable", "analysis_resource_setup_failed",
                     "correlation_template_unsupported"), 7),
}

# Signa fixa tantum fines processus transeunt.
_ERROR_EXITS.update({
    **dict.fromkeys((
        'calendar_range_exceeded', 'case_already_exists', 'case_create_failed',
        'case_directory_permissions', 'case_file_permissions', 'claim_history_mismatch',
        'clock_artifacts_required', 'clock_basis_required', 'conflicting_analysis_limits',
        'correlation_templates_required', 'count_anchor_window_required', 'dependency_cycle',
        'dependency_reference_missing', 'duplicate_analysis_name', 'duplicate_analysis_reference',
        'duplicate_claim_id', 'duplicate_clock_overlay', 'duplicate_correlation_template',
        'duplicate_dependency_edge', 'duplicate_json_key', 'empty_selector_values',
        'empty_time_interval', 'event_not_found', 'event_not_in_saved_witness_excerpt',
        'family_artifacts_required', 'field_namespace_mismatch', 'floating_point_not_supported',
        'identity_reference_missing', 'inconsistent_interpretation_identity', 'inconsistent_shared_error',
        'integer_out_of_range', 'invalid_analysis_fields', 'invalid_analysis_input_binding',
        'invalid_analysis_integer', 'invalid_analysis_object', 'invalid_analysis_reference',
        'invalid_analysis_result', 'invalid_canonical_value', 'invalid_clock_families',
        'invalid_cursor_sort_key', 'invalid_duplicate_partition', 'invalid_event_source_selection',
        'invalid_expected_revision', 'invalid_identifier', 'invalid_identity_assertion',
        'invalid_identity_binding', 'invalid_integrity_status', 'invalid_interval_boundary',
        'invalid_json', 'invalid_microsecond_string', 'invalid_object_kind',
        'invalid_object_schema', 'invalid_object_structure', 'invalid_object_text',
        'invalid_object_value', 'invalid_persist_flag', 'invalid_query',
        'invalid_scope_parse_selection', 'invalid_scoped_analysis_result', 'invalid_selector_value',
        'invalid_snapshot_table', 'invalid_source_coverage', 'invalid_text',
        'invalid_time_expression', 'invalid_time_filter', 'invalid_timestamp',
        'investigation_object_kind_mismatch', 'negative_order_window', 'object_not_found',
        'pair_predicate_selector_must_be_empty', 'scenario_clock_must_widen', 'scope_parse_selection_required',
        'scope_parse_selection_unavailable', 'selector_value_required', 'source_not_found',
        'source_not_resumable', 'synthetic_case_declaration_required', 'synthetic_demo_pair_missing',
        'time_magnitude_limit', 'timezone_required', 'unexpected_selector_value',
        'unsupported_analysis_field', 'unsupported_count_unit', 'unsupported_event_kind',
        'unsupported_selector_operator', 'unsupported_value_type',
    ), 2),
    **dict.fromkeys((
        'artifact_authorized_unavailable',
    ), 3),
    **dict.fromkeys((
        'acquisition_identity_mismatch', 'acquisition_revision_invalid', 'active_parse_run_missing',
        'analysis_claim_binding_mismatch', 'analysis_coverage_accounting_mismatch', 'analysis_coverage_binding_mismatch',
        'analysis_coverage_complete_invalid', 'analysis_coverage_disposition_invalid', 'analysis_coverage_event_count_mismatch',
        'analysis_coverage_prefix_invalid', 'analysis_coverage_range_invalid', 'analysis_coverage_state_invalid',
        'analysis_dependency_replay_mismatch', 'analysis_evaluation_binding_mismatch', 'analysis_input_integrity_failed',
        'analysis_input_replay_mismatch', 'analysis_pagination_incomplete', 'analysis_result_integrity_failed',
        'analysis_result_replay_mismatch', 'analysis_source_binding_mismatch', 'artifact_identity_mismatch',
        'batch_source_changed', 'case_metadata_invalid', 'case_open_failed',
        'case_schema_mismatch', 'catalog_digest_mismatch', 'catalog_identity_invalid',
        'database_integrity_failed', 'database_operation_failed', 'database_path_changed',
        'database_recovery_required', 'duplicate_normalized_observation', 'evaluation_dependency_analysis_mismatch',
        'evaluation_dependency_binding_invalid', 'evaluation_integrity_failed', 'event_disposition_mismatch',
        'event_identity_mismatch', 'event_record_count_invalid', 'evidence_changed_during_read',
        'evidence_copy_failed', 'evidence_digest_mismatch', 'evidence_missing',
        'evidence_read_truncated', 'evidence_size_mismatch', 'explanation_claim_binding_invalid',
        'explanation_coverage_binding_invalid', 'explanation_historical_witness_invalid', 'explanation_integrity_failed',
        'explanation_interpretation_binding_invalid', 'explanation_lineage_binding_invalid', 'explanation_lineage_schema_invalid',
        'explanation_record_missing', 'explanation_result_binding_invalid', 'explanation_schema_invalid',
        'explanation_witness_missing', 'explanation_witness_set_invalid', 'invalid_blob_entry',
        'invalid_investigation_object', 'invalid_parser_manifest', 'invalid_parser_manifest_member',
        'object_identity_mismatch', 'parse_accounting_digest_mismatch', 'parse_accounting_invalid',
        'parse_run_identity_mismatch', 'parser_approval_binding_invalid', 'parser_approval_required',
        'record_digest_mismatch', 'record_identity_mismatch', 'record_not_found',
        'record_range_invalid', 'resume_integrity_failed', 'snapshot_integrity_failed',
        'source_identity_mismatch', 'stored_object_digest_mismatch', 'stored_object_invalid',
        'stored_structure_invalid', 'time_expression_digest_mismatch', 'unexpected_blob_entry',
        'witness_raw_binding_invalid',
    ), 4),
    **dict.fromkeys((
        'case_locked', 'claim_previous_revision_required', 'demonstration_already_initialized',
        'resume_resource_policy_mismatch', 'revision_conflict', 'scope_revision_conflict',
    ), 5),
    **dict.fromkeys((
        'acquisition_count_limit', 'analysis_data_size_limit', 'analysis_event_limit',
        'analysis_finding_limit', 'analysis_reference_limit', 'analysis_report_limit',
        'artifact_size_limit', 'blob_inventory_limit', 'case_event_limit',
        'case_evidence_limit', 'case_record_limit', 'clock_segment_limit',
        'correlation_candidate_limit', 'correlation_scan_limit', 'database_size_limit',
        'demonstration_event_limit', 'dependency_closure_limit', 'dependency_edge_limit',
        'dependency_family_premise_limit', 'dependency_recomputation_limit', 'explanation_event_limit',
        'explanation_record_limit', 'explicit_sensitivity_plan_required', 'input_size_limit',
        'insufficient_disk_space', 'json_depth_limit', 'object_count_limit',
        'object_listing_limit', 'object_size_limit', 'object_structure_limit',
        'sensitivity_membership_limit', 'shared_error_limit', 'snapshot_object_limit',
        'snapshot_size_limit', 'storage_resource_limit', 'stored_resource_hard_cap_exceeded',
    ), 6),
    **dict.fromkeys((
        'composite_raw_requires_segments', 'correlation_template_unsupported', 'format_unsupported',
        'legacy_locator_layout_requires_copy', 'resume_parser_version_unavailable', 'unsupported_analysis_data',
        'unsupported_case_schema', 'unsupported_claim_schema', 'unsupported_clock_model',
        'unsupported_journal_mode', 'unsupported_predicate', 'unsupported_scenario_schema',
    ), 7),
})


def normalize_analysis_limits(overrides=None):
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, dict) or set(overrides) - (set(DEFAULTS) | {"schema"}):
        raise ProbentiumError("invalid_analysis_limits")
    if "schema" in overrides and overrides["schema"] != SCHEMA:
        raise ProbentiumError("invalid_analysis_limits")
    result = {"schema": SCHEMA, **DEFAULTS}
    for name, value in overrides.items():
        if name == "schema":
            continue
        minimum = 64 * 1024 ** 2 if name == "max_memory_bytes" else 1024 if name == "max_report_bytes" else 1
        if type(value) is not int or not minimum <= value <= HARD_CAPS[name]:
            raise ProbentiumError("invalid_analysis_limits")
        result[name] = value
    return result


class AnalysisBudget:
    """Numeri exacti et mora per intervalla finita observantur."""
    def __init__(self, limits):
        self.limits = normalize_analysis_limits(limits)
        self.relations = self.support_refs = 0
        self.deadline = time.monotonic() + self.limits["max_wall_seconds"]

    def relation(self, variables=0):
        if variables > self.limits["max_time_variables"]:
            raise ProbentiumError("analysis_time_variable_limit", 6)
        self.relations += 1
        if self.relations > self.limits["max_relations"]:
            raise ProbentiumError("analysis_relation_limit", 6)
        if self.relations % 256 == 0:
            self.check_time()

    def support(self, count):
        self.support_refs += count
        if self.support_refs > self.limits["max_support_refs"]:
            raise ProbentiumError("analysis_support_limit", 6)
        self.check_time()

    def check_time(self):
        if time.monotonic() > self.deadline:
            raise ProbentiumError("analysis_timeout", 6)


def capabilities():
    linux = sys.platform.startswith("linux")
    monitored = linux or sys.platform == "darwin"
    return {"schema": "probentium.analysis-resource-capabilities.v1", "strict_supported": linux,
            "memory_mode": "hard_enforced" if linux else "monitored" if monitored else "unavailable",
            "mechanism": "child_RLIMIT_AS_and_parent_RSS" if linux else "parent_ps_RSS" if monitored else "none",
            "memory_metric": "virtual_address_space_limit_and_sampled_RSS" if linux else "sampled_RSS",
            "monitor_interval_ms": 100, "network_sandbox": False,
            "limitations": ["sampled_RSS_can_miss_short_peaks", "process_limits_are_not_a_security_sandbox", "a_committed_object_can_precede_a_late_process_failure"]}


def _validate_job(operation, arguments):
    allowed = {
        "evaluate": ({"claim_id", "expected_revision", "persist"}, {"claim_id"}),
        "correlate": ({"template", "window_us", "threshold", "expected_revision"}, {"template", "window_us"}),
        "correlate_many": ({"requests", "expected_revision"}, {"requests"}),
        "scenario": ({"claim_ids", "scenario", "expected_revision", "persist"}, {"claim_ids", "scenario"}),
        "sensitivity": ({"claim_ids", "family_ids", "limit", "expected_revision"}, {"claim_ids"}),
    }
    if type(operation) is not str or operation not in allowed:
        raise ProbentiumError("analysis_operation_invalid")
    permitted, required = allowed[operation]
    if not isinstance(arguments, dict) or set(arguments) - permitted or not required <= set(arguments):
        raise ProbentiumError("analysis_arguments_invalid")
    if "expected_revision" in arguments and arguments["expected_revision"] is not None and (type(arguments["expected_revision"]) is not int or not 0 <= arguments["expected_revision"] <= 9007199254740991):
        raise ProbentiumError("analysis_arguments_invalid")
    if len(canonical_bytes(arguments)) > 1024 * 1024:
        raise ProbentiumError("analysis_arguments_invalid", 6)


def _rss_bytes(pid):
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/statm", "rb") as stream:
                values = stream.read(256).split()
            return int(values[1]) * os.sysconf("SC_PAGE_SIZE")
        if sys.platform == "darwin":
            result = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(pid)], check=True,
                                    capture_output=True, timeout=1, env={"PATH": os.defpath, "LC_ALL": "C"})
            return int(result.stdout.strip()) * 1024
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None
    return None


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def run_case_analysis(case_path, operation, arguments, *, limits=None, resource_mode="monitored"):
    """Vocetur ante apertionem casus in parente; mutex non hereditatur."""
    configured = normalize_analysis_limits(limits)
    _validate_job(operation, arguments)
    available = capabilities()
    if resource_mode not in ("strict", "monitored"):
        raise ProbentiumError("analysis_arguments_invalid")
    if resource_mode == "strict" and not available["strict_supported"]:
        raise ProbentiumError("strict_resource_mode_unsupported", 7)
    if available["memory_mode"] == "unavailable":
        raise ProbentiumError("analysis_monitor_unavailable", 7)
    path = os.path.abspath(os.fspath(case_path))
    job = {"schema": "probentium.analysis-job.v1", "case_path": path, "operation": operation,
           "arguments": arguments, "limits": configured, "resource_mode": resource_mode}
    with tempfile.TemporaryDirectory(prefix="probentium-analysis-") as directory:
        input_path, output_path = Path(directory) / "job.json", Path(directory) / "result.json"
        with input_path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical_bytes(job))
        process = subprocess.Popen([sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(Path(directory) / "bytecode"),
                                    "-m", "probentium.budgets", "--child", str(input_path), str(output_path)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   cwd=directory, env={"PATH": os.defpath, "LC_ALL": "C.UTF-8"}, close_fds=True)
        deadline, peak = time.monotonic() + configured["max_wall_seconds"], 0
        try:
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise ProbentiumError("analysis_timeout", 6)
                observed = _rss_bytes(process.pid)
                if observed is None and process.poll() is None:
                    raise ProbentiumError("analysis_monitor_unavailable", 7)
                peak = max(peak, observed or 0)
                if peak > configured["max_memory_bytes"]:
                    raise ProbentiumError("analysis_memory_limit", 6)
                time.sleep(.1)
            from testifex.safeio import bounded_read
            try:
                response = strict_json(bounded_read(output_path, configured["max_report_bytes"] + 65536),
                                       max_bytes=configured["max_report_bytes"] + 65536)
            except Exception:
                raise ProbentiumError("analysis_process_failed", 6) from None
            _validate_child_response(response, process.returncode, configured, available)
            resources = response["resources"]
            return {"schema": "probentium.analysis-execution.v1", "result": response["result"],
                    "input_revision": response["input_revision"], "case_revision": response["case_revision"],
                    "resources": {**resources, "requested_mode": resource_mode, "parent_observed_peak_rss_bytes": peak,
                                  "monitor_interval_ms": 100, "limitations": available["limitations"]}}
        finally:
            _stop(process)


def _validate_child_response(response, returncode, configured, available):
    if not isinstance(response, dict) or response.get("schema") != "probentium.analysis-child.v1":
        raise ProbentiumError("analysis_resource_receipt_invalid", 4)
    if set(response) == {"schema", "error", "exit_code"}:
        code, exit_code = response["error"], response["exit_code"]
        if (type(code) is not str or type(exit_code) is not int or _ERROR_EXITS.get(code) != exit_code
                or returncode != exit_code):
            raise ProbentiumError("analysis_process_failed", 6)
        raise ProbentiumError(code, exit_code)
    if (set(response) != {"schema", "result", "resources", "input_revision", "case_revision"}
            or returncode != 0 or not isinstance(response["result"], dict)):
        raise ProbentiumError("analysis_resource_receipt_invalid", 4)
    if any(type(response[key]) is not int or not 0 <= response[key] <= 9007199254740991 for key in ("input_revision", "case_revision")) or response["case_revision"] < response["input_revision"]:
        raise ProbentiumError("analysis_resource_receipt_invalid", 4)
    resources = response["resources"]
    try:
        validated_limits = normalize_analysis_limits(resources.get("limits")) if isinstance(resources, dict) else None
    except ProbentiumError:
        raise ProbentiumError("analysis_resource_receipt_invalid", 4) from None
    if (not isinstance(resources, dict) or set(resources) != {"limits", "memory_mode", "mechanism"}
            or validated_limits != resources["limits"]
            or resources != {"limits": configured, "memory_mode": available["memory_mode"], "mechanism": available["mechanism"]}):
        raise ProbentiumError("analysis_resource_receipt_invalid", 4)


def _apply_process_limits(limits):
    if sys.platform.startswith("linux"):
        import resource
        amount = limits["max_memory_bytes"]
        resource.setrlimit(resource.RLIMIT_AS, (amount, amount))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_AS) != (amount, amount):
            raise ProbentiumError("analysis_resource_setup_failed", 7)


def _child(input_path, output_path):
    response = {"schema": "probentium.analysis-child.v1"}
    exit_code = 0
    try:
        from testifex.safeio import bounded_read, write_new
        job = strict_json(bounded_read(Path(input_path), 2 * 1024 ** 2), max_bytes=2 * 1024 ** 2)
        if (not isinstance(job, dict) or set(job) != {"schema", "case_path", "operation", "arguments", "limits", "resource_mode"}
                or job["schema"] != "probentium.analysis-job.v1"):
            raise ProbentiumError("analysis_arguments_invalid")
        configured = normalize_analysis_limits(job["limits"])
        _validate_job(job["operation"], job["arguments"])
        if job["resource_mode"] not in ("strict", "monitored") or not isinstance(job["case_path"], str):
            raise ProbentiumError("analysis_arguments_invalid")
        if job["resource_mode"] == "strict" and not capabilities()["strict_supported"]:
            raise ProbentiumError("strict_resource_mode_unsupported", 7)
        _apply_process_limits(configured)
        from .store import CaseStore
        from . import investigation as inv
        functions = {"evaluate": inv.evaluate, "correlate": inv.correlate, "correlate_many": inv.correlate_many,
                     "scenario": inv.run_scenario, "sensitivity": inv.sensitivity}
        with CaseStore(job["case_path"]) as case:
            input_revision = case.revision
            arguments = dict(job["arguments"])
            expected = arguments.pop("expected_revision", None)
            if expected is not None and expected != input_revision:
                raise ProbentiumError("revision_conflict", 5)
            result = functions[job["operation"]](case, **arguments, analysis_limits=configured)
            case_revision = case.revision
        if len(canonical_bytes(result)) > configured["max_report_bytes"]:
            raise ProbentiumError("analysis_report_limit", 6)
        available = capabilities()
        response.update(result=result, input_revision=input_revision, case_revision=case_revision,
                        resources={"limits": configured, "memory_mode": available["memory_mode"], "mechanism": available["mechanism"]})
    except MemoryError:
        response.update(error="analysis_memory_limit", exit_code=6)
        exit_code = 6
    except ProbentiumError as exc:
        code = exc.code if type(exc.code) is str and _ERROR_EXITS.get(exc.code) == exc.exit_code else "analysis_process_failed"
        exit_code = _ERROR_EXITS[code]
        response.update(error=code, exit_code=exit_code)
    except Exception:
        response.update(error="analysis_process_failed", exit_code=6)
        exit_code = 6
    try:
        from testifex.safeio import write_new
        write_new(Path(output_path), canonical_bytes(response))
    except Exception:
        return 6
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--child":
        raise SystemExit(2)
    raise SystemExit(_child(sys.argv[2], sys.argv[3]))
