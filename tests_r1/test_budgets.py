"""Fines filii et exitus sine verbis privatis probantur."""
from copy import deepcopy
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probentium import budgets
from probentium.contracts import ProbentiumError
from probentium.store import CaseStore


class BudgetTests(unittest.TestCase):
    def test_configuration_copies_and_rejects_ambiguous_types(self):
        source = {"max_claims": 2000}
        original = deepcopy(source)
        value = budgets.normalize_analysis_limits(source)
        self.assertEqual(source, original)
        self.assertEqual(value["max_claims"], 2000)
        self.assertEqual(value["max_events"], 100000)
        for bad in ([], {"schema": "other"}, {"max_claims": True}, {"max_claims": 1.0}, {"max_events": 100001}, {"max_memory_bytes": 2 ** 31}):
            with self.subTest(bad=bad), self.assertRaises(ProbentiumError):
                budgets.normalize_analysis_limits(bad)

    def test_strict_unsupported_fails_before_child_or_case_open(self):
        with patch.object(budgets.sys, "platform", "darwin"), patch.object(budgets.subprocess, "Popen") as launch:
            with self.assertRaises(ProbentiumError) as caught:
                budgets.run_case_analysis("/not-a-real-case", "correlate", {"template": "post_auth_process", "window_us": "5"}, resource_mode="strict")
            self.assertEqual(caught.exception.code, "strict_resource_mode_unsupported")
            launch.assert_not_called()

    def test_unknown_operations_arguments_and_resource_mode_fail_before_launch(self):
        with patch.object(budgets.subprocess, "Popen") as launch:
            for op, args, mode in (("shell", {}, "strict"), ("correlate", {"command": "private-canary"}, "strict"),
                                   ("correlate", {"template": "post_auth_process", "window_us": "5"}, "disabled")):
                with self.subTest(op=op, mode=mode), self.assertRaises(ProbentiumError):
                    budgets.run_case_analysis("case", op, args, resource_mode=mode)
            launch.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process limit")
    def test_real_child_address_space_limit_rejects_allocation_parent_unchanged(self):
        before = resource.getrlimit(resource.RLIMIT_AS)
        script = "from probentium.budgets import _apply_process_limits, normalize_analysis_limits\n_apply_process_limits(normalize_analysis_limits({'max_memory_bytes':67108864}))\ntry:\n bytearray(134217728)\nexcept MemoryError:\n print('limited')\nelse:\n raise SystemExit(1)\n"
        result = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (0, b"limited\n"), result.stderr)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_AS), before)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process limit")
    def test_case_analysis_child_is_real_bounded_and_digest_configured(self):
        before = resource.getrlimit(resource.RLIMIT_AS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case"
            with CaseStore.create(path, "Synthetic budget case"):
                pass
            result = budgets.run_case_analysis(path, "correlate", {"template": "post_auth_process", "window_us": "5"}, resource_mode="strict")
        self.assertEqual(result["result"]["execution_state"], "complete")
        self.assertEqual(result["resources"]["memory_mode"], "hard_enforced")
        self.assertEqual(result["resources"]["limits"], result["result"]["analysis"]["limits"]["analysis_limits"])
        self.assertGreater(result["resources"]["parent_observed_peak_rss_bytes"], 0)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_AS), before)

    def test_monitored_capability_is_not_hard_enforcement(self):
        with patch.object(budgets.sys, "platform", "darwin"):
            value = budgets.capabilities()
        self.assertFalse(value["strict_supported"])
        self.assertEqual(value["memory_mode"], "monitored")
        self.assertIn("sampled_RSS_can_miss_short_peaks", value["limitations"])

    def test_read_only_operations_bind_expected_revision_inside_child(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case"
            with CaseStore.create(path):
                pass
            for operation, arguments in (("correlate", {"template": "post_auth_process", "window_us": "5"}),
                                         ("correlate_many", {"requests": []}), ("sensitivity", {"claim_ids": []})):
                with self.subTest(operation=operation), self.assertRaises(ProbentiumError) as caught:
                    budgets.run_case_analysis(path, operation, {**arguments, "expected_revision": 1})
                self.assertEqual((caught.exception.code, caught.exception.exit_code), ("revision_conflict", 5))
            for bad in (True, -1, "0"):
                with self.assertRaises(ProbentiumError):
                    budgets._validate_job("correlate_many", {"requests": [], "expected_revision": bad})

    def test_invalid_domain_inputs_preserve_fixed_exit_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case"
            with CaseStore.create(path):
                pass
            inputs = [("evaluate", {"claim_id": "f" * 64}, "object_not_found", 2),
                      ("correlate", {"template": "post_auth_process", "window_us": "private-canary"}, "invalid_microsecond_string", 2),
                      ("correlate", {"template": "private-canary", "window_us": "1"}, "correlation_template_unsupported", 7),
                      ("correlate_many", {"requests": [{"template": "post_auth_process", "window_us": "1", "extra": True}]}, "invalid_analysis_fields", 2)]
            for operation, arguments, code, exit_code in inputs:
                with self.subTest(operation=operation, code=code), self.assertRaises(ProbentiumError) as caught:
                    budgets.run_case_analysis(path, operation, arguments)
                self.assertEqual((caught.exception.code, caught.exception.exit_code), (code, exit_code))
                self.assertNotIn("private-canary", str(caught.exception))

    def test_hostile_child_error_receipts_only_allow_known_exact_pairs(self):
        limits = budgets.normalize_analysis_limits()
        available = budgets.capabilities()
        for error, exit_code, returncode in (({}, 6, 6), ([], 6, 6), ("private-canary", 2, 2),
                                             ("analysis_memory_limit", 2, 2), ("analysis_memory_limit", True, 1),
                                             ("analysis_memory_limit", 6, 0)):
            with self.subTest(error=error, exit_code=exit_code), self.assertRaises(ProbentiumError) as caught:
                budgets._validate_child_response({"schema": "probentium.analysis-child.v1", "error": error, "exit_code": exit_code}, returncode, limits, available)
            self.assertEqual((caught.exception.code, caught.exception.exit_code), ("analysis_process_failed", 6))
        with self.assertRaises(ProbentiumError) as caught:
            budgets._validate_child_response({"schema": "probentium.analysis-child.v1", "error": "analysis_memory_limit", "exit_code": 6}, 6, limits, available)
        self.assertEqual((caught.exception.code, caught.exception.exit_code), ("analysis_memory_limit", 6))

    def test_hostile_child_success_receipt_cannot_claim_other_limits_or_revision(self):
        limits = budgets.normalize_analysis_limits({"max_events": 1})
        available = budgets.capabilities()
        value = {"schema": "probentium.analysis-child.v1", "result": {}, "input_revision": 1, "case_revision": 1,
                 "resources": {"limits": limits, "memory_mode": available["memory_mode"], "mechanism": available["mechanism"]}}
        budgets._validate_child_response(value, 0, limits, available)
        for modify in (lambda v: v.update(case_revision=True), lambda v: v.update(case_revision=0),
                       lambda v: v.update(extra="private-canary"), lambda v: v.update(result=[]),
                       lambda v: v["resources"]["limits"].update(max_events=True),
                       lambda v: v["resources"].update(mechanism="unproven")):
            bad = deepcopy(value); modify(bad)
            with self.assertRaises(ProbentiumError):
                budgets._validate_child_response(bad, 0, limits, available)

    def test_wall_limit_terminates_worker_without_returning_a_partial_result(self):
        from unittest.mock import Mock
        process = Mock()
        process.poll.return_value = None
        with patch.object(budgets.subprocess, "Popen", return_value=process), patch.object(budgets.time, "monotonic", side_effect=[0, 2]), patch.object(budgets, "_stop") as stop:
            with self.assertRaises(ProbentiumError) as caught:
                budgets.run_case_analysis("case", "correlate", {"template": "post_auth_process", "window_us": "5"}, limits={"max_wall_seconds": 1})
            self.assertEqual(caught.exception.code, "analysis_timeout")
            stop.assert_called_once_with(process)
