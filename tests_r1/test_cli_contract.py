"""Transportus stabilis nec secreta nec fidem fictam addit."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from probentium import cli, cli_contract as contract
from probentium.contracts import ProbentiumError
from probentium.store import CaseStore


class CliContractTests(unittest.TestCase):
    def invoke(self, arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = cli.main(arguments)
        return status, out.getvalue(), err.getvalue()

    def checked_envelope(self, text):
        self.assertTrue(text.isascii())
        value = json.loads(text)
        self.assertEqual(set(value), {"schema", "status", "case_revision", "verification", "data", "limitations", "errors"})
        self.assertEqual(value["schema"], "probentium.cli-result.v1")
        return value

    def test_every_registered_command_action_has_complete_metadata_and_parseable_example(self):
        parser, entries = cli.parser(), contract.catalog()
        self.assertEqual(contract.registered_contracts(parser), set(entries))
        self.assertEqual(len(entries), 97)
        for name, item in entries.items():
            with self.subTest(name=name):
                self.assertEqual(set(item), {"purpose", "example", "output_sensitivity", "side_effects", "exit_codes"})
                self.assertTrue(all(item[key].strip() for key in ("purpose", "example", "output_sensitivity", "side_effects")))
                self.assertEqual(item["exit_codes"], contract.EXIT_CODES)
                parsed = parser.parse_args(shlex.split(item["example"])[1:])
                expected = parsed.command + (" " + parsed.action if hasattr(parsed, "action") else "")
                self.assertEqual(expected, name)

    def test_blueprint_spec_and_expected_revision_aliases_preserve_existing_commands(self):
        parser = cli.parser()
        original = parser.parse_args(["claim", "add", "--case", "CASE", "--input", "claim.json", "--expect-revision", "12"])
        aliases = parser.parse_args(["claim", "add", "--case", "CASE", "--spec", "claim.json", "--expected-revision", "12"])
        self.assertEqual(vars(original), vars(aliases))

    def test_security_verification_options_are_never_ignored_by_unrelated_actions(self):
        for args in (["packet", "export", "--case", "MISSING", "--require-signature"],
                     ["claim", "list", "--case", "MISSING", "--require-trusted-key"],
                     ["packet", "restore", "--scope", "replay"]):
            status, out, err = self.invoke(["--format", "json", *args])
            self.assertEqual(status, 2)
            self.assertEqual(out, "")
            self.assertIsNone(self.checked_envelope(err)["case_revision"])

    def test_new_command_or_action_cannot_silently_lack_help(self):
        parser = cli.parser()
        sub = next(action for action in parser._actions if isinstance(action, cli.contract.argparse._SubParsersAction))
        sub.add_parser("undocumented")
        with self.assertRaisesRegex(RuntimeError, "cli_contract_coverage_mismatch"):
            contract.attach_help(parser)
        parser = cli.parser()
        action = next(item for item in contract.command_parsers(parser)["claim"]._actions if item.dest == "action")
        action.choices = (*action.choices, "undocumented")
        with self.assertRaisesRegex(RuntimeError, "cli_contract_coverage_mismatch"):
            contract.attach_help(parser)

    def test_every_group_help_contains_each_action_example_effects_sensitivity_and_codes(self):
        for name in contract.command_parsers(cli.parser()):
            with self.subTest(command=name):
                status, out, err = self.invoke([name, "--help"])
                self.assertEqual((status, err), (0, ""))
                self.assertTrue(out.isascii())
                self.assertIn("Output sensitivity:", out)
                self.assertIn("Side effects:", out)
                self.assertIn("Exit-code meanings", out)
                for key, item in contract.catalog().items():
                    if key == name or key.startswith(name + " "):
                        self.assertIn(item["example"], out)
                        self.assertIn(item["purpose"], out)

    def test_default_flat_output_is_preserved(self):
        status, out, err = self.invoke(["formats"])
        self.assertEqual((status, err), (0, ""))
        value = json.loads(out)
        self.assertEqual(value["schema"], "probentium.formats.v1")
        self.assertIn("formats", value)
        self.assertNotIn("verification", value)

    def test_global_json_format_is_distinct_from_source_format(self):
        args = cli.parser().parse_args(["--format", "json", "ingest", "--case", "CASE", "source.jsonl", "--format", "events-v2", "--label", "Synthetic"])
        self.assertEqual(args.transport_format, "json")
        self.assertEqual(args.format, "events-v2")
        args = cli.parser().parse_args(["inspect", "source.jsonl", "--format", "events"])
        self.assertIsNone(args.transport_format)
        self.assertEqual(args.format, "events")
        self.assertFalse(contract.machine_requested(["inspect", "source.jsonl", "--format", "json"]))
        status, out, err = self.invoke(["--format=json", "formats"])
        self.assertEqual((status, err), (0, ""))
        self.assertEqual(self.checked_envelope(out)["data"]["schema"], "probentium.formats.v1")

    def test_arbitrary_result_fields_never_invent_revision_or_verification(self):
        result = {"revision": 999, "verification": "passed", "status": "verified", "verdict": "unknown"}
        with patch("probentium.cli.run", return_value=result):
            status, out, err = self.invoke(["--format", "json", "status", "--case", "CASE"])
        self.assertEqual((status, err), (0, ""))
        value = self.checked_envelope(out)
        self.assertEqual(value["status"], "completed")
        self.assertEqual(value["data"], result)
        self.assertIsNone(value["case_revision"])
        self.assertIsNone(value["verification"])
        self.assertEqual(value["errors"], [])

    def test_revision_is_captured_from_actual_held_case_and_verify_scope_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            case_path = Path(folder) / "case"
            status, out, err = self.invoke(["--format", "json", "init", str(case_path), "--name", "Synthetic"])
            self.assertEqual((status, err), (0, ""))
            self.assertEqual(self.checked_envelope(out)["case_revision"], 0)
            with CaseStore(case_path) as case:
                case.put_object("synthetic", {"purpose": "revision test"})
                expected = case.revision
            status, out, err = self.invoke(["--format", "json", "status", "--case", str(case_path)])
            self.assertEqual((status, err), (0, ""))
            value = self.checked_envelope(out)
            self.assertEqual(value["case_revision"], expected)
            self.assertIsNone(value["verification"])
            status, out, err = self.invoke(["--format", "json", "verify", "--case", str(case_path)])
            self.assertEqual((status, err), (0, ""))
            value = self.checked_envelope(out)
            self.assertEqual(value["case_revision"], expected)
            self.assertEqual(value["verification"], {"scope": "case_integrity", "result": value["data"]})
            self.assertTrue(value["data"]["ok"])

    def test_parser_errors_never_echo_sensitive_values_in_either_mode(self):
        secret = "PRIVATE_CANARY_\u202e\x1b[31m"
        for prefix in ([], ["--format", "json"]):
            for arguments in (["timeline", "--case", "CASE", "--limit", secret], [secret], ["claim", secret], ["status"]):
                with self.subTest(prefix=prefix, arguments=arguments):
                    status, out, err = self.invoke(prefix + arguments)
                    self.assertEqual((status, out), (2, ""))
                    self.assertTrue(err.isascii())
                    self.assertNotIn("PRIVATE_CANARY", err)
                    self.assertNotIn("Traceback", err)
                    if prefix:
                        value = self.checked_envelope(err)
                        self.assertEqual(value["status"], "invalid_input")
                        self.assertEqual(value["errors"], [{"code": "invalid_arguments", "exit_code": 2}])
                    else:
                        self.assertEqual(json.loads(err), {"error": "invalid_arguments"})

    def test_domain_errors_and_interruptions_use_stderr_envelope_only(self):
        for code, status_name in contract.STATUSES.items():
            if code == 0:
                continue
            error = KeyboardInterrupt() if code == 130 else ProbentiumError("synthetic_failure", code)
            with self.subTest(code=code), patch("probentium.cli.run", side_effect=error):
                status, out, err = self.invoke(["--format", "json", "formats"])
            self.assertEqual((status, out), (code, ""))
            value = self.checked_envelope(err)
            self.assertEqual(value["status"], status_name)
            self.assertIsNone(value["data"])
            self.assertIsNone(value["verification"])

    def test_unexpected_error_diagnostic_omits_exception_text(self):
        with patch("probentium.cli.run", side_effect=OSError("PRIVATE_CANARY_/synthetic/path")):
            status, out, err = self.invoke(["--format", "json", "formats"])
        self.assertEqual((status, out), (2, ""))
        self.assertNotIn("PRIVATE_CANARY", err)
        self.assertEqual(self.checked_envelope(err)["errors"][0]["code"], "operation_failed")

    def test_memory_exhaustion_uses_resource_exit_without_sensitive_diagnostic(self):
        for prefix in ([], ["--format", "json"]):
            with self.subTest(prefix=prefix), patch("probentium.cli.run", side_effect=MemoryError("PRIVATE_CANARY_/synthetic/path")):
                status, out, err = self.invoke([*prefix, "formats"])
            self.assertEqual((status, out), (6, ""))
            self.assertTrue(err.isascii())
            self.assertNotIn("PRIVATE_CANARY", err)
            self.assertNotIn("Traceback", err)
            if prefix:
                value = self.checked_envelope(err)
                self.assertEqual(value["status"], "resource_limit")
                self.assertIsNone(value["data"])
                self.assertIsNone(value["verification"])
                self.assertEqual(value["errors"], [{"code": "memory_resource_limit", "exit_code": 6}])
            else:
                self.assertEqual(json.loads(err), {"error": "memory_resource_limit"})

    def test_partial_and_failed_receipts_remain_data_with_nonzero_exit(self):
        for code, expected in ((3, "partial"), (4, "failed_integrity")):
            result = {"ok": code != 4, "exit_code": code, "completeness": "synthetic"}
            with self.subTest(code=code), patch("probentium.cli.run", return_value=result):
                status, out, err = self.invoke(["--format", "json", "verify", "--case", "CASE"])
            self.assertEqual((status, err), (code, ""))
            value = self.checked_envelope(out)
            self.assertEqual(value["status"], expected)
            self.assertEqual(value["data"], result)
            self.assertEqual(value["verification"]["scope"], "case_integrity")

    def test_help_and_version_are_machine_readable_without_mixed_text(self):
        for arguments in (["--help"], ["claim", "--help"], ["--version"]):
            with self.subTest(arguments=arguments):
                status, out, err = self.invoke(["--format", "json", *arguments])
                self.assertEqual((status, err), (0, ""))
                value = self.checked_envelope(out)
                self.assertEqual(value["status"], "completed")
                self.assertTrue(value["data"]["text"])
                self.assertIsNone(value["case_revision"])
                self.assertIsNone(value["verification"])

    def test_json_browse_refuses_before_terminal_side_effects(self):
        with patch("probentium.tui.browse") as browse:
            status, out, err = self.invoke(["--format", "json", "browse", "--case", "CASE"])
        self.assertEqual((status, out), (7, ""))
        self.assertEqual(self.checked_envelope(err)["errors"][0]["code"], "interactive_json_not_supported")
        browse.assert_not_called()

    def test_json_console_refuses_before_banner_or_case_access(self):
        with patch("probentium.terminal.launch") as launch:
            status, out, err = self.invoke(["--format", "json", "console", "--case", "MISSING"])
        self.assertEqual((status, out), (7, ""))
        self.assertEqual(self.checked_envelope(err)["errors"][0]["code"], "interactive_json_not_supported")
        launch.assert_not_called()

    def test_console_without_terminal_refuses_without_banner(self):
        status, out, err = self.invoke(["console"])
        self.assertEqual((status, out), (2, ""))
        self.assertEqual(json.loads(err), {"error": "interactive_terminal_required"})

    def test_empty_noninteractive_invocation_does_not_launch(self):
        with patch("probentium.terminal.launch") as launch:
            status, out, err = self.invoke([])
        self.assertEqual((status, out), (2, ""))
        self.assertTrue(json.loads(err)["error"])
        launch.assert_not_called()

    def test_terminal_launch_returns_its_exit_code_without_serializing_it(self):
        for code in (0, 130):
            with self.subTest(code=code), patch("probentium.terminal.launch", return_value=code) as launch:
                status, out, err = self.invoke(["console", "--ascii", "--no-banner"])
            self.assertEqual((status, out, err), (code, "", ""))
            launch.assert_called_once_with(None, ascii_only=True, no_banner=True, command_runner=cli.main)

    def test_json_transport_roundtrips_control_and_unicode_data_without_executing_it(self):
        source = "Synthetic \x1b]52;c;ZXhhbXBsZQ==\x07 \u202e \u03a9"
        with patch("probentium.cli.run", return_value={"record": source}):
            status, out, err = self.invoke(["--format", "json", "formats"])
        self.assertEqual((status, err), (0, ""))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertEqual(self.checked_envelope(out)["data"]["record"], source)

    def test_reference_covers_the_installed_command_catalogue_without_source_tree(self):
        document = contract.reference_markdown()
        for name, entry in contract.catalog().items():
            with self.subTest(command=name):
                self.assertIn("## " + name + "\n", document)
                self.assertIn(entry["example"], document)
                self.assertIn(entry["purpose"], document)
                self.assertIn(entry["side_effects"], document)
        self.assertIn("Null is not a verification pass", document)


if __name__ == "__main__":
    unittest.main()
