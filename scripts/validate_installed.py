#!/usr/bin/env python3
"""Exempla ficta extra arborem fontium et sine rete probantur."""
import argparse
import ctypes
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

MAX_OUTPUT = 16 * 1024 ** 2
DENIED = ("socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
          "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
          "socketcall", "io_uring_setup", "io_uring_enter", "io_uring_register")


class Rejected(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise Rejected(code)


def write_json(path, value):
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def clean_environment(python, directory):
    return {"PATH": str(Path(python).parent) + os.pathsep + os.defpath,
            "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0", "PIP_NO_INDEX": "1", "TMPDIR": str(directory / "temporary")}


def process(command, directory, environment, timeout=120):
    """Exitus et tempus finiuntur; error materiam privatam non reddit."""
    child = subprocess.Popen([str(item) for item in command], cwd=directory, env=environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True, start_new_session=True)
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name in outputs:
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "subprocess_timeout")
                for key, _ in selector.select(min(remaining, 1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[key.data].extend(data)
                    require(sum(map(len, outputs.values())) <= MAX_OUTPUT, "subprocess_output_limit")
        return child.wait(timeout=max(0.1, deadline - time.monotonic())), bytes(outputs["stdout"]), bytes(outputs["stderr"])
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def socket_probe():
    """Tentamen socket nullos fasciculos retis transmittit."""
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            opened = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            require(exc.errno == errno.EPERM, "network_probe_not_denied_by_policy")
        else:
            opened.close()
            raise Rejected("network_socket_not_denied")
    try:
        pair = socket.socketpair()
    except OSError as exc:
        require(exc.errno == errno.EPERM, "network_probe_not_denied_by_policy")
    else:
        for opened in pair:
            opened.close()
        raise Rejected("network_socketpair_not_denied")
    return {"ipv4_socket": "denied", "ipv6_socket": "denied", "unix_socket": "denied", "socketpair": "denied"}


def install_filter():
    require(sys.platform.startswith("linux"), "network_isolation_unsupported_platform")
    try:
        library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        raise Rejected("network_isolation_library_unavailable") from None
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    context = library.seccomp_init(0x7FFF0000)
    require(bool(context), "network_isolation_initialization_failed")
    installed = []
    try:
        for name in DENIED:
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                require(name not in {"socket", "socketpair", "connect", "sendto", "sendmsg"}, "network_isolation_syscall_unavailable")
                continue
            require(library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) == 0, "network_isolation_rule_failed")
            installed.append(name)
        require(libc.prctl(38, 1, 0, 0, 0) == 0, "network_isolation_privilege_guard_failed")
        require(library.seccomp_load(context) == 0, "network_isolation_load_failed")
    finally:
        library.seccomp_release(context)
    return {"status": "enforced", "mechanism": "linux_seccomp_errno_eperm",
            "denied_syscalls": installed, "before_exec_probe": socket_probe(),
            "scope": "validation child and descendants only", "descendant_policy": "inherited_by_fork_and_exec",
            "system_configuration_changed": False}


def bootstrap(directory, checkout):
    os.umask(0o077)
    try:
        isolation = install_filter()
    except (Rejected, AttributeError):
        write_json(directory / "receipt.json", {"schema": "probentium.installed-acceptance.v1", "status": "unsupported",
                   "synthetic_only": True, "checks": [], "network_isolation": {"status": "unsupported"},
                   "reason": "child_network_isolation_unavailable", "product_workflow_executed": False})
        return 7
    write_json(directory / "isolation.json", isolation)
    command = [sys.executable, "-I", str(Path(__file__).absolute()), "--_worker", str(directory), str(checkout)]
    os.execve(sys.executable, command, clean_environment(sys.executable, directory))


class Acceptance:
    def __init__(self, directory, checkout):
        self.directory, self.checkout = directory, checkout.resolve()
        self.environment = clean_environment(sys.executable, directory)
        self.checks, self.index = [], 0
        self.step = "initialization"
        self.receipt = {"schema": "probentium.installed-acceptance.v1", "status": "failed", "synthetic_only": True,
                        "python_version": ".".join(map(str, sys.version_info[:3])), "checks": self.checks,
                        "limitations": ["One synthetic acceptance run, not the full release or platform matrix.",
                                        "Network syscall denial is not a complete hostile-code or filesystem sandbox.",
                                        "Hash and signature checks do not establish factual truth or legal compliance."]}

    def passed(self, name, **metrics):
        self.checks.append({"name": name, "status": "passed", **metrics})

    def document(self, name, data):
        from probentium.contracts import canonical_bytes
        path = self.directory / (name + ".json")
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(canonical_bytes(data))
        return path

    def call(self, module, *arguments, expected=0, parse=True, timeout=120):
        self.index += 1
        command = [sys.executable, "-I", "-m", module, *arguments] if module else list(arguments)
        status, stdout, stderr = process(command, self.directory, self.environment, timeout)
        logs = self.directory / "diagnostics"
        for label, raw in (("stdout", stdout), ("stderr", stderr)):
            path = logs / ("step-%03d-%s.bin" % (self.index, label))
            with path.open("xb") as stream:
                os.chmod(path, 0o600)
                stream.write(raw)
        require(status == expected, "command_exit_mismatch")
        if not parse:
            return stdout
        try:
            value = json.loads(stdout)
        except (UnicodeError, ValueError):
            raise Rejected("command_json_invalid") from None
        require(isinstance(value, dict), "command_object_required")
        return value

    def run(self):
        started = time.monotonic()
        self.step = "inherited_network_policy"
        self.receipt["network_isolation"] = json.loads((self.directory / "isolation.json").read_bytes())
        self.receipt["network_isolation"]["after_exec_probe"] = socket_probe()
        libc = ctypes.CDLL(None)
        require(libc.prctl(21, 0, 0, 0, 0) == 2 and libc.prctl(39, 0, 0, 0, 0) == 1, "inherited_filter_missing")
        self.passed(self.step)

        self.step = "installed_module_origin"
        prefix = Path(sys.prefix).resolve()
        for name in ("probentium", "testifex"):
            module = importlib.import_module(name)
            location = Path(module.__file__).resolve()
            require(location.is_relative_to(prefix) and not location.is_relative_to(self.checkout), "installed_origin_mismatch")
        require(sys.prefix != sys.base_prefix, "isolated_environment_required")
        from probentium import __version__
        require(re.fullmatch(r"[A-Za-z0-9.+-]{1,64}", __version__) is not None, "package_version_invalid")
        self.receipt["tool_version"] = __version__
        self.passed(self.step, modules=["probentium", "testifex"], inside_environment=True, outside_checkout=True)

        self.step = "doctor"
        doctor = self.call("probentium", "doctor")
        require(doctor.get("version") == __version__ and doctor.get("offline_operation") is True and doctor.get("parser_process_isolation") is True, "doctor_contract_mismatch")
        self.passed(self.step)

        self.step = "extended_synthetic_demo"
        demo = self.call("probentium", "demo", self.directory / "review-demo")
        require(demo.get("synthetic") is True and demo.get("events") == 132, "demo_contract_mismatch")
        case = self.directory / "review-demo" / "case"
        require(Path(demo["case"]).resolve() == case.resolve(), "demo_output_location_mismatch")
        demonstration = demo["demonstration"]
        require(demonstration["unknown_verdict"] == "unknown" and demonstration["aligned_verdict"] == "entailed" and demonstration["scenario_verdict"] == "unresolved", "demo_semantics_mismatch")
        require("reporting" in demonstration, "extended_demo_missing")
        self.passed(self.step, normalized_events=132, unknown_verdict="unknown", aligned_verdict="entailed", widened_verdict="unresolved")

        self.step = "case_integrity"
        verified = self.call("probentium", "verify", "--case", case)
        require(verified.get("ok") is True and verified.get("completeness") == "acquired_bytes_present", "demo_integrity_failed")
        self.passed(self.step)

        self.step = "claim_explanation_and_currentness"
        aligned_id, unknown_id = demonstration["aligned_evaluation_id"], demonstration["unknown_evaluation_id"]
        explained = self.call("probentium", "claim", "explain", "--case", case, "--id", aligned_id)
        old = self.call("probentium", "claim", "stale", "--case", case, "--id", unknown_id)
        current = self.call("probentium", "claim", "stale", "--case", case, "--id", aligned_id)
        require(explained.get("paths") and old.get("status") == "stale" and current.get("status") == "current", "claim_history_mismatch")
        self.passed(self.step, previous="stale", aligned="current")

        self.step = "bounded_analysis_child"
        correlation = self.document("bounded-correlation", {"template": "auth_after_failures", "window_us": "300000000", "threshold": 5})
        receipt = self.call("probentium", "correlate", "run", "--case", case, "--input", correlation,
                            "--execution-receipt", "--resource-mode", "strict", "--expect-revision", str(verified["revision"]))
        require(receipt.get("schema") == "probentium.analysis-execution.v1" and
                receipt["input_revision"] == receipt["case_revision"] == verified["revision"] and
                receipt["resources"]["memory_mode"] == "hard_enforced", "analysis_receipt_mismatch")
        self.passed(self.step, memory_mode="hard_enforced", revision_bound=True)

        self.step = "typed_controls_and_frozen_deadline"
        observations = demonstration["control_observations"]["observation_refs"]
        require(len(observations) == 3, "typed_observation_demo_missing")
        for identity in observations:
            checked = self.call("probentium", "governance", "observation-assess", "--case", case, "--id", identity)
            require(checked.get("observation_ref") == identity and checked.get("legal_compliance") is not True,
                    "typed_observation_contract_mismatch")
        deadline = demonstration["reporting"]["deadline_evaluation_ref"]
        checked = self.call("probentium", "reporting", "deadline-replay", "--case", case, "--id", deadline)
        require(checked.get("status") == "replayed" and checked.get("legal_deadline_verified") is False, "deadline_replay_mismatch")
        self.passed(self.step, observations=3, deadline="replayed", legal_certification=False)

        self.step = "unified_dependency_graph"
        graph = self.call("probentium", "graph", "build", "--case", case)
        impact = self.call("probentium", "graph", "impact", "--case", case, "--id", graph["id"],
                           "--input", self.document("changed-premise", {"changed_ids": [demonstration["claim_id"]]}))
        require(impact.get("schema") == "probentium.graph-impact.v1" and impact.get("graph_currentness") == "current",
                "unified_graph_currentness_mismatch")
        self.passed(self.step, historical_results_rewritten=False)

        self.step = "explicit_signing_trust"
        key = self.directory / "signing.seed"
        public = self.call("probentium", "key", "generate", "--output", key)
        trust_data = {"schema": "probentium.trust.v1", "keys": [{"key_id": public["key_id"], "alias": "synthetic-acceptance", "status": "active", "reason": None}]}
        trust = self.document("trust", trust_data)
        self.passed(self.step)

        self.step = "revision_bound_signed_review"
        rationale = self.call("probentium", "review", "rationale", "--case", case, "--input", self.document("rationale", {"text": "Synthetic conditional review only; this exercise establishes no incident or legal finding."}))
        from probentium.store import CaseStore
        with CaseStore(case) as store:
            claim = store.get_object(demonstration["claim_id"])
            evaluation = store.get_object(aligned_id)["data"]
        decision = {"claim_id": claim["id"], "claim_revision": claim["revision"], "evaluation_digest": evaluation["result"]["digest"],
                    "snapshot_digest": evaluation["data_fingerprint"], "reviewer_key_id": public["key_id"], "disposition": "approve", "rationale_digest": rationale["rationale_digest"]}
        signed = self.call("probentium", "review", "create", "--case", case, "--key", key, "--input", self.document("decision", decision))
        review = self.document("signed-review", signed)
        checked = self.call("probentium", "review", "verify", "--case", case, "--trust", trust, "--input", review)
        require(checked.get("signature_status") == "valid" and checked.get("key_trust") == "trusted", "review_signature_mismatch")
        imported = self.call("probentium", "review", "import", "--case", case, "--trust", trust, "--input", review)
        require(imported.get("status") == "current" and imported.get("approval_effect") == "eligible_for_current_review", "review_binding_mismatch")
        self.passed(self.step)

        self.step = "signed_packet_and_trust_separation"
        packet = self.directory / "synthetic.pbp"
        self.call("probentium", "packet", "export", "--case", case, "--key", key, "--output", packet)
        untrusted = self.call("probentium", "packet", "verify", "--input", packet, "--require-signature")
        require(untrusted.get("ok") is True and untrusted.get("signature_status") == "valid" and untrusted.get("key_trust") == "unknown", "implicit_trust_detected")
        trusted = self.call("probentium", "packet", "verify", "--input", packet, "--trust", trust, "--require-trusted-key")
        require(trusted.get("ok") is True and trusted.get("key_trust") == "trusted" and trusted.get("normalization_replay") == "unavailable", "structural_verification_mismatch")
        revoked_data = {"schema": "probentium.trust.v1", "keys": [{**trust_data["keys"][0], "status": "revoked", "reason": "Synthetic revocation exercise."}]}
        revoked = self.call("probentium", "packet", "verify", "--input", packet, "--trust", self.document("revoked-trust", revoked_data), "--require-trusted-key", expected=4)
        require(revoked.get("signature_status") == "valid" and revoked.get("key_trust") == "revoked" and revoked.get("ok") is False, "revocation_not_enforced")
        self.passed(self.step, unknown_key="not_trusted", revoked_key="rejected")

        self.step = "semantic_packet_replay"
        replayed = self.call("probentium", "packet", "verify", "--input", packet, "--scope", "replay", "--trust", trust, "--require-trusted-key")
        require(replayed.get("ok") is True and replayed.get("normalization_replay") == "passed" and replayed.get("analysis_replay") == "passed", "semantic_replay_failed")
        self.passed(self.step, normalization="passed", analysis="passed")

        self.step = "restore_and_replay"
        restored = self.directory / "restored-case"
        self.call("probentium", "packet", "restore", "--input", packet, "--output", restored, "--trust", trust, "--require-trusted-key")
        restored_check = self.call("probentium", "verify", "--case", restored)
        restored_replay = self.call("probentium", "replay", "--case", restored)
        require(restored_check.get("ok") is True and restored_check.get("completeness") == "acquired_bytes_present", "restored_integrity_failed")
        require(restored_replay.get("normalization_replay") == "passed" and restored_replay.get("analysis_replay") == "passed", "restored_replay_failed")
        with CaseStore(case) as original, CaseStore(restored) as copied:
            require([row["id"] for row in original.query_events(limit=1000)["rows"]] == [row["id"] for row in copied.query_events(limit=1000)["rows"]], "restored_event_identity_mismatch")
        self.passed(self.step)

        self.step = "official_age_roundtrip_and_tamper"
        keygen, age = Path(sys.executable).parent / "age-keygen", Path(sys.executable).parent / "age"
        require(keygen.is_file() and age.is_file(), "official_age_unavailable")
        require(self.call(None, age, "--version", parse=False).strip() == b"v1.3.2", "age_version_mismatch")
        require(self.call(None, keygen, "--version", parse=False).strip() == b"v1.3.2", "age_version_mismatch")
        identity = self.directory / "age.identity"
        self.call(None, keygen, "-o", identity, parse=False)
        recipient = self.call(None, keygen, "-y", identity, parse=False).decode("ascii").strip()
        encrypted, decrypted = self.directory / "synthetic.age", self.directory / "decrypted.pbp"
        encryption = self.document("encrypt", {"packet": str(packet), "recipients": [recipient]})
        require(self.call("probentium", "packet", "encrypt", "--input", encryption, "--output", encrypted, "--trust", trust).get("ok") is True, "encryption_failed")
        decryption = self.document("decrypt", {"packet": str(encrypted), "identity_file": str(identity)})
        require(self.call("probentium", "packet", "decrypt", "--input", decryption, "--output", decrypted, "--trust", trust, "--require-trusted-key").get("ok") is True, "decryption_failed")
        require(packet.read_bytes() == decrypted.read_bytes(), "age_roundtrip_mismatch")
        damaged = self.directory / "tampered.age"
        data = bytearray(encrypted.read_bytes())
        data[-1] ^= 1
        with damaged.open("xb") as stream:
            stream.write(data)
        target = self.directory / "must-not-exist.pbp"
        tamper = self.document("tampered-decrypt", {"packet": str(damaged), "identity_file": str(identity)})
        self.call("probentium", "packet", "decrypt", "--input", tamper, "--output", target, "--trust", trust, "--require-trusted-key", expected=4, parse=False)
        require(not target.exists(), "unauthenticated_plaintext_published")
        self.passed(self.step, plaintext_byte_equal=True, damaged_ciphertext="rejected", damaged_output_published=False)

        self.step = "legacy_demo_parity"
        legacy_dir = self.directory / "legacy-demo"
        legacy = self.call("testifex", "demo", "--directory", legacy_dir)
        require(legacy.get("synthetic") is True and legacy.get("network_requests") == 0 and len(legacy.get("scenarios", [])) == 2, "legacy_demo_mismatch")
        for name in ("auth-case", "uncertain-case"):
            original, copy = legacy_dir / name, self.directory / ("legacy-copy-" + name)
            require(self.call("testifex", "verify", "--case", original).get("ok") is True, "legacy_integrity_failed")
            self.call("testifex", "replay", "--case", original, "--into", copy)
            before = self.call("testifex", "analyze", "--case", original)
            after = self.call("testifex", "analyze", "--case", copy)
            require(before == after, "legacy_replay_mismatch")
        self.passed(self.step, scenarios=2)

        self.receipt.update(status="passed", elapsed_ms=int((time.monotonic() - started) * 1000),
                            packet_sha256=hashlib.sha256(packet.read_bytes()).hexdigest(), product_workflow_executed=True)
        return 0


def worker(directory, checkout):
    os.umask(0o077)
    acceptance = Acceptance(directory, checkout)
    try:
        status = acceptance.run()
    except Exception as exc:
        code = exc.code if isinstance(exc, Rejected) else "acceptance_operation_failed"
        acceptance.receipt.update(status="failed", failed_step=acceptance.step, error=code)
        status = 4
    write_json(directory / "receipt.json", acceptance.receipt)
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate an installed package outside the checkout using only synthetic evidence and child-only Linux network syscall denial.")
    parser.add_argument("--python", type=Path, required=True, help="Absolute interpreter path inside the installed package environment")
    parser.add_argument("--output", type=Path, required=True, help="New private output directory; parent must exist")
    args = parser.parse_args(argv)
    try:
        require(args.python.is_absolute() and args.python.is_file(), "absolute_environment_interpreter_required")
        directory = Path(os.path.abspath(args.output))
        checkout = Path(__file__).resolve().parents[1]
        require(not directory.is_relative_to(checkout), "output_must_be_outside_checkout")
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
        for name in ("temporary", "diagnostics"):
            (directory / name).mkdir(mode=0o700)
        if not sys.platform.startswith("linux"):
            result = {"schema": "probentium.installed-acceptance.v1", "status": "unsupported", "checks": [],
                      "synthetic_only": True, "network_isolation": {"status": "unsupported"},
                      "reason": "child_network_isolation_unavailable", "product_workflow_executed": False}
            write_json(directory / "receipt.json", result)
            print(json.dumps({"schema": result["schema"], "status": "unsupported", "network_isolation": "unsupported", "checks": 0}))
            return 7
        command = [args.python, "-I", Path(__file__).absolute(), "--_bootstrap", directory, checkout]
        status, _, _ = process(command, directory, clean_environment(args.python, directory), timeout=900)
        receipt = directory / "receipt.json"
        require(receipt.is_file() and receipt.stat().st_size <= 1024 ** 2, "acceptance_receipt_missing")
        result = json.loads(receipt.read_bytes())
        require(result.get("status") in {"passed", "failed", "unsupported"}, "acceptance_receipt_invalid")
        require(status == {"passed": 0, "failed": 4, "unsupported": 7}[result["status"]], "acceptance_exit_mismatch")
        print(json.dumps({"schema": result["schema"], "status": result["status"], "checks": len(result["checks"]),
                          "network_isolation": result["network_isolation"]["status"]}, sort_keys=True))
        return status
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"error":"installed_validation_failed"}', file=sys.stderr)
        return 4


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] in {"--_bootstrap", "--_worker"}:
        function = bootstrap if sys.argv[1] == "--_bootstrap" else worker
        raise SystemExit(function(Path(sys.argv[2]), Path(sys.argv[3])))
    raise SystemExit(main())
