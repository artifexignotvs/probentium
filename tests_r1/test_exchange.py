"""Fasciculi adversi recipi nequeunt; proiectio privata verba omittit."""
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium.contracts import canonical_bytes, ProbentiumError
from probentium.store import CaseStore
from probentium.signatures import generate_key
from probentium import exchange as module


def members(raw):
    result, position = [], 0
    while raw[position:position + 512] != b"\0" * 512:
        header = raw[position:position + 512]
        name = header[:100].split(b"\0", 1)[0].decode("ascii")
        length = int(header[124:135], 8)
        position += 512
        result.append((name, raw[position:position + length]))
        position += (length + 511) // 512 * 512
    return result


def archive(rows):
    return b"".join(module._header(name, len(raw)) + raw + b"\0" * (-len(raw) % 512) for name, raw in rows) + b"\0" * 1024


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = self.root / "case"
        self.packet = self.root / "case.tfp"
        self.key = self.root / "key"
        self.public = generate_key(self.key)
        self.input = self.root / "input"
        self.raw = b'{"kind":"generic","timestamp":null,"actor":"private-canary-operator","path":"/private/canary"}\n'
        self.input.write_bytes(self.raw)
        with CaseStore.create(self.case, "Private case canary") as case:
            case.ingest(self.input, "events", "Private source canary")
            case.put_object("note", {"text": "Private note canary"})
            self.export = module.export_case(case, self.packet, signing_key=self.key)

    def tearDown(self):
        self.temp.cleanup()

    def trust(self, status="active"):
        return {"schema": "probentium.trust.v1", "keys": [{"key_id": self.public["key_id"], "alias": "fixture", "status": status, "reason": "fixture decision"}]}

    def altered(self, raw):
        path = self.root / "altered.tfp"
        path.write_bytes(raw)
        return module.verify_packet(path)

    def test_signed_roundtrip_deterministic_archive_and_separate_layers(self):
        receipt = module.verify_packet(self.packet)
        self.assertTrue(receipt["ok"], receipt)
        self.assertEqual(receipt["signature_status"], "valid")
        self.assertEqual(receipt["key_trust"], "unknown")
        self.assertEqual(receipt["normalization_replay"], "unavailable")
        with CaseStore(self.case) as case:
            module.export_case(case, self.root / "second.tfp", signing_key=self.key)
        self.assertEqual(self.packet.read_bytes(), (self.root / "second.tfp").read_bytes())
        self.assertEqual(self.export["byte_length"], self.packet.stat().st_size)
        self.assertNotIn(b"SQLite format", self.packet.read_bytes())

    def test_required_trust_and_revocation_are_distinct(self):
        unknown = module.verify_packet(self.packet, require_trusted_key=True)
        self.assertEqual(unknown["exit_code"], 3)
        trusted = module.verify_packet(self.packet, trust_store=self.trust(), require_trusted_key=True)
        self.assertTrue(trusted["ok"])
        revoked = module.verify_packet(self.packet, trust_store=self.trust("revoked"), require_trusted_key=True)
        self.assertEqual(revoked["signature_status"], "valid")
        self.assertEqual(revoked["key_trust"], "revoked")
        self.assertEqual(revoked["exit_code"], 4)

    def test_replay_without_backend_is_not_reported_passed(self):
        result = module.verify_packet(self.packet, scope="replay")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["normalization_replay"], "unsupported")
        self.assertEqual(result["transport_integrity"], "passed")

    def test_replay_callback_receives_only_bounded_verified_sources(self):
        observed = []
        def replay(manifest, snapshot, source_reader):
            artifact = snapshot["artifacts"][0]
            with source_reader(artifact["id"]) as stream:
                observed.append(stream.read())
                self.assertEqual(stream.read(), b"")
                with self.assertRaises(ValueError):
                    stream.seek(artifact["size"] + 1)
            return {"normalization_replay": "passed", "analysis_replay": "passed", "issues": []}
        self.assertTrue(module.verify_packet(self.packet, scope="replay", replay=replay)["ok"])
        self.assertEqual(observed, [self.raw])
        failed = lambda *args: {"normalization_replay": "failed", "analysis_replay": "unavailable", "issues": ["mismatch"]}
        self.assertEqual(module.verify_packet(self.packet, scope="replay", replay=failed)["exit_code"], 4)

    def test_real_signed_extended_demo_replays_through_cli(self):
        from probentium.demo import make_demo
        demonstration = make_demo(self.root / "synthetic-demo", extended=True)
        packet, trust = self.root / "synthetic.pbp", self.root / "trust.json"
        trust.write_bytes(canonical_bytes(self.trust()))
        with CaseStore(demonstration["case"]) as case:
            module.export_case(case, packet, signing_key=self.key)
        checked = subprocess.run([module.sys.executable, "-m", "probentium", "packet", "verify", "--input", str(packet),
                                  "--scope", "replay", "--trust", str(trust), "--require-trusted-key"],
                                 capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        result = json.loads(checked.stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["normalization_replay"], "passed")
        self.assertEqual(result["analysis_replay"], "passed")
        self.assertEqual(result["signature_status"], "valid")
        self.assertEqual(result["key_trust"], "trusted")
        self.assertNotIn("basis", result)

    def test_semantic_callback_cannot_override_transport_or_leak_extra_fields(self):
        from probentium import maintenance
        bad = [
            {"analysis_replay": "passed", "issues": [], "normalization_replay": "passed"},
            {"analysis_replay": "passed", "issues": [], "basis": "unverified private text"},
            {"analysis_replay": "unavailable", "issues": ["/private/canary"]},
        ]
        for value in bad:
            with self.subTest(shape=sorted(value)), patch("probentium.investigation.replay_snapshot", return_value=value):
                result = module.verify_packet(self.packet, scope="replay", replay=maintenance.replay_packet)
                self.assertEqual(result["exit_code"], 4)
                self.assertEqual(result["normalization_replay"], "passed")
                self.assertEqual(result["analysis_replay"], "failed")
                self.assertIn("invalid_analysis_replay_receipt", result["issues"])
                self.assertNotIn("/private/canary", json.dumps(result))
                self.assertNotIn("unverified private text", json.dumps(result))

    def test_real_replay_rejects_hash_consistent_false_normalized_event(self):
        from probentium import maintenance
        from probentium.store import _catalog_digest, _dump, _event_id
        packet = self.root / "false-normalization.tfp"
        with CaseStore(self.case) as case:
            event = case.query_events()["rows"][0]
            previous = event["id"]
            event["actor"] = event["normalized_output"]["actor"] = "different-fixture-operator"
            event["normalized_output_digest"] = module.object_digest(event["normalized_output"])
            event["id"] = _event_id(event)
            case.db.execute("UPDATE events SET id=?,actor=?,search=?,data=?,digest=? WHERE id=?",
                            (event["id"], event["actor"], canonical_bytes(event["normalized_output"]).decode().casefold(),
                             *_dump(event), previous))
            meta = dict(case.meta)
            meta["catalog_digest"] = _catalog_digest(case.db)
            case.db.execute("UPDATE meta SET data=?,digest=? WHERE key='case'", _dump(meta))
            module.export_case(case, packet, signing_key=self.key)
        structure = module.verify_packet(packet, trust_store=self.trust(), require_trusted_key=True)
        self.assertTrue(structure["ok"], structure)
        result = module.verify_packet(packet, scope="replay", trust_store=self.trust(),
                                      require_trusted_key=True, replay=maintenance.replay_packet)
        self.assertEqual(result["exit_code"], 4, result)
        self.assertEqual(result["transport_integrity"], "passed")
        self.assertEqual(result["signature_status"], "valid")
        self.assertEqual(result["normalization_replay"], "failed")
        self.assertEqual(result["analysis_replay"], "unavailable")
        self.assertIn("replay_normalization_mismatch", result["issues"])
        self.assertNotIn("invalid_replay_receipt", result["issues"])

    def test_semantic_backend_error_keeps_completed_normalization(self):
        from probentium import maintenance
        with patch("probentium.investigation.replay_snapshot", side_effect=ValueError("/private/canary")):
            result = module.verify_packet(self.packet, scope="replay", replay=maintenance.replay_packet)
        self.assertEqual(result["exit_code"], 4, result)
        self.assertEqual(result["normalization_replay"], "passed")
        self.assertEqual(result["analysis_replay"], "failed")
        self.assertIn("replay_invalid_data", result["issues"])
        self.assertNotIn("/private/canary", json.dumps(result))

    def test_verified_snapshot_never_exposes_sqlite_and_holds_file(self):
        with module.open_verified_snapshot(self.packet, self.trust(), True) as (manifest, snapshot, source_reader):
            self.assertEqual(snapshot["schema"], "probentium.case-snapshot.v1")
            with source_reader(snapshot["artifacts"][0]["id"]) as stream:
                self.assertEqual(stream.read(), self.raw)
            self.assertNotIn("sql", snapshot)

    def test_manifest_first_duplicate_missing_and_extra_members(self):
        rows = members(self.packet.read_bytes())
        for altered in ([rows[1], rows[0], *rows[2:]], [rows[0], rows[1], rows[1], *rows[2:]], [rows[0], *rows[2:]], [*rows, rows[1]]):
            with self.subTest(count=len(altered)):
                self.assertFalse(self.altered(archive(altered))["ok"])

    def test_pax_gnu_links_traversal_and_transport_metadata_rejected(self):
        original = self.packet.read_bytes()
        for offset, byte in ((156, b"x"), (156, b"g"), (156, b"L"), (156, b"2"), (156, b"1"), (100, b"7"), (108, b"1"), (136, b"1"), (265, b"u"), (345, b"x")):
            changed = bytearray(original)
            changed[offset:offset + 1] = byte
            changed[148:156] = b"        "
            checksum = sum(changed[:512])
            changed[148:156] = ("%06o\0 " % checksum).encode()
            with self.subTest(offset=offset, byte=byte):
                self.assertFalse(self.altered(bytes(changed))["ok"])
        for name in ("../manifest.json", "/manifest.json", "a/../../manifest.json"):
            changed = bytearray(original)
            changed[:100] = name.encode().ljust(100, b"\0")
            self.assertFalse(self.altered(bytes(changed))["ok"])

    def test_padding_truncation_and_trailing_garbage_rejected(self):
        original = self.packet.read_bytes()
        for raw in (original[:-1], original[:-512], original + b"x", original + b"\0" * (module.MAX_PADDING + 512)):
            self.assertFalse(self.altered(raw)["ok"])
        self.assertTrue(self.altered(original + b"\0" * 512)["ok"])
        rows = members(original)
        size = len(rows[0][1])
        changed = bytearray(original)
        if size % 512:
            changed[512 + size] = 1
            self.assertFalse(self.altered(bytes(changed))["ok"])

    def test_manifest_duplicate_keys_float_and_noncanonical_json_rejected(self):
        rows = members(self.packet.read_bytes())
        for raw in (rows[0][1] + b"\n", b'{"schema":"a","schema":"b"}', b'{"value":NaN}', b'{"value":1.2}'):
            self.assertFalse(self.altered(archive([("manifest.json", raw), *rows[1:]]))["ok"])

    def test_size_limits_checked_before_body_read(self):
        original = self.packet.read_bytes()
        with patch.object(module, "MAX_PACKET", 128):
            self.assertFalse(module.verify_packet(self.packet)["ok"])
        changed = module._header("manifest.json", module.MAX_JSON + 1) + b"\0" * 1024
        self.assertFalse(self.altered(changed)["ok"])
        with patch.object(module, "MAX_MEMBERS", 1):
            self.assertEqual(module.verify_packet(self.packet)["exit_code"], 6)

    def test_blob_and_signature_corruption_detected(self):
        rows = members(self.packet.read_bytes())
        changed = list(rows)
        changed[1] = (rows[1][0], bytes([rows[1][1][0] ^ 1]) + rows[1][1][1:])
        self.assertIn("blob_digest_mismatch", self.altered(archive(changed))["issues"])
        changed = list(rows)
        envelope = json.loads(changed[-1][1])
        envelope["context"] = "PROBENTIUM-PACKET-V1"
        changed[-1] = (changed[-1][0], canonical_bytes(envelope))
        receipt = self.altered(archive(changed))
        self.assertEqual(receipt["signature_status"], "invalid")

    def test_unsigned_structure_requires_explicit_policy_for_signature(self):
        unsigned = self.root / "unsigned.tfp"
        with CaseStore(self.case) as case:
            module.export_case(case, unsigned)
        self.assertTrue(module.verify_packet(unsigned)["ok"])
        self.assertEqual(module.verify_packet(unsigned, require_signature=True)["exit_code"], 3)

    def test_public_summary_contains_no_raw_fields_and_cannot_replay(self):
        output = self.root / "public.tfp"
        with CaseStore(self.case) as case:
            module.export_case(case, output, "public_summary", pseudonym_key_file=self.key, signing_key=self.key)
        raw = output.read_bytes()
        for canary in (b"private-canary", b"Private case", b"Private source", b"Private note", b"/private/canary"):
            self.assertNotIn(canary, raw)
        self.assertTrue(module.verify_packet(output)["ok"])
        self.assertEqual(module.verify_packet(output, scope="replay")["exit_code"], 3)
        with self.assertRaises(ProbentiumError):
            with module.open_verified_snapshot(output):
                pass

    def test_safe_outputs_no_overwrite_or_symlink_parent(self):
        with CaseStore(self.case) as case:
            with self.assertRaises(ProbentiumError):
                module.export_case(case, self.packet)
            alias = self.root / "alias"
            alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises((ProbentiumError, ValueError)):
                module.export_case(case, alias / "new.tfp")

    def test_changed_source_blocks_export(self):
        blob = next((self.case / "blobs").glob("*.bin"))
        blob.write_bytes(b"changed")
        with CaseStore(self.case) as case, self.assertRaises(ProbentiumError):
            module.export_case(case, self.root / "bad.tfp")
        self.assertFalse((self.root / "bad.tfp").exists())

    def test_age_absent_has_no_fallback_or_output(self):
        with patch.object(module, "_age_binary", return_value=None):
            result = module.encrypt_packet(self.packet, self.root / "encrypted.age", ["age1" + "a" * 58])
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["exit_code"], 7)
        self.assertFalse((self.root / "encrypted.age").exists())

    def test_recipient_dossier_field_allowlist_and_withholding(self):
        from probentium.regulatory import prepare_filing
        with CaseStore(self.case) as case:
            ref = case.query_events()["rows"][0]["id"]
            track = {"id": "incident", "profile": "gdpr-controller", "anchors": {"awareness": "2026-10-18T10:00:00Z"}}
            fields = [{"id": "selected", "value": "Approved sharing", "basis": "source_backed", "refs": [ref]},
                      {"id": "secret", "value": "private-field-canary", "basis": "human_attested", "refs": [], "reason": "Synthetic"}]
            filing = prepare_filing(track, fields, case.revision, "2026-10-18T12:00:00Z")
            wrapper = case.put_object("filing", filing)
            output = self.root / "recipient.pbp"
            module.export_case(case, output, "recipient_dossier", object_ids=[wrapper["id"]], field_allowlist={wrapper["id"]: ["selected"]}, purpose="Selected incident statement", signing_key=self.key)
            private = self.root / "private.pbp"
            module.export_case(case, private, signing_key=self.key)
        self.assertNotIn(b"private-field-canary", output.read_bytes())
        self.assertTrue(module.verify_packet(output)["ok"])
        self.assertEqual(module.verify_packet(output, scope="replay")["exit_code"], 3)
        self.assertTrue(module.verify_packet(private)["ok"])

    def test_official_age_roundtrip_and_authentication_failure(self):
        keygen = module.shutil.which("age-keygen")
        if keygen is None or module._age_binary() is None:
            self.skipTest("Official age binaries unavailable")
        identity = self.root / "age.identity"
        subprocess.run([str(keygen), "-o", str(identity)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recipient = subprocess.check_output([str(keygen), "-y", str(identity)], timeout=10).decode().strip()
        encrypted, decrypted = self.root / "case.age", self.root / "decrypted.tfp"
        result = module.encrypt_packet(self.packet, encrypted, [recipient])
        self.assertTrue(result["ok"])
        self.assertNotIn(b"private-canary", encrypted.read_bytes())
        result = module.decrypt_packet(encrypted, decrypted, identity)
        self.assertTrue(result["ok"])
        self.assertEqual(decrypted.read_bytes(), self.packet.read_bytes())
        raw = bytearray(encrypted.read_bytes())
        raw[-1] ^= 1
        damaged = self.root / "damaged.age"
        damaged.write_bytes(raw)
        target = self.root / "must-not-exist.tfp"
        with self.assertRaises(ProbentiumError):
            module.decrypt_packet(damaged, target, identity)
        self.assertFalse(target.exists())

    def test_chunked_snapshot_is_reiterable_and_lookup_bounded(self):
        with module.open_verified_snapshot(self.packet) as (manifest, snapshot, reader):
            self.assertIsInstance(snapshot, module.SnapshotView)
            self.assertEqual(snapshot.snapshot_digest, manifest["snapshot_digest"])
            self.assertNotIsInstance(snapshot["events"], list)
            first = snapshot["events"][0]
            self.assertEqual(list(snapshot["events"]), list(snapshot.iter_table("events")))
            self.assertEqual(snapshot.lookup("events", first["id"]), first)
            self.assertEqual(list(snapshot.iter_run_events(first["parse_run_id"])), [first])
            self.assertEqual(snapshot.event_for_record(first["parse_run_id"], first["primary_record_ref"]), first)
            self.assertEqual(list(snapshot.iter_run_records(first["parse_run_id"]))[0]["id"], first["primary_record_ref"])
        self.assertTrue(snapshot.closed)

    def test_multiple_small_chunks_preserve_all_rows_and_order(self):
        source = self.root / "larger"
        source.write_bytes(b'{"kind":"generic","timestamp":null}\n' * 40)
        packet = self.root / "chunked.tfp"
        with CaseStore.create(self.root / "larger-case", "Synthetic") as case:
            case.ingest(source, "events", "Synthetic")
            with patch.object(module, "MAX_CHUNK", 8192):
                module.export_case(case, packet)
                self.assertTrue(module.verify_packet(packet)["ok"])
        chunks = [json.loads(raw) for name, raw in members(packet.read_bytes()) if name.startswith("blobs/") and raw.startswith(b'{"rows":')]
        self.assertGreater(sum(chunk["table"] == "events" for chunk in chunks), 1)
        with module.open_verified_snapshot(packet) as (_, view, _):
            self.assertEqual(len(view["events"]), 40)
            self.assertEqual(len({row["id"] for row in view["events"]}), 40)

    def test_index_tampering_and_unreferenced_chunks_fail(self):
        original = members(self.packet.read_bytes())
        manifest = json.loads(original[0][1])
        digest = manifest["snapshot_digest"]
        index = json.loads(dict(original)["blobs/" + digest])
        variants = []
        changed = copy.deepcopy(index)
        changed["tables"][0]["count"] += 1
        variants.append(changed)
        changed = copy.deepcopy(index)
        nonempty = next(row for row in changed["tables"] if row["chunks"])
        nonempty["chunks"] = []
        variants.append(changed)
        changed = copy.deepcopy(index)
        nonempty = next(row for row in changed["tables"] if row["chunks"])
        nonempty["chunks"].append(nonempty["chunks"][0])
        variants.append(changed)
        for value in variants:
            raw = canonical_bytes(value)
            new_digest = hashlib.sha256(raw).hexdigest()
            altered = copy.deepcopy(manifest)
            altered["snapshot_digest"] = new_digest
            for descriptor in altered["objects"]:
                if descriptor["sha256"] == digest:
                    descriptor.update(sha256=new_digest, byte_length=len(raw))
            altered["objects"].sort(key=lambda row: row["sha256"])
            payloads = {name[6:]: data for name, data in original if name.startswith("blobs/") and name != "blobs/" + digest}
            payloads[new_digest] = raw
            rows = [("manifest.json", canonical_bytes(altered))] + [("blobs/" + key, payloads[key]) for key in sorted(payloads)]
            self.assertFalse(self.altered(archive(rows))["ok"])

    def test_small_flat_snapshot_protocol_remains_readable(self):
        class Legacy:
            def __init__(self, case):
                self.case = case
            def __getattr__(self, name):
                if name in ("snapshot_header", "iter_snapshot_rows"):
                    raise AttributeError(name)
                return getattr(self.case, name)
        target = self.root / "flat.tfp"
        with CaseStore(self.case) as case:
            module.export_case(Legacy(case), target)
        with module.open_verified_snapshot(target) as (_, snapshot, _):
            self.assertIsInstance(snapshot, dict)
            self.assertEqual(len(snapshot["events"]), 1)

    def test_authorized_purge_is_partial_not_corruption_and_no_full_export(self):
        from probentium import retention
        with CaseStore(self.case) as case:
            ids = [row["id"] for row in case.sources()]
            plan = retention.plan(case, ids, "Fixture", "Synthetic lifecycle", "2026-01-01T00:00:00Z")
            approval = retention.approve(case, plan["id"], "Fixture", "Synthetic approval")
            retention.execute(case, plan["id"], approval["id"], as_of="2026-10-18T00:00:00Z")
            with self.assertRaises(ProbentiumError) as error:
                module.export_case(case, self.root / "full.tfp")
            self.assertEqual(error.exception.exit_code, 3)
            self.assertFalse((self.root / "full.tfp").exists())
            module.export_case(case, self.root / "summary.tfp", "public_summary", pseudonym_key_file=self.key)
        self.assertTrue(module.verify_packet(self.root / "summary.tfp")["ok"])

    def test_eu_governance_dispatch_is_typed_and_requires_pbp(self):
        from probentium.governance import validate_record
        data = validate_record("service", {"logical_id": "fixture", "actor": "Fixture", "recorded_at": "2026-10-18T00:00:00Z",
                 "basis_refs": [], "rationale": "Synthetic inventory", "supersedes": None, "name": "Synthetic service",
                 "entity": "Fixture", "jurisdiction": "CZ", "owner": "Fixture", "criticality": "unknown", "unknown_dependencies": True})
        with CaseStore(self.case) as case:
            case.put_object("eu.service", data)
            with self.assertRaises(ProbentiumError):
                module.export_case(case, self.root / "eu.tfp")
            module.export_case(case, self.root / "eu.pbp")
        self.assertTrue(module.verify_packet(self.root / "eu.pbp")["ok"])
        broken = {"schema": "probentium.eu.v1", "kind": "control_evidence", "store_kind": "eu.service", "object_id": "1" * 64, "data": {**data, "legal_certification": True}}
        with self.assertRaises(ProbentiumError):
            module._eu(broken)

    def test_age_output_limit_precedes_final_publication(self):
        executable = self.root / "bounded-output"
        executable.write_text("#!" + module.sys.executable + "\nimport os\nos.write(1,b'x'*200000)\n")
        executable.chmod(0o700)
        target = self.root / "oversize.age"
        with patch.object(module, "_age_binary", return_value=str(executable)), patch.object(module, "MAX_PACKET", self.packet.stat().st_size + 1024):
            with self.assertRaises(ProbentiumError) as error:
                module.encrypt_packet(self.packet, target, ["age1" + "a" * 58])
        self.assertEqual(error.exception.exit_code, 6)
        self.assertFalse(target.exists())

    def test_recipient_unresolved_reference_never_claims_withheld_evidence(self):
        from probentium.regulatory import prepare_filing
        with CaseStore(self.case) as case:
            track = {"id": "incident", "profile": "gdpr-controller", "anchors": {"awareness": "2026-10-18T10:00:00Z"}}
            filing = prepare_filing(track, [{"id": "selected", "value": "Fixture", "basis": "source_backed", "refs": ["f" * 64]}], case.revision, "2026-10-18T12:00:00Z")
            wrapper = case.put_object("filing", filing)
            with self.assertRaises(ProbentiumError) as error:
                module.export_case(case, self.root / "invalid.pbp", "recipient_dossier", object_ids=[wrapper["id"]], field_allowlist={wrapper["id"]: ["selected"]}, purpose="Fixture")
            self.assertEqual(error.exception.code, "projection_reference_unresolved")

    def test_extended_eu_objects_projection_and_reconstruction(self):
        from probentium import reporting, maintenance
        private, recipient = self.root / "extended.pbp", self.root / "subset.pbp"
        with CaseStore(self.case) as case:
            reporting.build_demonstration(case, acknowledged_synthetic=True)
            module.export_case(case, private)
            filing = case.objects("eu.filing_snapshot")[-1]
            field = filing["data"]["snapshot"]["fields"][0]["id"]
            module.export_case(case, recipient, "recipient_dossier", object_ids=[filing["id"]], field_allowlist={filing["id"]: [field]}, purpose="Synthetic subset")
            original_count = len(case.objects())
        self.assertTrue(module.verify_packet(private)["ok"])
        self.assertTrue(module.verify_packet(recipient)["ok"])
        with module.open_verified_snapshot(private) as (_, snapshot, reader):
            receipt = maintenance.restore_snapshot(snapshot, reader, self.root / "restored")
        self.assertEqual(receipt["integrity"], "passed")
        with CaseStore(self.root / "restored") as restored:
            self.assertEqual(len(restored.objects()), original_count)

    def test_v2_large_timestamp_replay_is_separate_from_absent_analysis(self):
        from probentium import maintenance
        source = self.root / "v2.jsonl"
        source.write_bytes(canonical_bytes({"schema": "testifex.events.v2", "kind": "auth.success",
            "recorded_time": {"value": "9007199254740992", "encoding": "unix_us", "resolution_us": "1000"},
            "origin": None, "payload": {"service": "ssh"}}) + b"\n")
        packet = self.root / "v2.tfp"
        with CaseStore.create(self.root / "v2case", "Synthetic") as case:
            case.ingest(source, "events-v2", "Synthetic")
            module.export_case(case, packet)
        result = module.verify_packet(packet, "replay", replay=maintenance.replay_packet)
        self.assertEqual(result["normalization_replay"], "passed")
        self.assertEqual(result["analysis_replay"], "unavailable")
        self.assertEqual(result["exit_code"], 3)

    def test_nested_wrong_types_return_safe_failure_not_attribute_error(self):
        rows = members(self.packet.read_bytes())
        malformed = rows[:-1] + [(rows[-1][0], b"[]")]
        result = self.altered(archive(malformed))
        self.assertFalse(result["ok"])
        self.assertEqual(result["exit_code"], 4)
        with self.assertRaises(ProbentiumError):
            module._normalized_output([])

    def test_chunk_writer_splits_by_json_complexity_before_reader_limit(self):
        class Dense:
            def snapshot_header(self):
                return {"schema": "probentium.case-snapshot.v1", "meta": {}, "counts": {name: 2200 if name == "objects" else 0 for name in module._TABLES}}
            def iter_snapshot_rows(self, table):
                if table == "objects":
                    for number in range(2200):
                        yield {"id": format(number, "064x"), "data": {"samples": [0] * 500}}
        chunks = {}
        index = module._chunked_snapshot(Dense(), self.root, chunks)
        self.assertGreater(len(chunks), 1)
        self.assertLess(sum(row[0]["byte_length"] for row in chunks.values()), module.MAX_CHUNK)
        actual = 0
        for descriptor, path in chunks.values():
            decoded = module._json(path.read_bytes(), module.MAX_CHUNK)
            actual += len(decoded["rows"])
        self.assertEqual(actual, 2200)
        self.assertEqual(next(table["count"] for table in index["tables"] if table["name"] == "objects"), 2200)

    def test_retention_history_is_typed_and_requires_extended_packet(self):
        from probentium import retention
        with CaseStore(self.case) as case:
            retention.hold(case, [row["id"] for row in case.sources()], "Fixture", "Synthetic preservation")
            with self.assertRaises(ProbentiumError) as error:
                module.export_case(case, self.root / "retention.tfp")
            self.assertEqual(error.exception.code, "eu_content_requires_pbp")
            module.export_case(case, self.root / "retention.pbp")
        result = module.verify_packet(self.root / "retention.pbp")
        self.assertTrue(result["ok"], result)


if __name__ == "__main__":
    unittest.main()
