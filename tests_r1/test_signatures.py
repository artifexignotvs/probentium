"""Vector publicus et contextus distincti probantur."""
import base64
import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from probentium.contracts import ProbentiumError, canonical_bytes
from probentium import signatures as module


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "private.key"
        self.public = module.generate_key(self.key)
        self.document = {"schema": "testifex.packet.v1", "content": "Synthetic"}

    def tearDown(self):
        self.temp.cleanup()

    def trust(self, status="active"):
        return {"schema": "probentium.trust.v1", "keys": [{"key_id": self.public["key_id"], "alias": "reviewer", "status": status, "reason": "local decision"}]}

    def test_rfc8032_vector_one_empty_message(self):
        private_type, public_type, serialization, _ = module._crypto()
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        key = private_type.from_private_bytes(seed)
        self.assertEqual(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), public)
        self.assertEqual(key.sign(b""), signature)
        public_type.from_public_bytes(public).verify(signature, b"")

    def test_signature_valid_but_trust_is_explicit(self):
        env = module.sign_manifest(self.document, self.key)
        self.assertEqual(module.verify_manifest_signature(self.document, env)["key_trust"], "unknown")
        trusted = module.verify_manifest_signature(self.document, env, self.trust())
        self.assertEqual(trusted["signature_status"], "valid")
        self.assertEqual(trusted["key_trust"], "trusted")
        revoked = module.verify_manifest_signature(self.document, env, self.trust("revoked"))
        self.assertEqual(revoked["signature_status"], "valid")
        self.assertEqual(revoked["key_trust"], "revoked")
        self.assertNotEqual(revoked["trust_store_digest"], trusted["trust_store_digest"])

    def test_domain_and_manifest_tampering_rejected(self):
        env = module.sign_manifest(self.document, self.key)
        for key, value in (("context", "PROBENTIUM-PACKET-V1"), ("algorithm", "RSA"), ("manifest_sha256", "0" * 64), ("key_id", "0" * 64)):
            changed = {**env, key: value}
            with self.subTest(field=key), self.assertRaises(ProbentiumError):
                module.verify_manifest_signature(self.document, changed)
        with self.assertRaises(ProbentiumError):
            module.verify_manifest_signature({**self.document, "content": "Changed"}, env)
        with self.assertRaises(ProbentiumError):
            module.verify_manifest_signature({**self.document, "schema": "probentium.packet.v1"}, env)

    def test_invalid_signature_and_noncanonical_base64_rejected(self):
        env = module.sign_manifest(self.document, self.key)
        invalid = {**env, "signature": base64.urlsafe_b64encode(b"\0" * 64).decode().rstrip("=")}
        with self.assertRaises(ProbentiumError) as caught:
            module.verify_manifest_signature(self.document, invalid)
        self.assertEqual(caught.exception.code, "signature_invalid")
        for changed in ({**env, "signature": env["signature"] + "="}, {**env, "public_key": "AAAA"}, {**env, "unknown": True}):
            with self.assertRaises(ProbentiumError):
                module.verify_manifest_signature(self.document, changed)

    def test_canonical_bytes_required_for_external_envelopes(self):
        env = module.sign_manifest(self.document, self.key)
        with self.assertRaises(ProbentiumError):
            module.verify_manifest_signature(canonical_bytes(self.document) + b"\n", env)
        with self.assertRaises(ProbentiumError):
            module.verify_manifest_signature(self.document, canonical_bytes(env) + b"\n")

    def test_key_permissions_symlinks_and_overwrite_rejected(self):
        with self.assertRaises(ProbentiumError):
            module.generate_key(self.key)
        alias = self.root / "alias"
        alias.symlink_to(self.key)
        with self.assertRaises(ProbentiumError):
            module.sign_manifest(self.document, alias)
        self.key.chmod(0o644)
        with self.assertRaises(ProbentiumError):
            module.sign_manifest(self.document, self.key)
        self.key.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaises(ProbentiumError):
            module.sign_manifest(self.document, self.key)
        self.root.chmod(0o700)

    def test_revocation_reason_and_duplicate_trust_entries_rejected(self):
        trust = self.trust("revoked")
        trust["keys"][0]["reason"] = None
        with self.assertRaises(ProbentiumError):
            module.validate_trust_store(trust)
        trust = self.trust()
        trust["keys"].append(copy.deepcopy(trust["keys"][0]))
        with self.assertRaises(ProbentiumError):
            module.validate_trust_store(trust)


if __name__ == "__main__":
    unittest.main()
