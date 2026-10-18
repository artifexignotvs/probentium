"""Distributa corrupta, vias alienas et fidem tacitam recusamus."""
import base64
import copy
import csv
import hashlib
import io
import os
import py_compile
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from probentium import parser_artifact as p
from probentium.contracts import ProbentiumError, canonical_bytes, object_digest
from probentium.store import CaseStore
from probentium.worker import ParserWorker


class ParserArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.site = self.root / 'site'
        self.prefix = self.root / 'prefix'
        self.site.mkdir()
        self.prefix.mkdir()

    def wheel(self, name='probentium', version=None, *, changed=None, extras=None, record_edit=None, tag='py3-none-any'):
        version = version or ('0.2.0.dev3' if name == 'probentium' else p.DEPENDENCIES[name])
        info = name + '-' + version + '.dist-info'
        requirements = {'probentium': ['rfc8785==0.1.4', 'cryptography==50.0.2'], 'cffi': ["pycparser; implementation_name != 'PyPy'"],
                        'cryptography': ["cffi>=2.0.0; platform_python_implementation != 'PyPy'"], 'rfc8785': [], 'pycparser': []}[name]
        meta = 'Metadata-Version: 2.4\nName: ' + name + '\nVersion: ' + version + '\nRequires-Python: >=3.11\n'
        meta += ''.join('Requires-Dist: ' + item + '\n' for item in requirements)
        files = {name + '/__init__.py': b'VALUE = 7\n', info + '/METADATA': meta.encode(),
                 info + '/WHEEL': ('Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: ' + tag + '\n').encode()}
        if name == 'probentium':
            files['testifex/__init__.py'] = b'VALUE = 11\n'
            for schema in ('events-v2.schema.json', 'control-observation.v1.schema.json', 'deadline-plan.v1.schema.json'):
                files[name + '-' + version + '.data/data/share/probentium/schemas/' + schema] = b'{}\n'
        files.update(changed or {})
        record = [[key, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='), str(len(raw))] for key, raw in sorted(files.items())]
        record.append([info + '/RECORD', '', ''])
        if record_edit:
            record_edit(record)
        output = io.StringIO(newline='')
        csv.writer(output, lineterminator='\n').writerows(record)
        files[info + '/RECORD'] = output.getvalue().encode()
        target = self.root / (name + '.whl')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for key, raw in files.items():
                    archive.writestr(key, raw)
                for entry, raw in extras or []:
                    archive.writestr(entry, raw)
        return target, hashlib.sha256(target.read_bytes()).hexdigest()

    def manifest(self):
        distributions = []
        for name in sorted(p._ROOTS):
            path, digest = self.wheel(name)
            distributions.append(p._wheel(path, digest, name))
        return {'schema': p.SCHEMA, 'distributions': distributions, 'runtime': p._identity(),
                'installation_exceptions': list(p.EXCEPTIONS), 'limitations': list(p.LIMITATIONS)}

    def install_fixture(self, manifest):
        for distribution in manifest['distributions']:
            path = self.root / (distribution['name'] + '.whl')
            with zipfile.ZipFile(path) as archive:
                for item in distribution['files']:
                    destination = (self.site if item['area'] == 'site' else self.prefix) / item['target']
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.read(item['path']))
        versions = {item['name']: item['version'] for item in manifest['distributions']}
        self.addCleanup(patch.stopall)
        patch.object(p, '_layout', return_value={'site': self.site, 'prefix': self.prefix}).start()
        patch.object(p.importlib.metadata, 'distribution', side_effect=lambda name: SimpleNamespace(version=versions[name], locate_file=lambda _: self.site)).start()
        patch.object(p, '_import_origins').start()

    def test_wheel_hash_records_and_exact_inventory(self):
        manifest = self.manifest()
        self.assertEqual(p.validate_manifest(manifest), manifest)
        self.assertNotIn(str(self.root), canonical_bytes(manifest).decode())
        path, digest = self.wheel()
        with self.assertRaisesRegex(ProbentiumError, 'parser_wheel_digest_mismatch'):
            p._wheel(path, '0' * 64, 'probentium')
        self.assertEqual(p._wheel(path, digest, 'probentium')['version'], '0.2.0.dev3')
        for edit in (lambda rows: rows[0].__setitem__(1, 'sha256=' + 'A' * 43), lambda rows: rows[0].__setitem__(2, '999'), lambda rows: rows.pop(0)):
            path, digest = self.wheel(record_edit=edit)
            with self.assertRaises(ProbentiumError):
                p._wheel(path, digest, 'probentium')

    def test_zip_path_links_duplicates_and_executable_hooks(self):
        for name in ('../outside.py', '/absolute.py', 'probentium/../outside.py', 'probentium\\evil.py', 'evil.pth', 'probentium/cache.pyc'):
            with self.subTest(name=name):
                path, digest = self.wheel(changed={name: b'raise RuntimeError("never executed")'})
                with self.assertRaises(ProbentiumError):
                    p._wheel(path, digest, 'probentium')
        link = zipfile.ZipInfo('probentium/link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in ([(link, b'/private')], [('probentium/__init__.py', b'duplicate')]):
            path, digest = self.wheel(extras=extra)
            with self.assertRaises(ProbentiumError):
                p._wheel(path, digest, 'probentium')

    def test_zip_preallocation_limits_and_trailing_bytes(self):
        path, digest = self.wheel()
        with patch.object(p, 'MAX_MEMBER', 3):
            with self.assertRaisesRegex(ProbentiumError, 'parser_wheel_expansion_limit'):
                p._wheel(path, digest, 'probentium')
        raw = bytearray(path.read_bytes())
        struct.pack_into('<H', raw, len(raw) - 12, 65535)
        path.write_bytes(raw)
        with patch.object(p.zipfile, 'ZipFile') as opener:
            with self.assertRaises(ProbentiumError):
                p._wheel(path, hashlib.sha256(raw).hexdigest(), 'probentium')
            opener.assert_not_called()
        path, _ = self.wheel()
        raw = bytearray(path.read_bytes())
        struct.pack_into('<HH', raw, len(raw) - 14, 1, 1)
        path.write_bytes(raw)
        with patch.object(p.zipfile, 'ZipFile') as opener:
            with self.assertRaisesRegex(ProbentiumError, 'invalid_parser_wheel_directory'):
                p._wheel(path, hashlib.sha256(raw).hexdigest(), 'probentium')
            opener.assert_not_called()
        path, _ = self.wheel()
        path.write_bytes(path.read_bytes() + b'trailing')
        with self.assertRaisesRegex(ProbentiumError, 'parser_wheel_trailing_data'):
            p._wheel(path, hashlib.sha256(path.read_bytes()).hexdigest(), 'probentium')

    def test_symlink_and_fifo_artifacts_are_not_opened_as_inputs(self):
        path, digest = self.wheel()
        link = self.root / 'link.whl'
        link.symlink_to(path)
        fifo = self.root / 'pipe.whl'
        os.mkfifo(fifo)
        for item in (link, fifo):
            with self.assertRaisesRegex(ProbentiumError, 'parser_artifact_access_failed'):
                p._wheel(item, digest, 'probentium')

    def test_closed_dependencies_and_platform_constraints(self):
        for change in ({'probentium-0.2.0.dev3.dist-info/METADATA': b'Metadata-Version: 2.4\nName: probentium\nVersion: 0.2.0.dev3\nRequires-Python: >=3.11\nRequires-Dist: hostile==1\n'},):
            path, digest = self.wheel(changed=change)
            with self.assertRaisesRegex(ProbentiumError, 'parser_dependency_inventory_mismatch'):
                p._wheel(path, digest, 'probentium')
        path, digest = self.wheel(tag='cp999-cp999-impossible')
        with self.assertRaisesRegex(ProbentiumError, 'parser_wheel_platform_unsupported'):
            p._wheel(path, digest, 'probentium')
        self.assertFalse(p._compatible('py3-none-mystery'))
        self.assertFalse(p._compatible('cp399-abi3-manylinux_2_17_x86_64'))
        self.assertTrue(p._compatible('py3-none-any'))
        with self.assertRaisesRegex(ProbentiumError, 'parser_dependency_inventory_mismatch'):
            p.prepare_manifest(path, digest, [])

    def test_manifest_rejects_omitted_dependencies_bad_types_and_relocations(self):
        manifest = self.manifest()
        changes = [lambda m: m.__setitem__('unknown', True), lambda m: m['distributions'].pop(),
                   lambda m: m['distributions'][0].__setitem__('name', []), lambda m: m['distributions'][0].__setitem__('version', '99'),
                   lambda m: m['distributions'][0]['files'][0].__setitem__('size', True),
                   lambda m: m['distributions'][0]['files'][0].__setitem__('target', '../outside'),
                   lambda m: m['runtime'].__setitem__('bits', True), lambda m: m['distributions'][0]['files'].append(m['distributions'][0]['files'][0])]
        for change in changes:
            value = copy.deepcopy(manifest)
            change(value)
            with self.assertRaises(ProbentiumError):
                p.validate_manifest(value)
        value = copy.deepcopy(manifest)
        value['runtime']['python'] = '3.99.0'
        with self.assertRaisesRegex(ProbentiumError, 'parser_runtime_mismatch'):
            p.verify_manifest(value)

    def test_installed_files_and_schema_are_verified_without_approval(self):
        manifest = self.manifest()
        self.install_fixture(manifest)
        receipt = p.verify_manifest(manifest)
        self.assertEqual(receipt['approval'], 'not_inferred')
        self.assertEqual(receipt['installed_bytes'], 'verified')
        self.assertEqual(receipt['manifest_digest'], object_digest(manifest, p.DOMAIN))
        for relative in ('probentium/__init__.py', 'cryptography/__init__.py'):
            item = self.site / relative
            original = item.read_bytes()
            item.write_bytes(b'tampered')
            with self.assertRaises(ProbentiumError):
                p.verify_manifest(manifest)
            item.write_bytes(original)
        item = self.prefix / 'share/probentium/schemas/events-v2.schema.json'
        item.write_bytes(b'{"changed":true}')
        with self.assertRaises(ProbentiumError):
            p.verify_manifest(manifest)

    def test_unlisted_runtime_file_and_symlink_fail_closed(self):
        manifest = self.manifest()
        self.install_fixture(manifest)
        unexpected = self.site / 'probentium/injected.py'
        unexpected.write_text('VALUE = 99\n')
        with self.assertRaisesRegex(ProbentiumError, 'parser_unexpected_installed_file'):
            p.verify_manifest(manifest)
        unexpected.unlink()
        unexpected.symlink_to(self.site / 'probentium/__init__.py')
        with self.assertRaisesRegex(ProbentiumError, 'parser_installed_path_invalid'):
            p.verify_manifest(manifest)

    def test_generated_metadata_and_cache_are_explicitly_excluded(self):
        manifest = self.manifest()
        self.install_fixture(manifest)
        info = self.site / 'probentium-0.2.0.dev3.dist-info'
        (info / 'direct_url.json').write_text('{"url":"file:///private/source"}')
        source = self.site / 'probentium/__init__.py'
        cached = Path(py_compile.compile(str(source), doraise=True))
        p.verify_manifest(manifest)
        raw = cached.read_bytes()
        cached.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        p.verify_manifest(manifest)
        self.assertIn('source_bytecode_not_used_by_parser_worker', manifest['installation_exceptions'])
        cached.rename(cached.with_name('unrelated.pyc'))
        with self.assertRaisesRegex(ProbentiumError, 'parser_unexpected_installed_file'):
            p.verify_manifest(manifest)
        self.assertNotIn('/private', canonical_bytes(manifest).decode())

    def test_source_development_origin_is_not_a_distribution(self):
        with self.assertRaisesRegex(ProbentiumError, 'parser_import_origin_mismatch'):
            p._import_origins({})

    def test_actual_parser_uses_private_empty_cache_prefix_without_writing(self):
        raw = b'{"kind":"auth.failure","timestamp":"2026-10-18T12:00:00Z","actor":"operator"}\n'
        with ParserWorker(len(raw)) as worker:
            arguments = worker.process.args
            self.assertIn('-I', arguments)
            self.assertIn('-B', arguments)
            prefix = next(argument.split('=', 1)[1] for argument in arguments if argument.startswith('pycache_prefix='))
            self.assertTrue(Path(prefix).is_relative_to(Path(worker.directory.name)))
            self.assertFalse(Path(prefix).exists())
            self.assertEqual(worker.parse(raw, 'events', 1)['kind'], 'auth.failure')
            self.assertFalse(Path(prefix).exists())

    def test_approval_requires_explicit_selection_and_revision(self):
        manifest = self.manifest()
        with CaseStore.create(self.root / 'case', 'Synthetic artifact approval') as case:
            with patch.object(p, 'prepare_manifest', return_value=manifest), patch.object(p, 'verify_manifest') as verification:
                item = p.register(case, 'unused.whl', '0' * 64, [], approved_by='operator', reason='Synthetic local review', expected_revision=0)
                self.assertEqual(item['kind'], 'parser_approval')
                verification.assert_not_called()
                self.assertEqual(p.resolve_approval(case, item['id']), manifest)
                verification.assert_called_once_with(manifest)
                with self.assertRaises(ProbentiumError):
                    p.register(case, 'unused.whl', '0' * 64, [], approved_by='operator', reason='Another review', expected_revision=0)
                bad = copy.deepcopy(item['data'])
                bad['manifest_digest'] = '0' * 64
                with self.assertRaisesRegex(ProbentiumError, 'parser_approval_digest_mismatch'):
                    p.validate_approval(bad)
                self.assertEqual(case.objects('claim'), [])
