"""Offline release-boundary regressions for the allowlisted extension ZIP."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
import zipfile

from scripts.build_extension import EXTENSION_FILES, build_extension


ROOT = Path(__file__).resolve().parents[1]


class ExtensionPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyleak-extension-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.output = self.root / "dist"
        for name in EXTENSION_FILES:
            destination = self.root / "extension" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "extension" / name, destination)
        shutil.copyfile(ROOT / "pyproject.toml", self.root / "pyproject.toml")

    def manifest(self, mutate):
        path = self.root / "extension/manifest.json"
        document = json.loads(path.read_text())
        mutate(document)
        path.write_text(json.dumps(document))

    def build(self, **options):
        return build_extension(self.root, self.output, **options)

    def test_zip_is_deterministic_has_manifest_at_root_and_excludes_private_files(self):
        for name in (".env", "tests/private.test.js", "lib/unreviewed.js", "package.json"):
            path = self.root / "extension" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PRIVATE_SYNTHETIC_CANARY")
        result = self.build()
        first = (self.output / result["archive"]).read_bytes()
        for name in EXTENSION_FILES:
            path = self.root / "extension" / name
            os.utime(path, (1780000000, 1780000000))
            path.chmod(0o755)
        self.build()
        self.assertEqual(first, (self.output / result["archive"]).read_bytes())
        self.assertNotIn(b"PRIVATE_SYNTHETIC_CANARY", first)
        with zipfile.ZipFile(self.output / result["archive"]) as archive:
            self.assertEqual(archive.namelist(), sorted(EXTENSION_FILES))
            self.assertEqual(json.loads(archive.read("manifest.json"))["version"], result["version"])
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist()))
            self.assertTrue(all((info.external_attr >> 16) & 0o777 == 0o644 for info in archive.infolist()))
        digest, name = (self.output / "SHA256SUMS").read_text().split()
        self.assertEqual(name, result["archive"])
        self.assertEqual(digest, hashlib.sha256(first).hexdigest())

    def test_missing_runtime_input_fails_before_writing(self):
        (self.root / "extension/lib/analyzer.js").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_manifest_assets_must_be_in_explicit_allowlist(self):
        for reference in ("missing.js", "../private.js", "https://example.test/remote.js", "icons/%2e%2e/private.js"):
            with self.subTest(reference=reference):
                self.manifest(lambda doc: doc["background"].update(service_worker=reference))
                with self.assertRaisesRegex(ValueError, "asset reference|Asset reference"):
                    self.build()
        self.assertFalse(self.output.exists())

    def test_new_manifest_asset_fields_require_review(self):
        self.manifest(lambda doc: doc.update(web_accessible_resources=[{"resources": ["*"], "matches": ["<all_urls>"]}]))
        with self.assertRaisesRegex(ValueError, "Review new manifest fields"):
            self.build()

    def test_invalid_chrome_versions_cannot_change_archive_path(self):
        for version in ("../private", "0.0.0", "1.02.3", "65536", "1.2.3.4.5", "1.3.0-beta", "1\n2"):
            with self.subTest(version=version):
                self.manifest(lambda doc: doc.update(version=version))
                with self.assertRaisesRegex(ValueError, "version"):
                    self.build()
        self.assertFalse(self.output.exists())

    def test_html_module_and_devtools_references_are_checked(self):
        cases = (
            ("popup/popup.html", b'<script src="missing.js"></script>'),
            ("popup/popup.html", b'<script src="https://example.test/remote.js"></script>'),
            ("popup/popup.js", b"import { missing } from '../lib/missing.js';\n"),
            ("popup/popup.js", b"import('../lib/missing.js');\n"),
            ("devtools/devtools.js", b"chrome.devtools.panels.create('Secrets', null, 'missing.html');\n"),
        )
        for name, content in cases:
            with self.subTest(name=name, content=content):
                path = self.root / "extension" / name
                original = path.read_bytes()
                path.write_bytes(content)
                try:
                    with self.assertRaisesRegex(ValueError, "asset reference|Asset reference"):
                        self.build()
                finally:
                    path.write_bytes(original)

    def test_symlink_file_and_parent_directory_are_rejected(self):
        source = self.root / "extension/lib/analyzer.js"
        target = self.root / "private.js"
        source.rename(target)
        source.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build()
        source.unlink()
        target.rename(source)
        directory = self.root / "extension/lib"
        target_directory = self.root / "private-lib"
        directory.rename(target_directory)
        directory.symlink_to(target_directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build()

    def test_output_cannot_overwrite_sources_or_follow_links(self):
        with self.assertRaisesRegex(ValueError, "under dist"):
            build_extension(self.root, self.root / "extension")
        self.output.symlink_to(self.root / "extension", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build()

    def python_artifacts(self):
        version = tomllib.loads((self.root / "pyproject.toml").read_text())["project"]["version"]
        self.output.mkdir(exist_ok=True)
        names = (f"keyleak_detector-{version}-py3-none-any.whl", f"keyleak_detector-{version}.tar.gz")
        for name in names:
            (self.output / name).write_bytes(b"synthetic artifact bytes")
        return names

    def test_release_checksums_cover_exactly_current_python_artifacts_and_zip(self):
        expected = set(self.python_artifacts())
        (self.output / "private-report.json").write_text("PRIVATE_SYNTHETIC_CANARY")
        result = self.build(include_python=True)
        expected.add(result["archive"])
        checksums = (self.output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual({line.split()[1] for line in checksums}, expected)
        for line in checksums:
            digest, name = line.split()
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertNotIn("private-report", "\n".join(checksums))

    def test_missing_extra_or_linked_python_artifacts_fail_closed(self):
        names = self.python_artifacts()
        missing = self.output / names[0]
        missing.unlink()
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.build(include_python=True)
        missing.write_bytes(b"synthetic wheel")
        extra = self.output / "unrelated-1.0-py3-none-any.whl"
        extra.write_bytes(b"unrelated")
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.build(include_python=True)
        extra.unlink()
        missing.unlink()
        missing.symlink_to(self.root / "pyproject.toml")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build(include_python=True)


if __name__ == "__main__":
    unittest.main()
