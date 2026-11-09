"""Publication-boundary tests: only intended static files may leave the checkout."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_browser_app", ROOT / "scripts" / "build_browser_app.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BrowserBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "repo"
        self.output = self.base / "public"
        self.write("web/index.html", '<script type="module" src="./src/app.js"></script>')
        self.write("web/styles.css", "body { color: #123; }")
        self.write("web/src/app.js", "import { scan } from '../../extension/lib/analyzer.js';\n")
        self.write("web/sw.js", "const version = '__KEYLEAK_CACHE_VERSION__';\nconst assets = __KEYLEAK_OFFLINE_ASSETS__;\n")
        self.write("web/manifest.webmanifest", '{"start_url":"./","scope":"./"}')
        for name in BUILDER.ENGINE_MODULES:
            self.write(f"extension/lib/{name}", "export const scan = () => [];\n")
        self.write("site/php-check/index.html", '<script src="./checker.js"></script>')
        self.write("site/php-check/checker.js", "/* legacy PHP checker */")
        self.write("site/favicon.ico", "icon")

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def snapshot(self):
        return {str(path.relative_to(self.output)): path.read_bytes()
                for path in self.output.rglob("*") if path.is_file()}

    def test_only_public_runtime_files_are_published(self):
        for name in (".env", "scan-results.json", "site/CNAME", "web/.env",
                     "web/tests/private.test.js", "web/node_modules/secret.js",
                     "web/src/unused.test.js", "web/src/node_modules/secret.js",
                     "extension/lib/key-tester.js"):
            self.write(name, "private development data")
        manifest = BUILDER.build_browser_app(self.repo, self.output)
        published = self.snapshot()
        self.assertEqual(set(published), {
            "index.html", "styles.css", "src/app.js", "sw.js", "manifest.webmanifest",
            "engine/analyzer.js", "engine/patterns.js", "engine/false-positives.js",
            "engine/reporting.js", "php-check/index.html", "php-check/checker.js",
            "favicon.ico", ".nojekyll", "offline-assets.json",
        })
        self.assertIn(b"'../engine/analyzer.js'", published["src/app.js"])
        self.assertEqual(published["php-check/checker.js"], b"/* legacy PHP checker */")
        self.assertNotIn("./php-check/checker.js", manifest["assets"])
        self.assertTrue(all(asset.startswith("./") for asset in manifest["assets"]))
        for asset in manifest["assets"]:
            self.assertTrue((self.output / asset).is_file(), asset)
        self.assertNotIn(b"__KEYLEAK_", published["sw.js"])

    def test_identical_inputs_are_reproducible_and_remove_stale_build_files(self):
        first = BUILDER.build_browser_app(self.repo, self.output)
        before = self.snapshot()
        (self.output / "stale.js").write_text("old code")
        second = BUILDER.build_browser_app(self.repo, self.output)
        self.assertEqual(first, second)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(json.loads((self.output / "offline-assets.json").read_text()), first)

    def test_code_and_service_worker_changes_invalidate_cache_version(self):
        first = BUILDER.build_browser_app(self.repo, self.output)
        self.write("extension/lib/patterns.js", "export const updated = true;")
        second = BUILDER.build_browser_app(self.repo, self.output)
        self.assertNotEqual(first["version"], second["version"])
        source = self.repo / "web/sw.js"
        source.write_text(source.read_text() + "\n// changed worker logic\n")
        third = BUILDER.build_browser_app(self.repo, self.output)
        self.assertNotEqual(second["version"], third["version"])

    def test_missing_input_does_not_destroy_previous_build(self):
        BUILDER.build_browser_app(self.repo, self.output)
        before = self.snapshot()
        (self.repo / "extension/lib/reporting.js").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            BUILDER.build_browser_app(self.repo, self.output)
        self.assertEqual(before, self.snapshot())

    def test_refuses_source_tree_and_unrelated_output_directories(self):
        for output in (self.repo, self.repo / "web", self.repo.parent):
            with self.subTest(output=output), self.assertRaises(ValueError):
                BUILDER.build_browser_app(self.repo, output)
        self.output.mkdir()
        (self.output / "keep.txt").write_text("not a build")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            BUILDER.build_browser_app(self.repo, self.output)
        self.assertEqual((self.output / "keep.txt").read_text(), "not a build")

    def test_refuses_symlinked_publish_inputs(self):
        target = self.base / "private.js"
        target.write_text("not intended for publishing")
        link = self.repo / "web/src/app.js"
        link.unlink()
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            BUILDER.build_browser_app(self.repo, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
