"""Exercise release-job permissions and the real uploader shell offline."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
UPLOAD_JOB = WORKFLOW["jobs"]["github-release-assets"]
UPLOAD_STEP = next(step for step in UPLOAD_JOB["steps"] if "run" in step)


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keyleak-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.log = self.root / "upload.json"
        stub = self.bin / "gh"
        stub.write_text(f"#!{sys.executable}\nimport json, os, pathlib, sys\npathlib.Path(os.environ['UPLOAD_LOG']).write_text(json.dumps(sys.argv[1:]))\n")
        stub.chmod(0o755)
        self.names = ["keyleak-detector-extension-v1.3.0.zip", "keyleak_detector-0.7.0-py3-none-any.whl", "keyleak_detector-0.7.0.tar.gz"]
        for name in self.names:
            (self.assets / name).write_bytes(f"synthetic {name}".encode())
        (self.assets / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.assets / name).read_bytes()).hexdigest()}  {name}\n"
            for name in sorted(self.names)
        ))

    def upload(self):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   GH_TOKEN="synthetic-token", RELEASE_TAG="v0.7.0",
                   GITHUB_REPOSITORY="test/fixture", UPLOAD_LOG=str(self.log))
        return subprocess.run(["bash", "-c", UPLOAD_STEP["run"]], cwd=self.assets,
                              env=env, text=True, capture_output=True, timeout=10)

    def test_permissions_keep_build_code_separate_from_publishing_credentials(self):
        self.assertEqual(WORKFLOW.get("on", WORKFLOW.get(True)), {"release": {"types": ["published"]}})
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})
        self.assertEqual(WORKFLOW["jobs"]["build"]["permissions"], {"contents": "read"})
        self.assertEqual(UPLOAD_JOB["permissions"], {"contents": "write"})
        self.assertEqual(UPLOAD_JOB["needs"], "build")
        self.assertEqual(len(UPLOAD_JOB["steps"]), 2)
        self.assertTrue(UPLOAD_JOB["steps"][0]["uses"].startswith("actions/download-artifact@"))
        self.assertNotIn("environment", WORKFLOW["jobs"]["pypi-publish"])
        for job in WORKFLOW["jobs"].values():
            privileged = any(value == "write" for value in job.get("permissions", {}).values())
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[a-f0-9]{40}$")
                    if privileged:
                        self.assertNotIn("checkout", step["uses"])
                if privileged and "run" in step:
                    self.assertNotRegex(step["run"], r"\b(?:python|node|npm|pip|poetry)\b")

    def test_verified_assets_upload_without_overwriting_existing_releases(self):
        result = self.upload()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.log.read_text()), ["release", "upload", "v0.7.0", *self.names, "SHA256SUMS", "--repo", "test/fixture"])

    def test_tampered_asset_stops_before_upload(self):
        (self.assets / self.names[0]).write_bytes(b"changed after checksumming")
        self.assertNotEqual(self.upload().returncode, 0)
        self.assertFalse(self.log.exists())

    def test_manifest_paths_are_compared_as_data_and_never_followed(self):
        (self.assets / "SHA256SUMS").write_text("0" * 64 + "  ../private-file\n")
        self.assertNotEqual(self.upload().returncode, 0)
        self.assertFalse(self.log.exists())

    def test_extra_wheel_and_linked_asset_stop_before_upload(self):
        extra = self.assets / "keyleak_detector-0.6.0-py3-none-any.whl"
        extra.write_bytes(b"old wheel")
        self.assertNotEqual(self.upload().returncode, 0)
        self.assertFalse(self.log.exists())
        extra.unlink()
        archive = self.assets / self.names[0]
        archive.rename(self.root / "private-file")
        archive.symlink_to(self.root / "private-file")
        self.assertNotEqual(self.upload().returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
