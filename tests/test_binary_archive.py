import io
import contextlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from keyleak.archive_scanner import (
    ArchiveScanError,
    _extract_binary_archive,
    scan_archive,
)
from keyleak.cli import main


class BinaryArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make_zip(self, name="app.zip", entries=None, compression=zipfile.ZIP_STORED):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for member, data in entries or [("app.bin", b"binary")]:
                archive.writestr(member, data)
        return path

    def extract(self, archive):
        dest = self.root / "out"
        dest.mkdir(exist_ok=True)
        return _extract_binary_archive(archive, dest)

    def test_zip_traversal_is_rejected(self):
        archive = self.make_zip(entries=[("../outside", b"bad")])
        with self.assertRaisesRegex(ArchiveScanError, "Unsafe archive member path"):
            self.extract(archive)

    def test_tar_traversal_is_rejected(self):
        archive = self.root / "unsafe.tar"
        with tarfile.open(archive, "w") as tf:
            info = tarfile.TarInfo("../../outside")
            info.size = 3
            tf.addfile(info, io.BytesIO(b"bad"))
        with self.assertRaisesRegex(ArchiveScanError, "Unsafe archive member path"):
            self.extract(archive)

    def test_zip_symlinks_are_rejected(self):
        archive = self.root / "link.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "target")
        with self.assertRaisesRegex(ArchiveScanError, "Symlink"):
            self.extract(archive)

    def test_tar_symlinks_and_hardlinks_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            archive = self.root / f"link-{kind}.tar"
            with tarfile.open(archive, "w") as tf:
                info = tarfile.TarInfo("link")
                info.type = kind
                info.linkname = "target"
                tf.addfile(info)
            with self.assertRaisesRegex(ArchiveScanError, "Link in tar"):
                self.extract(archive)

    def test_entry_count_limit(self):
        archive = self.make_zip(entries=[("one", b"1"), ("two", b"2")])
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 1):
            with self.assertRaisesRegex(ArchiveScanError, "entry count"):
                self.extract(archive)

    def test_zip_entry_limit_is_checked_before_zipfile_construction(self):
        archive = self.make_zip(entries=[("one", b"1"), ("two", b"2")])
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 1):
            with patch("keyleak.archive_scanner.zipfile.ZipFile") as zip_file:
                with self.assertRaisesRegex(ArchiveScanError, "entry count"):
                    self.extract(archive)
        zip_file.assert_not_called()

    def test_zip_central_directory_byte_limit_is_checked_before_zipfile(self):
        archive = self.make_zip(entries=[("one", b"1")])
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES", 1):
            with patch("keyleak.archive_scanner.zipfile.ZipFile") as zip_file:
                with self.assertRaisesRegex(ArchiveScanError, "central directory"):
                    self.extract(archive)
        zip_file.assert_not_called()

    def test_forged_low_zip_directory_size_does_not_bypass_byte_limit(self):
        archive = self.make_zip(entries=[("one", b"1")])
        contents = bytearray(archive.read_bytes())
        eocd = contents.rfind(b"PK\x05\x06")
        contents[eocd + 12:eocd + 16] = (1).to_bytes(4, "little")
        archive.write_bytes(contents)
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES", 20):
            with patch("keyleak.archive_scanner.zipfile.ZipFile") as zip_file:
                with self.assertRaisesRegex(ArchiveScanError, "central directory"):
                    self.extract(archive)
        zip_file.assert_not_called()

    def test_forged_low_zip_eocd_count_does_not_hide_entries(self):
        archive = self.make_zip(entries=[("one", b"1"), ("two", b"2")])
        contents = bytearray(archive.read_bytes())
        eocd = contents.rfind(b"PK\x05\x06")
        contents[eocd + 8:eocd + 12] = (1).to_bytes(2, "little") * 2
        contents[eocd + 12:eocd + 16] = (46).to_bytes(4, "little")
        archive.write_bytes(contents)
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 1):
            with patch("keyleak.archive_scanner.zipfile.ZipFile") as zip_file:
                with self.assertRaisesRegex(ArchiveScanError, "entry count"):
                    self.extract(archive)
        zip_file.assert_not_called()

    def test_member_and_aggregate_expanded_size_limits(self):
        archive = self.make_zip(entries=[("one", b"1234"), ("two", b"5678")])
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_MEMBER_BYTES", 3):
            with self.assertRaisesRegex(ArchiveScanError, "member exceeds"):
                self.extract(archive)
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_TOTAL_BYTES", 6):
            with self.assertRaisesRegex(ArchiveScanError, "total expanded"):
                self.extract(archive)

    def test_compression_ratio_limit(self):
        archive = self.make_zip(
            entries=[("payload", b"A" * 4096)], compression=zipfile.ZIP_DEFLATED
        )
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_RATIO", 2):
            with self.assertRaisesRegex(ArchiveScanError, "compression ratio"):
                self.extract(archive)

    def test_tar_pax_metadata_counts_toward_expanded_byte_limit(self):
        archive = self.root / "metadata.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tf:
            info = tarfile.TarInfo("small.txt")
            info.size = 1
            info.pax_headers = {"comment": "x" * 4096}
            tf.addfile(info, io.BytesIO(b"x"))
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_TOTAL_BYTES", 1024):
            with self.assertRaisesRegex(ArchiveScanError, "expanded size limit"):
                self.extract(archive)

    def test_apk_and_ipa_are_zip_containers_when_opted_in(self):
        for suffix in (".apk", ".ipa"):
            archive = self.make_zip(name=f"app{suffix}", entries=[("Payload/app", b"x")])
            self.assertTrue((self.extract(archive) / "Payload/app").exists())

    def test_scan_uses_normalized_archive_member_provenance_after_extraction(self):
        key = b"AKIA1234567890ABCDEF"
        member = b"\x00\x01prefix:" + key + b"\x00tail"
        archive = self.make_zip("release.apk", [("Payload/./app.bin", member)])
        result = scan_archive(str(archive), scan_binaries=True)
        findings = result["report"]["findings"]
        finding = next(item for item in findings if item["detector_id"] == "leak.aws_access_key")
        self.assertEqual(finding["source"], f"{archive.resolve()}!/Payload/app.bin")
        self.assertEqual(finding["evidence"]["byte_offset"], member.index(key))

    def test_scan_binaries_applies_to_pre_extracted_directory_inputs(self):
        directory = self.root / "release"
        directory.mkdir()
        member = directory / "app.bin"
        key = b"AKIA1234567890ABCDEF"
        member.write_bytes(b"prefix:" + key + b"\x00")

        report = scan_archive(str(directory), scan_binaries=True)["report"]
        finding = next(item for item in report["findings"] if item["detector_id"] == "leak.aws_access_key")

        self.assertEqual(finding["source"], str(member.resolve()))
        self.assertEqual(finding["evidence"]["byte_offset"], len(b"prefix:"))

    def test_archive_budget_failure_keeps_prior_findings_and_marks_incomplete(self):
        key = b"AKIA1234567890ABCDEF"
        archive = self.make_zip(
            "partial.zip",
            [("first.bin", b"prefix:" + key), ("too-large.bin", b"x" * 64)],
        )
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_MEMBER_BYTES", 32):
            envelope = scan_archive(str(archive), scan_binaries=True)
            report = envelope["report"]
            finding = next(
                item for item in report["findings"]
                if item["detector_id"] == "leak.aws_access_key"
            )

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main([
                    "archive", str(archive), "--scan-binaries", "--fail-on", "critical",
                ])

        self.assertEqual(finding["source"], f"{archive.resolve()}!/first.bin")
        self.assertEqual(finding["evidence"]["byte_offset"], len(b"prefix:"))
        self.assertEqual(report["coverage"]["status"], "incomplete")
        self.assertTrue(report["archive_extraction_incomplete"])
        self.assertEqual(exit_code, 2)

    def test_binary_scanning_remains_opt_in(self):
        archive = self.make_zip()
        report = type("Report", (), {"to_dict": lambda self: {"findings": []}})()
        with patch("keyleak.archive_scanner.scan_path", return_value=report) as scan:
            scan_archive(str(archive))
        self.assertNotIn("scan_binaries", scan.call_args.kwargs)
        self.assertNotIn("binary_source_prefix", scan.call_args.kwargs)

    def test_archive_contents_are_never_executed(self):
        marker = self.root / "executed"
        script = f"#!/bin/sh\ntouch {marker}\n"
        archive = self.make_zip("app.ipa", [("Payload/run.sh", script.encode())])
        scan_archive(str(archive), scan_binaries=True)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
