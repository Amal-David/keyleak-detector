import io
import lzma
import contextlib
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from keyleak.archive_scanner import (
    ArchiveScanError,
    _copy_limited,
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
        """Keep fixture extraction roots separate so duplicate-member checks remain meaningful."""
        dest = self.root / (archive.name + ".out")
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

    def test_scan_binaries_visits_native_members_under_dist(self):
        member = (Path(__file__).parent / "fixtures" / "binary_canary.macho").read_bytes()
        archive = self.make_zip("release.zip", [("dist/app.macho", member)])

        report = scan_archive(str(archive), scan_binaries=True)["report"]

        finding = next(item for item in report["findings"] if item["detector_id"] == "leak.aws_access_key")
        self.assertEqual(finding["source"], f"{archive.resolve()}!/dist/app.macho")
        self.assertEqual(finding["evidence"]["byte_offset"], member.index(b"AKIA1234567890ABCDEF"))
        self.assertEqual(report["coverage"]["status"], "complete")

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
        """Stable member provenance must not implicitly enable binary extraction."""
        archive = self.make_zip()
        report = type("Report", (), {"to_dict": lambda self: {"findings": []}})()
        with patch("keyleak.archive_scanner.scan_path", return_value=report) as scan:
            scan_archive(str(archive))
        self.assertNotIn("scan_binaries", scan.call_args.kwargs)
        self.assertEqual(scan.call_args.kwargs["binary_source_prefix"], str(archive.resolve()))

    def test_archive_contents_are_never_executed(self):
        marker = self.root / "executed"
        script = f"#!/bin/sh\ntouch {marker}\n"
        archive = self.make_zip("app.ipa", [("Payload/run.sh", script.encode())])
        scan_archive(str(archive), scan_binaries=True)
        self.assertFalse(marker.exists())

    def test_nested_archives_preserve_provenance_and_share_limits(self):
        """Nesting preserves logical member identities without resetting resource limits."""
        key = b"AKIA1234567890ABCDEF"
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("second.bin", key)
        outer = self.make_zip(entries=[("first.bin", key), ("inner.zip", inner.getvalue())])
        report = scan_archive(str(outer), scan_binaries=True)["report"]
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(report["coverage"]["status"], "complete")
        self.assertIn(f"{outer.resolve()}!/inner.zip!/second.bin", {f["source"] for f in report["findings"]})
        self.assertEqual(report["scan_manifest"]["archives"][0]["status"], "expanded")
        limits = [
            ("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 2),
            ("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_TOTAL_BYTES", len(inner.getvalue()) + len(key)),
            ("keyleak.binary_scanner.MAX_BINARY_FILES", 1),
            ("keyleak.archive_scanner.MAX_ARCHIVE_DEPTH", 0),
        ]
        for name, value in limits:
            with self.subTest(limit=name), patch(name, value):
                limited = scan_archive(str(outer), scan_binaries=True)["report"]
                self.assertEqual(len(limited["findings"]), 1)
                self.assertEqual(limited["coverage"]["status"], "incomplete")

    def test_duplicate_and_malformed_nested_members_keep_prior_evidence(self):
        """Rejected members must not overwrite or discard previously collected evidence."""
        key = b"AKIA1234567890ABCDEF"
        for entries in ([('first.bin', key), ('broken.zip', b'not a zip')],
                        [('first.bin', key), ('first.bin', b'overwritten')]):
            with self.subTest(entries=len(entries)):
                archive = self.make_zip(entries=entries)
                report = scan_archive(str(archive), scan_binaries=True)["report"]
                self.assertEqual(len(report["findings"]), 1)
                self.assertEqual(report["coverage"]["status"], "incomplete")

    def test_oversized_input_returns_incomplete_instead_of_a_success_or_traceback(self):
        """An input cap is an incomplete assessment and must produce the corresponding CLI exit."""
        archive = self.make_zip()
        with patch("keyleak.archive_scanner.MAX_ARCHIVE_INPUT_BYTES", 1):
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["archive", str(archive), "--scan-binaries"])
            report = scan_archive(str(archive), scan_binaries=True)["report"]
        self.assertEqual(status, 2)
        self.assertEqual(report["input_artifact"]["status"], "input_limit")
        self.assertEqual(report["coverage"]["status"], "incomplete")

    def test_directory_nested_snapshots_share_a_copy_budget(self):
        """Directory inputs must obey one aggregate snapshot budget across nested containers."""
        key = b"AKIA1234567890ABCDEF"
        directory = self.root / "release"
        directory.mkdir()
        for name in ("first.zip", "second.zip"):
            with zipfile.ZipFile(directory / name, "w") as archive:
                archive.writestr("app.bin", key)
        size = (directory / "first.zip").stat().st_size
        with patch("keyleak.archive_scanner.MAX_ARCHIVE_INPUT_BYTES", size):
            report = scan_archive(str(directory), scan_binaries=True)["report"]
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["coverage"]["status"], "incomplete")

    def test_input_digest_and_findings_describe_the_same_snapshot(self):
        """Changing the original after copying must not change the bytes bound to the report."""
        import hashlib
        key = b"AKIA1234567890ABCDEF"
        archive = self.make_zip(entries=[("app.bin", key)])
        original_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        extract = _extract_binary_archive

        def replace_original(snapshot, dest, **kwargs):
            """Mutate only the original input to test the snapshot's independence."""
            archive.write_bytes(b"changed after snapshot")
            return extract(snapshot, dest, **kwargs)

        with patch("keyleak.archive_scanner._extract_binary_archive", side_effect=replace_original):
            report = scan_archive(str(archive), scan_binaries=True)["report"]
        self.assertEqual(report["input_artifact"]["sha256"], original_hash)
        self.assertEqual(len(report["findings"]), 1)

    def test_nested_expansion_respects_local_directory_exclusions(self):
        """Container discovery cannot widen the directory scope selected by the local scanner."""
        key = b"AKIA1234567890ABCDEF"
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as zf:
            zf.writestr("app.bin", key)
        archive = self.make_zip(entries=[("app.bin", key), ("package/dist/nested.zip", nested.getvalue())])
        report = scan_archive(str(archive), scan_binaries=True)["report"]
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["scan_manifest"]["archives"], [])
        self.assertEqual(report["inventory"]["excluded_directories"], 1)
        self.assertEqual(report["coverage"]["status"], "complete")

    def test_failed_member_does_not_reserve_unused_snapshot_budget(self):
        """An oversized or unreadable first archive must not suppress a later valid one."""
        key = b"AKIA1234567890ABCDEF"
        contents = io.BytesIO()
        with zipfile.ZipFile(contents, "w") as zf:
            zf.writestr("app.bin", key)
        from keyleak.archive_scanner import _snapshot_archive
        for failure in ("oversized", "unreadable"):
            with self.subTest(failure=failure):
                directory = self.root / failure
                directory.mkdir()
                bad = (directory / "a-bad.zip").resolve()
                bad.write_bytes(contents.getvalue() + (b"x" if failure == "oversized" else b""))
                (directory / "b-good.zip").write_bytes(contents.getvalue())

                def snapshot_or_fail(archive, snapshot, limit, **kwargs):
                    """Inject a read failure without depending on host permission semantics."""
                    if archive == bad and failure == "unreadable":
                        raise PermissionError("synthetic read failure")
                    return _snapshot_archive(archive, snapshot, limit, **kwargs)

                with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_MEMBER_BYTES", len(contents.getvalue())), \
                     patch("keyleak.archive_scanner._snapshot_archive", side_effect=snapshot_or_fail):
                    report = scan_archive(str(directory), scan_binaries=True)["report"]
                self.assertEqual(len(report["findings"]), 1)
                self.assertTrue(report["findings"][0]["source"].endswith("b-good.zip!/app.bin"))
                self.assertEqual(report["coverage"]["status"], "incomplete")

    def test_partial_snapshot_charges_actual_bytes_and_preserves_remaining_budget(self):
        """A failed copy consumes its written prefix, leaving only the true remaining budget."""
        key = b"AKIA1234567890ABCDEF"
        directory = self.root / "partial-copy"
        directory.mkdir()
        contents = io.BytesIO()
        with zipfile.ZipFile(contents, "w") as zf:
            zf.writestr("app.bin", key)
        for name in ("a-bad.zip", "b-good.zip", "c-over-budget.zip"):
            (directory / name).write_bytes(contents.getvalue())
        bad = (directory / "a-bad.zip").resolve()
        broken = io.BytesIO()
        broken.read = unittest.mock.Mock(side_effect=[contents.getvalue()[:4], OSError("synthetic read failure")])
        original_open = Path.open

        def open_with_failure(path, *args, **kwargs):
            """Fail after one copied prefix while using real files for all other I/O."""
            if path == bad and args and args[0] == "rb":
                return broken
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", open_with_failure), \
             patch("keyleak.archive_scanner.MAX_ARCHIVE_INPUT_BYTES", 2 * len(contents.getvalue()) + 3):
            report = scan_archive(str(directory), scan_binaries=True)["report"]
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings"][0]["source"].endswith("b-good.zip!/app.bin"))
        self.assertEqual([item["status"] for item in report["scan_manifest"]["archives"]],
                         ["unreadable", "expanded", "unreadable"])
        self.assertEqual(report["coverage"]["status"], "incomplete")

    def test_corrupt_compressed_tar_keeps_parent_and_later_sibling_findings(self):
        """A malformed compressed child must not abort the enclosing assessment."""
        key = b"AKIA1234567890ABCDEF"
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as zf:
            zf.writestr("app.bin", key)
        for suffix, invalid in (("xz", b"invalid xz"), ("gz", b"\x1f\x8b\x08\x00" + bytes(6) + b"\xff" * 20)):
            with self.subTest(compression=suffix):
                archive = self.make_zip(entries=[("first.bin", key), (f"a-bad.tar.{suffix}", invalid),
                                                 ("z-good.zip", nested.getvalue())])
                report = scan_archive(str(archive), scan_binaries=True)["report"]
                self.assertEqual(len(report["findings"]), 2)
                self.assertTrue(any(f["source"].endswith("z-good.zip!/app.bin") for f in report["findings"]))
                self.assertEqual(report["coverage"]["status"], "incomplete")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["archive", str(archive), "--scan-binaries", "--fail-on", "critical"]), 2)

    def test_decoder_read_error_removes_a_partial_member(self):
        """Partially decompressed bytes must not masquerade as a complete extracted member."""
        for error in (lzma.LZMAError, zlib.error, tarfile.ReadError):
            with self.subTest(decoder_error=error):
                source = unittest.mock.Mock()
                source.read.side_effect = [b"partial", error("synthetic corruption")]
                target = self.root / "partial.bin"
                with self.assertRaises(error):
                    _copy_limited(source, target, 16, 16, 0)
                self.assertFalse(target.exists())

    def test_truncated_tar_does_not_report_a_partial_member_as_scanned(self):
        """A rejected member must be absent from the successful artifact manifest."""
        key = b"AKIA1234567890ABCDEF"
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode="w") as archive:
            for name, value in (("first.bin", key), ("partial.bin", b"x" * 1024)):
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        path = self.root / "truncated.tar"
        path.write_bytes(contents.getvalue()[:1536 + 16])
        report = scan_archive(str(path), scan_binaries=True)["report"]
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual([a["source"] for a in report["scan_manifest"]["artifacts"]],
                         [f"{path.resolve()}!/first.bin"])
        self.assertEqual(report["coverage"]["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
