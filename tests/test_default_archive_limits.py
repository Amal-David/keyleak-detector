"""Default archive scans must retain bounds without --scan-binaries."""

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from keyleak.archive_scanner import ArchiveScanError, extract_archive, scan_archive


class DefaultArchiveLimitTests(unittest.TestCase):
    def setUp(self):
        """Keep all fixtures small and private; lower limits instead of making bombs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_default_zip_checks_entry_limit_before_allocating_index(self):
        """Reject over-budget metadata before constructing ZipFile or scanning."""
        archive = self.root / "sample.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("one.txt", "one")
            zf.writestr("two.txt", "two")
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 1), \
             patch("keyleak.archive_scanner.zipfile.ZipFile") as constructor, \
             patch("keyleak.archive_scanner.scan_path") as scanner:
            with self.assertRaisesRegex(ArchiveScanError, "entry count"):
                scan_archive(str(archive))
        constructor.assert_not_called()
        scanner.assert_not_called()

    def test_default_zip_enforces_member_and_total_limits(self):
        """Enforce both byte budgets on the default public extraction path."""
        archive = self.root / "sample.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("one.txt", "12345678")
            zf.writestr("two.txt", "12345678")
        for setting, limit, message in (
            ("MAX_BINARY_ARCHIVE_MEMBER_BYTES", 4, "member exceeds"),
            ("MAX_BINARY_ARCHIVE_TOTAL_BYTES", 12, "total expanded"),
        ):
            with self.subTest(setting=setting), patch("keyleak.archive_scanner." + setting, limit):
                with self.assertRaisesRegex(ArchiveScanError, message):
                    scan_archive(str(archive))

    def test_default_compressed_tar_bounds_the_expanded_stream(self):
        """Count decompressed TAR metadata as well as member payloads."""
        archive = self.root / "sample.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            info = tarfile.TarInfo("hello.txt")
            info.size = 5
            tf.addfile(info, io.BytesIO(b"hello"))
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_TOTAL_BYTES", 256):
            with self.assertRaisesRegex(ArchiveScanError, "total expanded"):
                scan_archive(str(archive))

    def test_default_tar_rejects_links(self):
        """Do not accept symlinks or hardlinks even when they stay inside the archive."""
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                archive = self.root / "sample.tar"
                with tarfile.open(archive, "w") as tf:
                    info = tarfile.TarInfo("link")
                    info.type = kind
                    info.linkname = "hello.txt"
                    tf.addfile(info)
                with self.assertRaisesRegex(ArchiveScanError, "Link in tar"):
                    scan_archive(str(archive))

    def test_prefixed_zip_remains_scannable_with_metadata_limits(self):
        """A benign prepended stub must not break ZIP offset accounting."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("hello.txt", "hello")
            zf.writestr("second.txt", "second")
        archive = self.root / "prefixed.zip"
        archive.write_bytes(b"benign non-executable prefix\n" + buffer.getvalue())
        destination = self.root / "prefixed-output"
        destination.mkdir()
        extract_archive(archive, destination)
        self.assertEqual((destination / "hello.txt").read_text(), "hello")
        with patch("keyleak.archive_scanner.MAX_BINARY_ARCHIVE_ENTRIES", 1), \
             patch("keyleak.archive_scanner.zipfile.ZipFile") as constructor:
            with self.assertRaisesRegex(ArchiveScanError, "entry count"):
                extract_archive(archive, self.root / "rejected")
        constructor.assert_not_called()

    def test_supported_archives_still_extract_regular_text(self):
        """Keep the existing ZIP, TAR, gzip, and bzip2 formats usable."""
        for suffix, mode in ((".zip", None), (".tar", "w"), (".tgz", "w:gz"), (".tar.bz2", "w:bz2")):
            with self.subTest(suffix=suffix):
                archive = self.root / ("sample" + suffix)
                if mode is None:
                    with zipfile.ZipFile(archive, "w") as zf:
                        zf.writestr("hello.txt", "hello")
                else:
                    with tarfile.open(archive, mode) as tf:
                        info = tarfile.TarInfo("hello.txt")
                        info.size = 5
                        tf.addfile(info, io.BytesIO(b"hello"))
                destination = self.root / ("output" + suffix)
                destination.mkdir()
                extract_archive(archive, destination)
                self.assertEqual((destination / "hello.txt").read_text(), "hello")


if __name__ == "__main__":
    unittest.main()
