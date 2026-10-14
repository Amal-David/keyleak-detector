"""Regression tests that run against the real CLI/scanner in repository CI."""

import inspect
import os
import unittest
from unittest import mock

from keyleak.cli import build_parser
from keyleak import site_scanner


class DistributionIntegrationTests(unittest.TestCase):
    def test_site_cli_defaults_to_no_install(self):
        args = build_parser().parse_args(["site-scan", "example.test"])
        self.assertTrue(args.no_auto_install)

    def test_site_cli_explicit_consent(self):
        args = build_parser().parse_args(["site-scan", "example.test", "--auto-install"])
        self.assertFalse(args.no_auto_install)

    def test_site_api_defaults_to_no_install(self):
        self.assertIs(inspect.signature(site_scanner.scan_site).parameters["auto_install"].default, False)

    def test_discovery_api_defaults_to_no_install(self):
        self.assertIs(inspect.signature(site_scanner.discover_subdomains).parameters["auto_install"].default, False)

    def test_ensure_api_defaults_to_no_install(self):
        self.assertIs(inspect.signature(site_scanner._ensure_subfinder).parameters["auto_install"].default, False)

    def test_missing_tool_does_not_run_installer_by_default(self):
        with mock.patch.object(site_scanner.shutil, "which", return_value=None), \
             mock.patch.object(site_scanner.subprocess, "run") as run, \
             mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(site_scanner._ensure_subfinder())
            run.assert_not_called()

    def test_managed_install_veto_prevents_all_subprocesses(self):
        with mock.patch.object(site_scanner.shutil, "which", return_value=None), \
             mock.patch.object(site_scanner.subprocess, "run") as run, \
             mock.patch.dict(os.environ, {"KEYLEAK_MANAGED_INSTALL": "1"}, clear=True):
            self.assertFalse(site_scanner._ensure_subfinder(auto_install=True))
            run.assert_not_called()

    def test_present_tool_is_usable_even_with_installation_disabled(self):
        with mock.patch.object(site_scanner.shutil, "which", return_value="/usr/bin/subfinder"), \
             mock.patch.object(site_scanner.subprocess, "run") as run, \
             mock.patch.dict(os.environ, {"KEYLEAK_MANAGED_INSTALL": "1"}, clear=True):
            self.assertTrue(site_scanner._ensure_subfinder())
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
