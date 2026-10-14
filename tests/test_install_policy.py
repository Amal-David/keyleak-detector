"""Offline tests for optional-tool consent and package-manager vetoes."""

import argparse
import contextlib
import io
import os
import unittest
from unittest import mock

from keyleak.install_policy import add_tool_install_flags, tool_install_allowed


class ToolInstallPolicyTests(unittest.TestCase):
    def test_default_is_no_install(self):
        self.assertFalse(tool_install_allowed(environ={}))

    def test_explicit_consent(self):
        self.assertTrue(tool_install_allowed(requested=True, environ={}))

    def test_false_request(self):
        self.assertFalse(tool_install_allowed(requested=False, environ={}))

    def test_truthy_objects_are_not_consent(self):
        for value in ("true", "false", 1, [True], None):
            with self.subTest(value=value):
                self.assertFalse(tool_install_allowed(requested=value, environ={}))

    def test_environment_never_grants_consent(self):
        self.assertFalse(tool_install_allowed(environ={"KEYLEAK_AUTO_INSTALL": "1"}))

    def test_existing_opt_out_wins(self):
        self.assertFalse(tool_install_allowed(requested=True, environ={"KEYLEAK_NO_AUTO_INSTALL": "1"}))

    def test_managed_install_wins(self):
        self.assertFalse(tool_install_allowed(requested=True, environ={"KEYLEAK_MANAGED_INSTALL": "1"}))

    def test_all_disable_spellings(self):
        for name in ("KEYLEAK_NO_AUTO_INSTALL", "KEYLEAK_MANAGED_INSTALL"):
            for value in ("1", "true", "yes", "on", " TRUE ", "Yes", "ON"):
                with self.subTest(name=name, value=value):
                    self.assertFalse(tool_install_allowed(requested=True, environ={name: value}))

    def test_explicit_false_veto_values(self):
        for name in ("KEYLEAK_NO_AUTO_INSTALL", "KEYLEAK_MANAGED_INSTALL"):
            for value in ("", "0", "false", "no", "off", " FALSE "):
                with self.subTest(name=name, value=value):
                    self.assertTrue(tool_install_allowed(requested=True, environ={name: value}))

    def test_unknown_nonempty_veto_fails_closed(self):
        for name in ("KEYLEAK_NO_AUTO_INSTALL", "KEYLEAK_MANAGED_INSTALL"):
            for value in ("tru", "enabled", "2"):
                with self.subTest(name=name, value=value):
                    self.assertFalse(tool_install_allowed(requested=True, environ={name: value}))

    def test_one_veto_is_enough(self):
        self.assertFalse(tool_install_allowed(requested=True, environ={
            "KEYLEAK_NO_AUTO_INSTALL": "0", "KEYLEAK_MANAGED_INSTALL": "1",
        }))
        self.assertFalse(tool_install_allowed(requested=True, environ={
            "KEYLEAK_NO_AUTO_INSTALL": "1", "KEYLEAK_MANAGED_INSTALL": "0",
        }))

    def test_reads_current_environment(self):
        with mock.patch.dict(os.environ, {"KEYLEAK_MANAGED_INSTALL": "1"}, clear=True):
            self.assertFalse(tool_install_allowed(requested=True))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(tool_install_allowed(requested=True))

    def test_explicit_empty_mapping_does_not_read_environment(self):
        with mock.patch.dict(os.environ, {"KEYLEAK_MANAGED_INSTALL": "1"}, clear=True):
            self.assertTrue(tool_install_allowed(requested=True, environ={}))

    def test_does_not_mutate_settings(self):
        settings = {"KEYLEAK_MANAGED_INSTALL": " 0 "}
        tool_install_allowed(requested=True, environ=settings)
        self.assertEqual(settings, {"KEYLEAK_MANAGED_INSTALL": " 0 "})


class ToolInstallFlagTests(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser()
        add_tool_install_flags(self.parser)

    def test_default_preserves_legacy_field_and_disables_install(self):
        self.assertTrue(self.parser.parse_args([]).no_auto_install)

    def test_explicit_enable(self):
        self.assertFalse(self.parser.parse_args(["--auto-install"]).no_auto_install)

    def test_explicit_disable(self):
        self.assertTrue(self.parser.parse_args(["--no-auto-install"]).no_auto_install)

    def test_conflicting_flags_rejected_in_either_order(self):
        for args in (["--auto-install", "--no-auto-install"], ["--no-auto-install", "--auto-install"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    self.parser.parse_args(args)
                self.assertEqual(raised.exception.code, 2)

    def test_help_names_both_vetoes(self):
        text = self.parser.format_help()
        self.assertIn("KEYLEAK_MANAGED_INSTALL", text)
        self.assertIn("KEYLEAK_NO_AUTO_INSTALL", text)

    def test_consent_does_not_override_veto(self):
        args = self.parser.parse_args(["--auto-install"])
        self.assertFalse(tool_install_allowed(requested=not args.no_auto_install,
                                             environ={"KEYLEAK_MANAGED_INSTALL": "1"}))


if __name__ == "__main__":
    unittest.main()
