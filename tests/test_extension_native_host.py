"""Contracts for Chrome-triggered local scanner lifecycle management."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from keyleak import extension_host
from keyleak import extension_host_install
from keyleak import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
CHALLENGE = "a" * 64
PROOF = "b" * 64


class NativeHostLifecycleTests(unittest.TestCase):
    def test_health_payload_requires_keyleak_service_identity(self):
        self.assertFalse(extension_host.is_keyleak_health({"status": "ok"}))
        self.assertTrue(
            extension_host.is_keyleak_health(
                {"status": "ok", "service": "keyleak-detector"}
            )
        )

    def test_scanner_health_sends_the_locally_derived_proof(self):
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(
            {"status": "ok", "service": "keyleak-detector"}
        ).encode("utf-8")
        response.__enter__.return_value = response

        with mock.patch.object(
            extension_host,
            "urlopen",
            return_value=response,
        ) as open_url:
            health = extension_host.scanner_health(CHALLENGE, PROOF)

        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("X-keyleak-proof"), PROOF)
        self.assertEqual(
            health,
            {"status": "ok", "service": "keyleak-detector"},
        )

    def test_docker_binary_preserves_multicall_symlink_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "docker-tools"
            target.touch()
            docker = root / "docker"
            docker.symlink_to(target)
            with mock.patch.object(extension_host.shutil, "which", return_value=str(docker)):
                selected = extension_host.docker_binary()

        self.assertEqual(selected, str(docker))

    def test_extension_failure_copy_never_sends_users_back_to_manual_docker(self):
        popup = (REPO_ROOT / "extension" / "popup" / "popup.js").read_text(encoding="utf-8")
        worker = (REPO_ROOT / "extension" / "service-worker.js").read_text(encoding="utf-8")

        self.assertNotIn("docker compose", popup.lower())
        self.assertNotIn("docker compose", worker.lower())
        self.assertIn("Starting the local scanner automatically", popup)

    def test_extension_scan_route_is_authenticated_and_reports_activity(self):
        app_source = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
        worker = (REPO_ROOT / "extension" / "service-worker.js").read_text(
            encoding="utf-8"
        )

        self.assertIn("@_active_scans.track", app_source)
        self.assertIn("'scan_active': _active_scans.active", app_source)
        self.assertIn("@app.route('/extension/scan'", app_source)
        self.assertIn("proof_matches(", app_source)
        self.assertIn("scannerRequestHeaders", worker)
        self.assertIn("${LOCAL_SERVER}/extension/scan", worker)

    def test_message_surface_accepts_only_fixed_lifecycle_actions(self):
        with mock.patch.object(extension_host, "ensure_running", return_value={"ok": True}):
            self.assertEqual(
                extension_host.handle_message(
                    {"action": "ensure_running", "challenge": CHALLENGE}
                ),
                {"ok": True},
            )
            extension_host.ensure_running.assert_called_once_with(CHALLENGE)

        rejected = extension_host.handle_message(
            {
                "action": "ensure_running",
                "challenge": CHALLENGE,
                "url": "https://example.test/?token=secret",
            }
        )
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["code"], "INVALID_MESSAGE")

        rejected = extension_host.handle_message({"action": "ensure_running"})
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["code"], "INVALID_MESSAGE")

        rejected = extension_host.handle_message({"action": "run"})
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["code"], "UNSUPPORTED_ACTION")

    def test_ensure_running_starts_only_the_named_compose_service_and_records_ownership(self):
        with (
            mock.patch.object(
                extension_host,
                "scanner_health",
                side_effect=[None, None, {"status": "ok", "proof": PROOF}],
            ),
            mock.patch.object(extension_host, "extension_token", return_value="token"),
            mock.patch.object(extension_host, "challenge_proof", return_value=PROOF),
            mock.patch.object(extension_host, "ensure_docker_ready"),
            mock.patch.object(extension_host, "compose_container_id", side_effect=[None, "container-123"]),
            mock.patch.object(extension_host, "run_compose") as run_compose,
            mock.patch.object(extension_host, "write_owner") as write_owner,
            mock.patch.object(extension_host, "renew_lease", return_value="lease-1") as renew,
            mock.patch.object(extension_host, "schedule_watchdog") as schedule,
        ):
            result = extension_host.ensure_running(CHALLENGE)

        run_compose.assert_called_once_with(
            "up",
            "-d",
            extension_host.COMPOSE_SERVICE,
            auth_token="token",
        )
        write_owner.assert_called_once_with("container-123")
        renew.assert_called_once_with()
        schedule.assert_called_once_with("lease-1")
        self.assertEqual(
            result,
            {
                "ok": True,
                "status": "started",
                "owned": True,
                "proof": PROOF,
            },
        )

    def test_rebuild_transfers_helper_ownership_to_the_recreated_container(self):
        with (
            mock.patch.object(
                extension_host,
                "scanner_health",
                side_effect=[None, None, {"status": "ok", "proof": PROOF}],
            ),
            mock.patch.object(extension_host, "extension_token", return_value="token"),
            mock.patch.object(extension_host, "challenge_proof", return_value=PROOF),
            mock.patch.object(extension_host, "ensure_docker_ready"),
            mock.patch.object(extension_host, "compose_container_id", side_effect=["old", "new"]),
            mock.patch.object(extension_host, "read_owner", return_value={"container_id": "old"}),
            mock.patch.object(extension_host, "run_compose"),
            mock.patch.object(extension_host, "write_owner") as write_owner,
            mock.patch.object(extension_host, "renew_lease", return_value="lease-2"),
            mock.patch.object(extension_host, "schedule_watchdog"),
        ):
            result = extension_host.ensure_running(CHALLENGE)

        write_owner.assert_called_once_with("new")
        self.assertEqual(
            result,
            {
                "ok": True,
                "status": "started",
                "owned": True,
                "proof": PROOF,
            },
        )

    def test_existing_unowned_scanner_is_never_stopped_or_claimed(self):
        with (
            mock.patch.object(
                extension_host,
                "scanner_health",
                side_effect=[
                    {"status": "ok", "service": "keyleak-detector", "proof": PROOF}
                ],
            ),
            mock.patch.object(extension_host, "extension_token", return_value="token"),
            mock.patch.object(extension_host, "challenge_proof", return_value=PROOF),
            mock.patch.object(extension_host, "ensure_docker_ready"),
            mock.patch.object(
                extension_host,
                "compose_container_id",
                return_value="manual-container",
            ),
            mock.patch.object(extension_host, "read_owner", return_value=None),
            mock.patch.object(extension_host, "run_compose") as run_compose,
            mock.patch.object(extension_host, "renew_lease") as renew,
        ):
            result = extension_host.ensure_running(CHALLENGE)

        run_compose.assert_not_called()
        renew.assert_not_called()
        self.assertEqual(
            result,
            {
                "ok": True,
                "status": "already_running",
                "owned": False,
                "proof": PROOF,
            },
        )

    def test_authenticated_health_without_a_compose_container_is_not_trusted(self):
        with (
            mock.patch.object(
                extension_host,
                "scanner_health",
                return_value={"status": "ok", "service": "keyleak-detector"},
            ),
            mock.patch.object(extension_host, "extension_token", return_value="token"),
            mock.patch.object(extension_host, "challenge_proof", return_value=PROOF),
            mock.patch.object(extension_host, "ensure_docker_ready"),
            mock.patch.object(extension_host, "compose_container_id", return_value=None),
            mock.patch.object(extension_host, "read_owner", return_value=None),
            mock.patch.object(extension_host, "run_compose") as run_compose,
        ):
            with self.assertRaisesRegex(
                extension_host.NativeHostError,
                "managed Compose container",
            ):
                extension_host.ensure_running(CHALLENGE)

        run_compose.assert_not_called()

    def test_touch_renews_without_polling_compose_or_spawning_another_watchdog(self):
        with (
            mock.patch.object(extension_host, "read_owner", return_value={"container_id": "owned"}),
            mock.patch.object(extension_host, "renew_lease", return_value="same-token") as renew,
            mock.patch.object(extension_host, "compose_container_id") as compose_id,
            mock.patch.object(extension_host, "schedule_watchdog") as schedule,
        ):
            result = extension_host.touch()

        renew.assert_called_once_with()
        compose_id.assert_not_called()
        schedule.assert_not_called()
        self.assertEqual(result, {"ok": True, "owned": True})

    def test_idle_watchdog_stops_only_the_container_recorded_as_owned(self):
        with (
            mock.patch.object(extension_host, "read_owner", return_value={"container_id": "container-123"}),
            mock.patch.object(extension_host, "compose_container_id", return_value="container-123"),
            mock.patch.object(extension_host, "run_compose") as run_compose,
            mock.patch.object(extension_host, "clear_owner") as clear_owner,
        ):
            self.assertTrue(extension_host.stop_owned_container())

        run_compose.assert_called_once_with("stop", extension_host.COMPOSE_SERVICE)
        clear_owner.assert_called_once_with()

        with (
            mock.patch.object(extension_host, "read_owner", return_value={"container_id": "old"}),
            mock.patch.object(extension_host, "compose_container_id", return_value="replacement"),
            mock.patch.object(extension_host, "run_compose") as run_compose,
        ):
            self.assertFalse(extension_host.stop_owned_container())
        run_compose.assert_not_called()


class NativeHostInstallerTests(unittest.TestCase):
    def test_cli_exposes_one_time_installer_with_optional_explicit_id(self):
        args = cli.build_parser().parse_args(
            [
                "install-extension-host",
                "--extension-id",
                "abcdefghijklmnopabcdefghijklmnop",
            ]
        )

        self.assertEqual(args.command, "install-extension-host")
        self.assertEqual(args.extension_id, ["abcdefghijklmnopabcdefghijklmnop"])

    def test_discovers_unpacked_extension_and_writes_exact_origin_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            extension_dir = root / "checkout" / "extension"
            extension_dir.mkdir(parents=True)
            profile = root / "Chrome" / "Default"
            profile.mkdir(parents=True)
            (profile / "Preferences").write_text(
                json.dumps(
                    {
                        "extensions": {
                            "settings": {
                                "abcdefghijklmnopabcdefghijklmnop": {
                                    "path": str(extension_dir),
                                    "state": 1,
                                }
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            ids = extension_host_install.discover_extension_ids(
                extension_dir,
                [root / "Chrome"],
            )
            manifest = extension_host_install.build_manifest(ids, root / "launcher")

        self.assertEqual(ids, ["abcdefghijklmnopabcdefghijklmnop"])
        self.assertEqual(
            manifest["allowed_origins"],
            ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
        )
        self.assertEqual(manifest["path"], str((root / "launcher").resolve()))

    def test_invalid_preferences_shapes_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            extension_dir = root / "checkout" / "extension"
            extension_dir.mkdir(parents=True)
            profile = root / "Chrome" / "Default"
            profile.mkdir(parents=True)

            for invalid_payload in ([], {"extensions": []}, {"extensions": None}):
                (profile / "Preferences").write_text(
                    json.dumps(invalid_payload),
                    encoding="utf-8",
                )
                self.assertEqual(
                    extension_host_install.discover_extension_ids(
                        extension_dir,
                        [root / "Chrome"],
                    ),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
