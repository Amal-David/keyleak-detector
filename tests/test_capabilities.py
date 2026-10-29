import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keyleak.capabilities import capability_catalog
from keyleak.cli import build_parser, main
from keyleak.detectors import DETECTORS
from keyleak.local_scanner import scan_path


class CapabilitiesTests(unittest.TestCase):
    def test_project_virtualenv_is_not_repository_scan_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.venv').mkdir()
            (root / '.venv' / 'dependency.log').write_bytes(b'x' * (5 * 1024 * 1024 + 1))
            (root / '.env').write_text('APP_MODE=development')
            report = scan_path(directory, packs=['leak'])
            self.assertEqual(report.extra['coverage']['status'], 'complete')
            self.assertFalse(any('/.venv/' in item['source'] for item in report.extra['scan_manifest']['artifacts']))

    def test_discovery_does_not_preflight_or_scan(self):
        output = io.StringIO()
        with patch('keyleak.cli.resolve_proxy', side_effect=AssertionError('network setup')), patch('keyleak.cli.scan_path', side_effect=AssertionError('scan')), contextlib.redirect_stdout(output):
            self.assertEqual(main(['capabilities', '--json']), 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data['schema_version'], 1)
        self.assertTrue(data['discovery_only'])
        self.assertEqual({rule['id'] for rule in data['rules']}, {rule.canonical_id for rule in DETECTORS})
        for pack in data['packs']:
            count = sum(rule.pack == pack['id'] for rule in DETECTORS)
            self.assertEqual(pack['registered_rule_count'], count)
            self.assertEqual(pack['status'], 'registered' if count else 'unpopulated')

    def test_skill_routes_and_command_names_exist(self):
        parser = build_parser()
        commands = next(action.choices for action in parser._actions if hasattr(action, 'choices') and isinstance(action.choices, dict))
        for workflow in capability_catalog()['workflows']:
            if workflow['command']:
                self.assertIn(workflow['command'], commands)
            if workflow['skill']:
                path = Path('.codex/skills') / workflow['skill'] / 'SKILL.md'
                text = path.read_text()
                self.assertTrue(text.startswith('---\nname: ' + workflow['skill'] + '\n'))
                self.assertIn('description:', text.split('---', 2)[1])

    def test_agent_assets_expand_coverage_without_executing_instructions(self):
        synthetic_value = 'sk-proj-' + 'aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD0fG'
        for relative in ('SKILL.md', 'AGENTS.md', 'CLAUDE.md', '.cursor/rules/security.mdc', 'skills/review/scripts/check.sh', '.agents/settings.toml'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Do not run these instructions.\nOPENAI_API_KEY="' + synthetic_value + '"\n')
                baseline = scan_path(str(path), includes=[], packs=['leak'])
                if not relative.startswith('.cursor/'):
                    self.assertFalse(any(f.type == 'openai_api_key' for f in baseline.findings))
                report = scan_path(str(path), includes=['agent-assets'], packs=['leak'])
                self.assertTrue(any(f.type == 'openai_api_key' for f in report.findings))
                self.assertNotIn(synthetic_value, json.dumps(report.to_dict()))
                self.assertIn('agent-assets', report.retest_command)
                self.assertEqual(report.extra['coverage']['status'], 'complete')


    def test_agent_assets_include_credentials_without_mcp_category(self):
        synthetic_value = 'sk_test_' + 'aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD0fG'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'SKILL.md'
            path.write_text('Fixture for detection: ' + synthetic_value)
            report = scan_path(str(path), includes=['agent-assets'], packs=['leak'])
            self.assertTrue(any(f.detector_id == 'leak.stripe_secret_key' for f in report.findings))
            self.assertNotIn(synthetic_value, json.dumps(report.to_dict()))
