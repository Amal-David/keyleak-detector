import json
import textwrap
import tempfile
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from unittest import mock

from keyleak.cli import main
from keyleak.local_scanner import scan_path
import unittest

from keyleak.serialization_audit import audit_python_serialization
from keyleak.reporting import build_report, format_html, format_markdown, format_sarif


class SerializationAuditTests(unittest.TestCase):
    def audit(self, source):
        return audit_python_serialization(textwrap.dedent(source), "app/settings.py")

    def test_generated_holders_need_no_literal_key(self):
        for declaration in (
            "from dataclasses import dataclass\n@dataclass\nclass Config:",
            "from attrs import define\n@define\nclass Config:",
            "from pydantic import BaseModel\nclass Config(BaseModel):",
            "from typing import NamedTuple\nclass Config(NamedTuple):",
        ):
            with self.subTest(declaration=declaration):
                findings = self.audit(declaration + "\n    api_key: str\n")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "medium")
                self.assertEqual(findings[0].validation_status, "lead")

    def test_repr_false_is_partial_until_dump_is_used(self):
        holder = '''\
            import dataclasses as dc
            @dc.dataclass
            class Config:
                password: str = dc.field(repr=False)
        '''
        self.assertEqual(self.audit(holder), [])
        findings = self.audit(textwrap.dedent(holder) + "\nconfig = Config()\ndc.asdict(config)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("dump", findings[0].evidence.snippet)

    def test_pydantic_flags_protect_different_paths(self):
        for flags, sink, expected in (
            ("repr=False", "repr(config)", 0),
            ("repr=False", "config.model_dump()", 1),
            ("exclude=True", "config.model_dump()", 0),
            ("exclude=True", "repr(config)", 1),
            ("repr=False, exclude=True", "repr(config)\nconfig.model_dump()", 0),
        ):
            with self.subTest(flags=flags, sink=sink):
                findings = self.audit(f"from pydantic import BaseModel, Field\nclass Config(BaseModel):\n    token: str = Field({flags})\nconfig = Config()\n{sink}\n")
                self.assertEqual(len(findings), expected)
                if findings:
                    self.assertEqual(findings[0].severity, "high")

    def test_raw_access_bypasses_flags_and_wrappers(self):
        holder = "from pydantic import BaseModel, Field, SecretStr\nclass Config(BaseModel):\n    token: SecretStr = Field(repr=False, exclude=True)\nconfig = Config()\n"
        for sink in ("vars(config)", "config.__dict__", "import pickle\npickle.dumps(config)", "import json\njson.dumps(config, default=vars)"):
            with self.subTest(sink=sink):
                findings = self.audit(holder + sink)
                self.assertEqual(len(findings), 1)
                self.assertIn("raw attributes", findings[0].evidence.snippet)
                self.assertIn("allowlist", findings[0].remediation)

    def test_logging_formatting_alias_and_typed_parameter(self):
        findings = self.audit('''\
            from dataclasses import dataclass
            @dataclass
            class Config:
                clientSecret: str
            def log(config: Config):
                alias = config
                logger.info("%s", alias)
                return f"{config!r}"
        ''')
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item.severity == "high" for item in findings))

    def test_reassignment_and_separate_function_scopes_do_not_connect(self):
        findings = self.audit('''\
            from dataclasses import dataclass, field, asdict
            @dataclass
            class Config:
                token: str = field(repr=False)
            def first():
                config = Config()
            def second():
                asdict(config)
            config = Config()
            config = object()
            asdict(config)
        ''')
        self.assertEqual(findings, [])

    def test_no_generated_holder_no_findings_and_classvars_are_not_fields(self):
        self.assertEqual(self.audit('''\
            from dataclasses import dataclass, InitVar
            from typing import ClassVar
            class Plain:
                password: str
            @dataclass
            class Config:
                token_count: ClassVar[int]
                password: InitVar[str]
                tokenizer: str
                label: str
        '''), [])

    def test_secret_wrapper_generated_paths_and_safe_dict_are_not_reported(self):
        self.assertEqual(self.audit('''\
            from pydantic import BaseModel, SecretStr
            class Config(BaseModel):
                token: SecretStr
            config = Config()
            repr(config)
            config.model_dump()
            logger.info({"kind": type(config).__name__})
        '''), [])

    def test_custom_dump_and_filtered_asdict_are_not_assumed_to_expose(self):
        self.assertEqual(self.audit("from dataclasses import dataclass, field, asdict\n@dataclass\nclass Config:\n    token: str = field(repr=False)\nconfig = Config()\nasdict(config, dict_factory=safe_dict)\n"), [])
        self.assertEqual(self.audit("from pydantic import BaseModel, Field\nclass Config(BaseModel):\n    token: str = Field(repr=False)\n    def model_dump(self): return {}\nconfig = Config()\nconfig.model_dump()\n"), [])

    def test_secret_union_annotation_is_not_assumed_to_coerce_to_wrapper(self):
        findings = self.audit("from pydantic import BaseModel, SecretStr\nclass Config(BaseModel):\n    token: str | SecretStr\nconfig = Config()\nrepr(config)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_evidence_never_copies_source_values(self):
        marker = "private-runtime-value-for-redaction-check"
        findings = self.audit(f"from dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str = '{marker}'\nrepr(Config())\n")
        report = build_report("app/settings.py", findings, scan_mode="local")
        for serialized in (json.dumps(report.to_dict()), format_html(report), format_markdown(report), format_sarif(report)):
            self.assertNotIn(marker, serialized)
            self.assertIn("secret_serialization", serialized)

    def test_syntax_error_is_not_a_clean_result(self):
        with self.assertRaises(SyntaxError):
            self.audit("class Config(:")

    def test_attrs_legacy_fields_and_namedtuple_dump(self):
        for holder, sink in (
            ("import attr\n@attr.s\nclass Config:\n    token = attr.ib(repr=False)", "attr.asdict(config)"),
            ("from typing import NamedTuple\nclass Config(NamedTuple):\n    token: str", "config._asdict()"),
        ):
            with self.subTest(holder=holder):
                findings = self.audit(holder + "\nconfig = Config()\n" + sink)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "high")

    def test_dataclass_annotation_alone_does_not_wrap_plain_string(self):
        findings = self.audit("from dataclasses import dataclass\nfrom pydantic import SecretStr\n@dataclass\nclass Config:\n    token: SecretStr\nrepr(Config('plain-string'))\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_import_and_constructor_shadowing_do_not_trace(self):
        source = "from dataclasses import dataclass, field, asdict\n@dataclass\nclass Config:\n    token: str = field(repr=False)\n"
        for body in (
            "def render(Config):\n    asdict(Config())",
            "config = Config()\nasdict = lambda value: {}\nasdict(config)",
            "config = Config()\nif ready:\n    config = object()\nasdict(config)",
            "for config in []:\n    config = Config()\nasdict(config)",
            "config = Config()\n[asdict(config) for config in []]",
        ):
            with self.subTest(body=body):
                self.assertEqual(self.audit(source + body), [])

    def test_custom_repr_only_blocks_the_generated_repr_path(self):
        findings = self.audit("from dataclasses import dataclass, asdict\n@dataclass\nclass Config:\n    password: str\n    def __repr__(self): return 'Config'\nconfig = Config()\nrepr(config)\nasdict(config)\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("dump", findings[0].evidence.snippet)


class SerializationLocalTests(unittest.TestCase):
    def test_opt_in_cli_replay_and_report_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.py"
            path.write_text("from dataclasses import dataclass, asdict\n@dataclass\nclass Config:\n    api_key: str\nasdict(Config())\n")
            default = scan_path(directory, packs=["leak"])
            self.assertFalse(any(item.type == "secret_serialization" for item in default.findings))
            report = scan_path(directory, includes=["serialization"], packs=["leak"])
            (finding,) = [item for item in report.findings if item.type == "secret_serialization"]
            self.assertEqual(finding.severity, "high")
            self.assertEqual(finding.evidence.line, 5)
            self.assertEqual(report.extra["coverage"]["status"], "complete")
            self.assertIn("serialization", report.retest_command)
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                code = main(["local", directory, "--include", "serialization", "--packs", "leak", "--json"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["summary"]["high_severity"], 1)

    def test_invalid_and_oversized_source_have_incomplete_coverage(self):
        for content in (b"class Config(:", b"x = '\xff'", b"#" * (5 * 1024 * 1024 + 1)):
            with self.subTest(size=len(content)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "settings.py"
                path.write_bytes(content)
                report = scan_path(directory, includes=["serialization"], packs=["leak"])
                self.assertEqual(report.extra["coverage"]["status"], "incomplete")
                self.assertNotEqual(report.verdict["status"], "SAFE_TO_SHIP")

    def test_analysis_limits_retain_findings_and_mark_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.py"
            path.write_text("from dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str\nrepr(Config())\nrepr(Config())\nrepr(Config())\n")
            with mock.patch("keyleak.serialization_audit.MAX_FINDINGS", 2):
                report = scan_path(directory, includes=["serialization"], packs=["leak"])
            self.assertEqual(len([item for item in report.findings if item.type == "secret_serialization"]), 2)
            self.assertEqual(report.extra["coverage"]["status"], "incomplete")
            self.assertEqual(report.extra["scan_manifest"]["artifacts"][0]["status"], "partial")
            with mock.patch("keyleak.serialization_audit.MAX_AST_NODES", 2):
                report = scan_path(directory, includes=["serialization"], packs=["leak"])
            self.assertEqual(report.extra["coverage"]["status"], "incomplete")

    def test_empty_scope_and_wrong_pack_are_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix, packs in (("js", ["leak"]), ("py", ["appsec"])):
                with self.subTest(suffix=suffix, packs=packs):
                    path = Path(directory) / ("settings." + suffix)
                    path.write_text("# no runtime credentials")
                    report = scan_path(str(path), includes=["serialization"], packs=packs)
                    self.assertEqual(report.extra["coverage"]["status"], "incomplete")

    def test_test_fixture_and_example_holders_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            for folder in ("tests", "fixtures", "examples", "node_modules", ".venv", "dist"):
                path = Path(directory) / folder / "settings.py"
                path.parent.mkdir()
                path.write_text("from dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str\n")
            report = scan_path(directory, includes=["serialization"], packs=["leak"])
            self.assertFalse(any(item.type == "secret_serialization" for item in report.findings))
            self.assertEqual(report.extra["coverage"]["status"], "incomplete")

    def test_source_is_not_executed_and_pep263_encoding_is_respected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.py"
            path.write_bytes(b"# coding: latin-1\nraise RuntimeError('\xe9')\nfrom dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str\n")
            report = scan_path(directory, includes=["serialization"], packs=["leak"])
            self.assertEqual(report.extra["coverage"]["status"], "complete")
            self.assertTrue(any(item.type == "secret_serialization" for item in report.findings))


class SerializationReviewRegressions(unittest.TestCase):
    def test_attribute_writes_keep_holder_type(self):
        source = "from dataclasses import dataclass, field, asdict\n@dataclass\nclass Config:\n    token: str = field(repr=False)\nconfig = Config('fixture')\nconfig.token = 'updated'\nasdict(config)\n"
        findings = audit_python_serialization(source, "settings.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_explicit_repr_conversions_bypass_safe_string_methods(self):
        base = "from pydantic import BaseModel, Field\nclass Config(BaseModel):\n    token: str = Field(exclude=True)\n    def __str__(self): return 'safe'\n    def __format__(self, spec): return 'safe'\nconfig = Config(token='fixture')\n"
        for conversion in ('r', 'a'):
            with self.subTest(conversion=conversion):
                findings = audit_python_serialization(base + 'f"{config!' + conversion + '}"', "settings.py")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].severity, "high")
        self.assertEqual(audit_python_serialization(base + 'f"{config}"', "settings.py"), [])

    def test_attr_namespace_aliases_preserve_partial_protection(self):
        for decorator in ('define', 'frozen', 'mutable'):
            with self.subTest(decorator=decorator):
                base = f"import attr\n@attr.{decorator}\nclass Config:\n    token: str = attr.field(repr=False)\nconfig = Config('fixture')\n"
                self.assertEqual(audit_python_serialization(base, "settings.py"), [])
                self.assertEqual(audit_python_serialization(base + 'attr.asdict(config)', "settings.py")[0].severity, 'high')

    def test_optional_secret_wrappers_are_safe_but_scalar_secrets_remain(self):
        for annotation in ('Optional[SecretStr]', 'SecretStr | None', 'None | SecretStr', 'Union[None, SecretStr]'):
            with self.subTest(annotation=annotation):
                base = f"from typing import Optional, Union\nfrom pydantic import BaseModel, SecretStr\nclass Config(BaseModel):\n    token: {annotation}\nconfig = Config(token='fixture')\nrepr(config)\nconfig.model_dump()"
                self.assertEqual(audit_python_serialization(base, 'settings.py'), [])
        for field, annotation in (('token', 'int'), ('password', 'int'), ('token', 'str | SecretStr')):
            with self.subTest(field=field, annotation=annotation):
                base = f"from pydantic import BaseModel, SecretStr\nclass Config(BaseModel):\n    {field}: {annotation}\nrepr(Config())"
                self.assertEqual(audit_python_serialization(base, 'settings.py')[0].severity, 'high')
        source = "from dataclasses import dataclass\n@dataclass\nclass Config:\n    token_ttl: int\n    password_min_length: int\n    cookie_secure: bool\n"
        self.assertEqual(audit_python_serialization(source, 'settings.py'), [])

    def test_non_holder_methods_are_scanned(self):
        source = "from pydantic import BaseModel, Field\nclass Config(BaseModel):\n    token: str = Field(exclude=True)\nclass Service:\n    def run(self, config: Config):\n        logger.info(config)"
        self.assertEqual(audit_python_serialization(source, 'settings.py')[0].severity, 'high')

    def test_structural_fingerprint_can_suppress_across_line_changes(self):
        from keyleak.suppressions import SuppressionSet, is_suppressed
        source = "from dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str\n"
        with mock.patch.dict('os.environ', {'KEYLEAK_FINDING_FINGERPRINT_KEY': 'fixture-key'}):
            first = audit_python_serialization(source, 'settings.py')[0]
            second = audit_python_serialization('\n' + source, 'settings.py')[0]
        self.assertTrue(first.fingerprint)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertTrue(is_suppressed(second, SuppressionSet(fingerprints={first.fingerprint})))

    def test_scan_root_ancestor_names_do_not_exclude_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'examples' / 'project'
            root.mkdir(parents=True)
            path = root / 'settings.py'
            path.write_text("from dataclasses import dataclass\n@dataclass\nclass Config:\n    token: str\n")
            for target in (root, path):
                report = scan_path(str(target), includes=['serialization'], packs=['leak'])
                self.assertTrue(any(f.type == 'secret_serialization' for f in report.findings))
