"""Prevent installation paths from silently using different direct dependencies."""

from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"([A-Za-z0-9_.-]+)(?:\[([A-Za-z0-9_,.-]+)\])?==([^\s;]+)")


def canonical_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


class DependencyManifestConsistencyTests(unittest.TestCase):
    def normalize_pins(self, entries):
        result = {}
        for entry in entries:
            match = PIN.fullmatch(entry)
            self.assertIsNotNone(match, f"Runtime dependencies must be exact pins: {entry}")
            name, extras, version = match.groups()
            name = canonical_name(name)
            self.assertNotIn(name, result, f"Duplicate dependency: {name}")
            result[name] = (version, tuple(sorted(
                canonical_name(extra) for extra in (extras or "").split(",") if extra
            )))
        return result

    def test_all_installation_paths_declare_the_same_pins_and_extras(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        requirements = [
            line.strip() for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        pep621 = self.normalize_pins(project["project"]["dependencies"])
        poetry_pins = []
        for name, declaration in project["tool"]["poetry"]["dependencies"].items():
            if name == "python":
                self.assertEqual(declaration, project["project"]["requires-python"])
                continue
            if isinstance(declaration, str):
                poetry_pins.append(f"{name}=={declaration}")
            else:
                self.assertEqual(set(declaration), {"version", "extras"})
                extras = ",".join(declaration["extras"])
                poetry_pins.append(f"{name}[{extras}]=={declaration['version']}")
        self.assertEqual(pep621, self.normalize_pins(requirements))
        self.assertEqual(pep621, self.normalize_pins(poetry_pins))

        # Poetry checks the whole lock graph in CI; this catches a direct pin
        # drifting even when the tests are run outside the Poetry workflow.
        lock = tomllib.loads((ROOT / "poetry.lock").read_text(encoding="utf-8"))
        locked_versions = {}
        for package in lock["package"]:
            locked_versions.setdefault(canonical_name(package["name"]), set()).add(package["version"])
        for name, (version, _) in pep621.items():
            self.assertEqual(locked_versions.get(name), {version}, f"Stale lock entry for {name}")


if __name__ == "__main__":
    unittest.main()
