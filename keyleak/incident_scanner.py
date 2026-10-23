"""Read-only, bounded checks for the October 2026 incident snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import stat
import tomllib
from pathlib import Path

from .models import Evidence, Finding, build_coverage
from .reporting import build_report


SNAPSHOT = "2026-10-22"
LITELLM_REFERENCE = "https://docs.litellm.ai/blog/security-incident-oct-21-2026"
TRUST_REFERENCE = "https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576"
RAILWAY_REFERENCE = "https://blog.railway.com/p/security-disclosure-wednesday-october-21st"
ROOTS_REFERENCE = "https://emudhra.we-have-a-problem.com/roots.json"
TRUST_MINIMUMS = {"certifi": (2026, 10, 19), "pip": (26, 2, 2), "uv": (0, 13, 4),
                  "sigstore": (4, 5, 1), "conda": (26, 9, 4), "pixi": (0, 82, 1)}
MALICIOUS_NPM = {
    "claude-desktop-setup": "https://github.com/advisories/GHSA-f4mf-vhm8-xxqc",
    "@decoopus/claude-setup": "https://osv.dev/vulnerability/MAL-2026-18054",
}
TRUST_ANCHORS = {
    "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d": "emSign Root TLS CA - G3",
    "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5": "emSign Root CS CA - G3",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services",
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
}
MANIFESTS = ("requirements.txt", "poetry.lock", "uv.lock", "package.json", "package-lock.json")
MAX_BYTES = 4 * 1024 * 1024


def _finding(source, detector, title, evidence, reason, fix, reference, severity="high"):
    return Finding(type=title, severity=severity, confidence=0.9,
                   detector_id=f"incident:{detector}", source=str(source),
                   evidence=Evidence(source=str(source), snippet=evidence, redacted_value=evidence),
                   risk_reason=reason, remediation=fix, category="leak",
                   validation_status="lead", references=[reference])


def _dependency_findings(name, version, ecosystem, source):
    findings = []
    if ecosystem == "npm":
        if name in MALICIOUS_NPM:
            findings.append(_finding(
                source, "malicious-npm", "Known malicious npm dependency", name,
                "The dependency is covered by a malware advisory. A manifest does not prove it ran.",
                "Remove it. If installed or run, isolate and rebuild the environment and rotate reachable credentials from a clean machine.",
                MALICIOUS_NPM[name], "critical"))
        return findings
    name = re.sub(r"[-_.]+", "-", name).lower()
    if name not in TRUST_MINIMUMS and name != "litellm":
        return findings
    stable = re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", version)
    if not stable:
        return [_finding(source, "unresolved-dependency", "Incident dependency version needs verification", name,
                         "No exact stable version was available in this input.",
                         "Check the resolved installed version against the incident advisory.",
                         LITELLM_REFERENCE if name == "litellm" else TRUST_REFERENCE, "medium")]
    parsed = tuple(map(int, version.split(".")))
    evidence = f"{name}=={version}"
    if name == "litellm" and parsed == (1, 107, 0):
        findings.append(_finding(
            source, "litellm-20261021", "Compromised LiteLLM release reference", evidence,
            "The manifest references the compromised release; source-tag contents do not establish artifact safety.",
            "Do not start Python in an affected environment. Rebuild from verified artifacts and rotate all reachable credentials from a clean environment if it ran.",
            LITELLM_REFERENCE, "critical"))
    elif name in TRUST_MINIMUMS and parsed < TRUST_MINIMUMS[name]:
        minimum = ".".join(map(str, TRUST_MINIMUMS[name]))
        findings.append(_finding(
            source, "emudhra-package", "Trust-store package predates incident update", evidence,
            "This pinned version predates the published eMudhra trust-store remediation; vendor backports require separate verification.",
            f"Update {name} to {minimum} or a vendor-confirmed fixed build. Rebuild environments and images; check independent runtime trust stores.",
            TRUST_REFERENCE))
    return findings


def _manifest_dependencies(path, text):
    if path.name == "requirements.txt":
        text = re.sub(r"\\\r?\n\s*", " ", text)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(.*)$", line)
            if match:
                spec = match[2].split(";", 1)[0].split(" #", 1)[0].strip()
                exact = re.fullmatch(r"==([0-9.]+)(?:\s+--hash=\S+)*", spec)
                yield match[1], exact[1] if exact else "", "PyPI"
            else:
                raise ValueError("unsupported requirements directive")
    elif path.name in {"poetry.lock", "uv.lock"}:
        data = tomllib.loads(text)
        packages = data.get("package", [])
        if not isinstance(packages, list):
            raise ValueError("package must be an array of tables")
        for package in packages:
            if (not isinstance(package, dict) or not isinstance(package.get("name"), str)
                    or not isinstance(package.get("version", ""), str)):
                raise ValueError("invalid package metadata")
            yield package["name"], package.get("version", ""), "PyPI"
    else:
        data = json.loads(text)
        if path.name == "package.json":
            for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for name, version in data.get(group, {}).items():
                    yield _npm_dependency(name, version)
        else:
            if not any(key in data for key in ("packages", "dependencies")):
                raise ValueError("unsupported npm lockfile structure")
            if any(not isinstance(data[key], dict) for key in ("packages", "dependencies") if key in data):
                raise ValueError("invalid npm lockfile structure")
            # npm v2/v3 retain the install path even when the name field is absent.
            for location, package in data.get("packages", {}).items():
                if "node_modules/" in location:
                    name = package.get("name") or location.rsplit("node_modules/", 1)[-1]
                    yield _npm_dependency(name, package.get("version", ""))
            pending = list(data.get("dependencies", {}).items())
            while pending:
                name, package = pending.pop()
                yield _npm_dependency(name, package.get("version", ""))
                pending.extend(package.get("dependencies", {}).items())


def _npm_dependency(name, version):
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("invalid npm dependency metadata")
    alias = re.fullmatch(r"npm:(@[^/\s]+/[^@\s]+|[^@/\s]+)@.+", version)
    return (alias[1] if alias else name), version, "npm"


def _bundle_findings(path, text):
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if not blocks or text.count("-----BEGIN CERTIFICATE-----") != len(blocks):
        raise ValueError("missing or truncated PEM certificates")
    findings = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    for block in blocks:
        der = ssl.PEM_cert_to_DER_cert(block)
        # Validate that the PEM actually encodes an X.509 certificate.
        context.load_verify_locations(cadata=block)
        fingerprint = hashlib.sha256(der).hexdigest()
        if fingerprint in TRUST_ANCHORS:
            findings.append(_finding(
                path, "emudhra-anchor", "Incident-related trust anchor present",
                f"{TRUST_ANCHORS[fingerprint]} SHA256:{fingerprint}",
                "This anchor can chain to compromised intermediates. Its presence alone does not prove acceptance when a client enforces revocation or distrust policies.",
                "Apply your runtime/vendor trust update and verify compromised chains are rejected. Do not remove unrelated certificates by subject-name matching.",
                ROOTS_REFERENCE))
    return findings


def scan_incidents(path: str, *, ca_bundle=None, railway=False):
    target = Path(path).expanduser()
    if target.is_symlink() or not target.exists():
        raise ValueError("Supply an existing regular manifest or project directory, not a symlink.")
    files = [target / name for name in MANIFESTS if (target / name).exists()] if target.is_dir() else [target]
    manifests_found = bool(files)
    if ca_bundle:
        files.append(Path(ca_bundle).expanduser())
    findings, reasons = [], []
    completed = 0
    if not manifests_found:
        reasons.append("No supported root manifests were found; nested projects are outside this check.")
    for file in files:
        try:
            if file.is_symlink() or not stat.S_ISREG(file.stat().st_mode):
                raise ValueError("not a regular file")
            with file.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("file exceeds size limit")
            text = raw.decode("utf-8")
            if ca_bundle and file == Path(ca_bundle).expanduser():
                findings.extend(_bundle_findings(file, text))
            elif file.name in MANIFESTS:
                seen = set()
                for name, version, ecosystem in _manifest_dependencies(file, text):
                    dependency = (name, version, ecosystem)
                    if dependency in seen:
                        continue
                    seen.add(dependency)
                    findings.extend(_dependency_findings(name, version, ecosystem, file))
            else:
                raise ValueError("unsupported manifest")
            completed += 1
        except (OSError, ValueError, TypeError, KeyError, AttributeError, ssl.SSLError):
            reasons.append("An input was unreadable, oversized, malformed, symlinked, or unsupported.")
    if railway:
        findings.append(_finding(
            target, "railway-rotation", "Railway incident recovery requested", "Railway usage asserted by operator",
            "Railway reported possible access to decrypted environment variables. This check cannot identify affected accounts or prove theft.",
            "Rotate all environment variables containing secrets and private registry credentials stored in Railway. Update dependent services, revoke old credentials, and review access logs; follow the provider disclosure.",
            RAILWAY_REFERENCE))
    findings.append(_finding(
        target, "scope", "Incident snapshot: limited assessment", SNAPSHOT,
        "Checks cover selected root manifests and an explicitly supplied PEM bundle. Installed artifacts, nested projects, OS/Node trust stores, revocation policies, and provider-side exposure are not verified.",
        "Review the incident documentation and assess deployed runtimes separately. No matching finding is not a clean bill of health.",
        "https://github.com/Amal-David/keyleak-detector", "medium"))
    report = build_report(str(target), findings, scan_mode="incident-check")
    report.extra["incident_snapshot"] = SNAPSHOT
    report.extra["coverage"] = build_coverage(
        "incident_inputs", len(files) or 1, completed, failed=len(files) - completed if files else 1,
        reasons=reasons,
    )
    report.retest_command = "See keyleak incident-check --help; repeat with the same explicit inputs."
    return report
