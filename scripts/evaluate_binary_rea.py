#!/usr/bin/env python3
"""Evaluate KeyLeak strings and REA/Ghidra on synthetic, non-executed binaries."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from keyleak.local_scanner import scan_path
from keyleak.models import coverage_is_incomplete


CANARY = "AKIA1234567890" "ABCDEF"
PUBLIC_EXAMPLE = "AKIAIOSFODNN7" "EXAMPLE"
XOR_KEY = 0xAA


def _compile(compiler: str, source: Path, output: Path) -> None:
    result = subprocess.run(
        [compiler, "-O0", "-fno-inline", str(source), "-o", str(output)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Synthetic corpus compilation failed ({result.returncode}); details suppressed.")


def _make_corpus(root: Path, compiler: str) -> tuple[Path, Path, Path, Path]:
    source_dir = root / "source"
    artifact_dir = root / "artifacts"
    source_dir.mkdir(parents=True)
    artifact_dir.mkdir()
    marker = root / "plain-binary-executed"

    plain_source = source_dir / "plain.c"
    plain_source.write_text(
        "#include <stdio.h>\n"
        f"static volatile const char embedded[] = \"{CANARY}\";\n"
        "int main(void) {\n"
        f"  FILE *marker = fopen({json.dumps(str(marker))}, \"w\");\n"
        "  if (marker) { fputs(\"ran\", marker); fclose(marker); }\n"
        "  return embedded[0] == 0;\n"
        "}\n",
        encoding="utf-8",
    )
    public_source = source_dir / "public.c"
    public_source.write_text(
        "#include <stdio.h>\n"
        f"static volatile const char sample[] = \"{PUBLIC_EXAMPLE}\";\n"
        "int main(void) {\n"
        f"  FILE *marker = fopen({json.dumps(str(marker))}, \"w\");\n"
        "  if (marker) { fputs(\"ran\", marker); fclose(marker); }\n"
        "  return sample[0] == 0;\n"
        "}\n",
        encoding="utf-8",
    )

    encoded = [ord(char) ^ XOR_KEY for char in CANARY]
    xor_source = source_dir / "xor.c"
    xor_source.write_text(
        "#include <stdio.h>\n"
        "#include <stddef.h>\n"
        "static volatile const unsigned char encoded[] = {"
        + ",".join(f"0x{value:02x}" for value in encoded)
        + "};\n"
        "__attribute__((noinline)) int reveal_token(void) {\n"
        "  volatile unsigned char decoded[sizeof(encoded)];\n"
        "  for (size_t i = 0; i < sizeof(encoded); ++i) {\n"
        f"    decoded[i] = encoded[i] ^ 0x{XOR_KEY:02x};\n"
        "  }\n"
        "  return decoded[0];\n"
        "}\n"
        "int main(void) {\n"
        "  int result = reveal_token();\n"
        f"  FILE *marker = fopen({json.dumps(str(marker))}, \"w\");\n"
        "  if (marker) { fputs(\"ran\", marker); fclose(marker); }\n"
        "  return result == 0;\n"
        "}\n",
        encoding="utf-8",
    )

    plain_binary = artifact_dir / "plain.elf"
    public_binary = artifact_dir / "public.elf"
    xor_binary = artifact_dir / "xor.elf"
    _compile(compiler, plain_source, plain_binary)
    _compile(compiler, public_source, public_binary)
    _compile(compiler, xor_source, xor_binary)
    if CANARY.encode() in xor_binary.read_bytes():
        raise RuntimeError("XOR corpus binary unexpectedly contains the plaintext canary.")
    return artifact_dir, plain_binary, public_binary, xor_binary


def _findings(report: Any, source_name: str) -> list[Any]:
    return [
        finding
        for finding in report.findings
        if Path(finding.source).name == source_name
        and finding.detector_id == "leak.aws_access_key"
    ]


def _rea_json(rea: str, arguments: list[str]) -> Any:
    command = [rea, *arguments]
    if arguments[0] != "providers":
        command.extend(["--provider", "ghidra"])
    command.extend(["--format", "json", "--full-output"])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=os.environ.copy(),
    )
    try:
        stdout, _stderr = process.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        raise RuntimeError(f"REA {arguments[0]} timed out; output suppressed.") from None
    if process.returncode:
        raise RuntimeError(f"REA {arguments[0]} failed ({process.returncode}); output suppressed.")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"REA {arguments[0]} returned non-JSON output; output suppressed.") from None


def _search_values(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        items = value.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and isinstance(item.get("value"), str):
                    yield item
        for item in value.values():
            yield from _search_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _search_values(item)


def _procedure_address(value: Any, procedure_name: str) -> str | None:
    for item in _search_values(value):
        if procedure_name in item["value"] and isinstance(item.get("address"), str):
            return item["address"]
    return None


def _all_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _all_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_text(item)


def _pseudocode_text(value: Any) -> str:
    return max(_all_text(value), key=len, default="")


def _sanitized_excerpt(text: str) -> str:
    text = text.replace(CANARY, "<SYNTHETIC_CANARY>")
    text = text.replace(PUBLIC_EXAMPLE, "<PUBLIC_TEST_VALUE>")
    text = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", text)
    text = re.sub(r"\b\d+\b", "<N>", text)
    text = re.sub(r"/[^\s\"']+/(?:tmp|runner_temp)/[^\s\"']*", "<TEMP_PATH>", text)
    return text[:240]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rea", required=True, help="Path to the pinned local REA CLI")
    args = parser.parse_args()
    rea = str(Path(args.rea).resolve())
    if not Path(rea).is_file():
        raise RuntimeError("Pinned REA CLI is missing.")
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("A local C compiler is required for the synthetic corpus.")

    with tempfile.TemporaryDirectory(prefix="keyleak-rea-eval-") as temporary:
        root = Path(temporary)
        artifact_dir, plain_binary, public_binary, xor_binary = _make_corpus(root, compiler)
        report = scan_path(str(artifact_dir), profile="full", packs=["leak"], scan_binaries=True)
        plain_findings = _findings(report, plain_binary.name)
        public_findings = _findings(report, public_binary.name)
        xor_findings = _findings(report, xor_binary.name)
        if len(plain_findings) != 1 or public_findings or xor_findings:
            raise RuntimeError("KeyLeak deterministic baseline did not match the synthetic corpus expectations.")
        plain_offset = plain_findings[0].evidence.byte_offset
        if plain_binary.read_bytes()[plain_offset:plain_offset + len(CANARY)] != CANARY.encode():
            raise RuntimeError("KeyLeak plaintext byte offset did not match the raw binary bytes.")
        report_json = json.dumps(report.to_dict())
        if CANARY in report_json:
            raise RuntimeError("A raw synthetic canary appeared in the KeyLeak report.")
        if coverage_is_incomplete(report.extra.get("coverage")):
            raise RuntimeError("The synthetic KeyLeak corpus unexpectedly had incomplete coverage.")

        provider_status = _rea_json(rea, ["providers"])
        provider_data = provider_status.get("data", provider_status)
        if not isinstance(provider_data, dict):
            raise RuntimeError("REA returned an invalid provider-status envelope.")
        ghidra = next(
            (
                candidate
                for candidate in provider_data.get("analysis_provider_candidates", [])
                if candidate.get("provider", {}).get("id") == "ghidra"
            ),
            None,
        )
        if not ghidra or ghidra.get("availability", {}).get("status") != "available":
            raise RuntimeError("REA's pinned Ghidra provider is unavailable on the CI runner.")

        _rea_json(rea, ["analyze", str(plain_binary)])
        plain_search = _rea_json(rea, ["search", str(plain_binary), CANARY, "--kind", "strings"])
        public_search = _rea_json(rea, ["search", str(public_binary), PUBLIC_EXAMPLE, "--kind", "strings"])
        xor_search = _rea_json(rea, ["search", str(xor_binary), CANARY, "--kind", "strings"])
        plain_hits = [item for item in _search_values(plain_search) if CANARY in item["value"]]
        public_hits = [item for item in _search_values(public_search) if PUBLIC_EXAMPLE in item["value"]]
        xor_hits = [item for item in _search_values(xor_search) if CANARY in item["value"]]
        if not plain_hits or not public_hits:
            raise RuntimeError("REA/Ghidra did not recover the synthetic plaintext string corpus.")
        if xor_hits:
            raise RuntimeError("REA's strings inventory unexpectedly contained the runtime-constructed canary.")

        procedure_search = _rea_json(
            rea,
            ["search", str(xor_binary), "reveal_token", "--kind", "procedures"],
        )
        address = _procedure_address(procedure_search, "reveal_token")
        if not address:
            raise RuntimeError("REA/Ghidra did not resolve the synthetic XOR function.")
        decompile = _rea_json(rea, ["decompile", str(xor_binary), address])
        decompile_text = _pseudocode_text(decompile)
        if not decompile_text:
            raise RuntimeError("REA/Ghidra returned no pseudocode for the synthetic XOR function.")
        xor_visible = bool(re.search(r"\^|\bxor\b", decompile_text, re.IGNORECASE))
        excerpt = _sanitized_excerpt(decompile)
        if CANARY in excerpt or PUBLIC_EXAMPLE in excerpt:
            raise RuntimeError("The sanitized REA excerpt contains a raw synthetic test value.")
        if (root / "plain-binary-executed").exists():
            raise RuntimeError("A target binary was executed during the static REA evaluation.")

        print(json.dumps({
            "corpus": {
                "files": 3,
                "keyleak_plaintext_positive": len(plain_findings) == 1,
                "keyleak_public_example_negative": not public_findings,
                "keyleak_xor_runtime_negative": not xor_findings,
                "keyleak_plaintext_byte_offset": plain_offset,
                "keyleak_report_raw_canary": False,
                "keyleak_coverage": report.extra["coverage"]["status"],
            },
            "rea_ghidra": {
                "version": "3.1.0",
                "provider_available": True,
                "plaintext_string_search_hits": len(plain_hits),
                "public_example_string_search_hits": len(public_hits),
                "xor_plaintext_string_search_hits": len(xor_hits),
                "xor_decompile_available": True,
                "xor_operation_visible": xor_visible,
                "sanitized_xor_excerpt": excerpt,
                "target_executed": False,
                "model_provider_called": False,
            },
            "integration_gate": {
                "decision": "NO_GO",
                "reason": "REA/Ghidra exposes local analysis evidence, but it does not classify secrets; a model-assisted interpretation and its configured data boundary are not validated by this local run.",
                "provider_data_boundary_validated": False,
            },
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
