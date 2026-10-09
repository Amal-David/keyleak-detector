# Scan a local release’s binaries

Use `--scan-binaries` when you want KeyLeak to look for printable secrets in a release artifact as well as ordinary source and configuration files. This walkthrough creates a fictional `ABCapp` release using a synthetic detector test string assembled from pieces at run time. It is not a working credential, nothing is sent to a provider, and the sample files are never executed.

The flag and output shape shown here describe the PR source checkout; an installed release may not include them yet. For local dependency/build, browser, site, and extension workflows, see the [scanner workflows guide](SCANNER_WORKFLOWS.md).

## Create a small local test release

From the source checkout, install dependencies once if needed:

```bash
poetry install
```

Create one ASCII and two UTF-16 test files under a disposable release directory:

```bash
DEMO_ROOT="$(mktemp -d)"
export DEMO_ROOT
python3 - <<'PY'
import os
from pathlib import Path

artifacts = Path(os.environ["DEMO_ROOT"]) / "abc-release" / "artifacts"
artifacts.mkdir(parents=True)
fake_key = "AKIA" + "1234567890" + "ABCDEF"
prefix = "ABC demo: "
for filename, encoding in (
    ("abc-ascii.bin", "ascii"),
    ("abc-utf16le.bin", "utf-16le"),
    ("abc-utf16be.bin", "utf-16be"),
):
    (artifacts / filename).write_bytes(
        prefix.encode(encoding) + fake_key.encode(encoding)
    )
PY
```

Scan the directory locally. `launch-gate` includes the leak detectors used by this example:

```bash
poetry run keyleak local "$DEMO_ROOT/abc-release" \
  --scan-binaries --launch-profile launch-gate --json --fail-on high \
  > "$DEMO_ROOT/report.json"
scan_exit=$?
```

This synthetic example returns exit `2` because it deliberately contains three matches at the selected `high` threshold. Inspect the redacted locations, not a raw value:

```bash
python3 - "$DEMO_ROOT/report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.load(open(sys.argv[1], encoding="utf-8"))
for finding in report["findings"]:
    evidence = finding["evidence"]
    print(
        finding["type"],
        Path(finding["source"]).name,
        "byte_offset=" + str(evidence["byte_offset"]),
        evidence["redacted_value"],
    )
print("summary:", report["summary"])
print("coverage:", report["coverage"])
PY
```

The verified output was three `aws_access_key` findings: `abc-ascii.bin` at byte offset `10`, and the UTF-16LE and UTF-16BE files at offset `20` each. In every case the evaluator checked that the reported offset points to the start of the encoded match in the original file. JSON evidence includes `byte_offset` and `redacted_value`; it does not include a detected-encoding field. The report showed three high findings, complete 3/3 coverage, and `BLOCK_SHIP`. The scanner read bytes and did not execute any file.

Offsets are zero-based byte positions in the original binary. For archive scans, they refer to the uncompressed member bytes; the source identifies the member as `archive.zip!/path/in/archive`. A line number is not a substitute for this byte offset. `--scan-binaries` recognizes PE, ELF, Mach-O, and WASM headers, plus common suffixes including `.dll`, `.exe`, `.so`, `.dylib`, `.wasm`, `.bin`, `.elf`, and `.macho`. Extraction checks printable ASCII, UTF-16LE, and UTF-16BE strings; runtime-built, encrypted, or non-printable values can be missed.

## Scan a ZIP/APK/IPA or tar release

Use the separate `archive` command for a `.zip`, `.tar.gz`/tar variant, or directory. APK and IPA packages are ZIP containers; the scanner inspects recognized binary members when you opt in:

```bash
python3 - "$DEMO_ROOT/abc-release" "$DEMO_ROOT/abc-release.zip" <<'PY'
from pathlib import Path
from zipfile import ZipFile
import sys

root, output = Path(sys.argv[1]), Path(sys.argv[2])
with ZipFile(output, "w") as archive:
    for path in sorted((root / "artifacts").iterdir()):
        archive.write(path, f"abc-release/artifacts/{path.name}")
PY

poetry run keyleak archive "$DEMO_ROOT/abc-release.zip" \
  --scan-binaries --launch-profile ci --out "$DEMO_ROOT/archive-report.json" \
  --fail-on high
scan_exit=$?
```

The archive output is a chain-of-custody envelope. Its `report.findings` retain member paths and redacted evidence; `report.coverage` describes extraction and scan completeness. The synthetic ZIP example returned three findings and exit `2`; its coverage was complete, and the envelope contained no raw test string.

Work is bounded: at most 10 MiB per binary file, 1,000 files and 100 MiB of binary input per scan, with a separate printable-string work limit. Archive extraction stops at 10,000 entries, 100 MiB per member, 500 MiB total, or a 200:1 expansion ratio. ZIP64 archives are not supported by this opt-in path. If a budget is reached, findings already collected are retained, coverage becomes incomplete, and the CLI returns exit `2`; do not treat that report as a complete clean scan.

## Fix and verify

For this toy example, replace the synthetic string with benign test text, then rerun the same command:

```bash
python3 - "$DEMO_ROOT/abc-release/artifacts" <<'PY'
from pathlib import Path
import sys

encodings = {
    "abc-ascii.bin": "ascii",
    "abc-utf16le.bin": "utf-16le",
    "abc-utf16be.bin": "utf-16be",
}
for path in Path(sys.argv[1]).iterdir():
    path.write_bytes("ABC demo: clean build".encode(encodings[path.name]))
PY

poetry run keyleak local "$DEMO_ROOT/abc-release" \
  --scan-binaries --launch-profile launch-gate --json --fail-on high \
  > "$DEMO_ROOT/report-clean.json"
```

The clean synthetic directory returned zero findings, complete 3/3 coverage, `SAFE_TO_SHIP`, and exit `0`. This only verifies the toy directory. For a real client-side credential, rotate/revoke the exposed credential with its provider, remove it from the built artifact, rebuild, and scan the actual release. Moving it into `VITE_`/`NEXT_PUBLIC_` configuration still embeds it in client code; privileged requests belong on a backend.

REA/Ghidra was evaluated separately on synthetic binaries. It found plaintext strings in both the canary and public example, missed the XOR-built string in its string search, and exposed an XOR operation in decompiled code for a human to inspect. That is analysis evidence, not automatic secret classification. No model provider was called, so provider data handling remains unvalidated and production model integration is **NO-GO**. See the [measured evaluation](REA_BINARY_EVALUATION.md).
