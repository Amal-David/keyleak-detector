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

The output contains three `aws_access_key` findings: `abc-ascii.bin` at byte offset `10`, and the UTF-16LE and UTF-16BE files at offset `20` each. Evidence includes `byte_offset`, `byte_length`, `redacted_value`, and `extraction.encoding`. The report contains three high findings, complete 3/3 coverage, and `BLOCK_SHIP`. The scanner reads bytes without executing the files.

Offsets are zero-based byte positions in the original binary. For archive scans, they refer to the uncompressed member bytes; the source identifies the member as `archive.zip!/path/in/archive`. A line number is not a substitute for this byte offset. `--scan-binaries` recognizes PE, ELF, Mach-O, and WASM headers, plus common suffixes including `.dll`, `.exe`, `.so`, `.dylib`, `.wasm`, `.bin`, `.elf`, and `.macho`.

Extraction checks ASCII-range strings in ASCII, UTF-16LE/BE, and UTF-32LE/BE. It also decodes contiguous Base64, hex, and fully percent-encoded strings through at most two transforms. For decoded findings, `byte_offset` and `byte_length` cover the outer encoded span. `extraction.transforms` records each transform's input range, and `extraction.decoded_offset` locates the match in the final decoded text. The encoded span is not necessarily an exact character-by-character mapping of the secret. Decoded values and surrounding binary strings are not stored in reports.

ELF32/64 headers and bounded section ranges provide class, byte order, machine ID, section index/range, and declared virtual address where available. File offsets remain distinct from virtual addresses. Malformed headers, extended section counts, and excessive section counts mark coverage incomplete. Other recognized formats receive string scanning without structural analysis. This is not decompilation: encrypted values, runtime construction, compressed executable sections, and unsupported application resources can still be missed.

## Read coverage and repeat the same scan

`coverage` counts attempted/completed checks, failures, and skips. `inventory` separately counts discovered files, selected files, nested containers, unsupported files, intentional exclusions, and excluded directories. Counts do not include unseen files inside excluded directories. Unsupported selected binary inputs and empty binary scope return incomplete coverage and exit `2`. DEX, binary Android resources, and generic XML/plist resources are not semantic mobile analysis; APK/IPA support covers selected container members only.

Text, Markdown, HTML, JSON, and SARIF preserve coverage. A complete zero-finding local result is labeled **No findings in selected checks**; the machine status remains `SAFE_TO_SHIP` for compatibility. The result is scoped to the declared extraction methods and limits.

Use the generated `retest_command` to repeat a scan. Local retests preserve effective includes, packs, launch profile, binary/build/dependency flags, and CLI failure/suppression policy. Archive retests use the original input and archive options. `scan_manifest` records scanner version, effective options, limits, and SHA-256 digests of the file bytes actually scanned. Repeating a command against changed inputs or a different scanner version is a new assessment.

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

The archive output is a version-2 integrity envelope. Its `report.findings` retain member paths and redacted evidence; `report.coverage` describes extraction and scan completeness. Nested supported archives are expanded through three levels below the root, with provenance such as `release.zip!/inner.zip!/app.bin`. Entry, expanded-byte, binary-byte, file and finding budgets are shared across nesting levels. Earlier findings survive a malformed child, duplicate member, or exhausted budget.

The scanner hashes and scans bounded temporary archive snapshots so the input digest describes the archive bytes analyzed. `input_artifact` identifies the root archive, while the manifest identifies scanned members and nested containers. Version 2 binds the entire report and envelope metadata, including coverage and retest configuration. Set `KEYLEAK_COC_KEY` to authenticate the envelope with HMAC; without it, the envelope is hash-only and cannot prove who produced it. `verify_envelope(..., require_signature=True)` rejects unsigned results. Shipped version-1 envelopes remain verifiable under their narrower, findings-only integrity contract. Neither format establishes external provenance or legal admissibility.

Work is bounded: at most 10 MiB per binary file, 1,000 files and 100 MiB of
binary input per scan, and 10,000 findings across binary artifacts per scan.
Each artifact also has a 50 MiB string-extraction-work limit, a 1 billion
detector-input-unit limit (printable characters multiplied by active detectors),
and a 100,000-run limit. Decoding permits 10,000 candidates and 10 MiB of
encoded candidate work per binary; ELF metadata permits 4,096 section headers.
Binary findings omit surrounding string snippets to
avoid exposing neighboring credentials. Archive extraction stops at 10,000
entries, 100 MiB per member, 500 MiB total expanded work, or a 200:1 expansion ratio.
Root archive snapshots are capped at 500 MiB. ZIP64
archives are not supported by this opt-in path. If a budget is reached, findings
already collected are retained, coverage becomes incomplete, and the CLI
returns exit `2`; do not treat that report as a complete clean scan.

A decode-depth limit stops that branch while scanning continues through later
strings. Failed archive snapshots charge only bytes actually copied, so an
oversized or unreadable member does not consume the budget available to siblings.

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
