# Distribution readiness

This document describes the packaging contract and remaining release work.
It is not a claim of inclusion in Homebrew core, Debian, Fedora, or Kali, nor
an assertion of eligibility for a third-party program.

## Installation policy

`keyleak site-scan` and the Python `scan_site()` API no longer install discovery
tools by default. Installed `subfinder` and `amass` remain usable. The existing
crt.sh and DNS discovery paths remain available when tools are absent.
These are networked discovery methods, not an offline replacement for them.

An interactive operator can explicitly request the existing installer:

```sh
keyleak site-scan your-owned-domain.example --auto-install
```

The existing `--no-auto-install` option remains supported and is now the default.
Passing both options is an argument error. For Python callers,
`auto_install=True` is explicit consent, subject to the vetoes below.

The following environment settings disable installation even when explicitly
requested:

```sh
export KEYLEAK_NO_AUTO_INSTALL=1
# For a package-manager-provided wrapper or managed environment:
export KEYLEAK_MANAGED_INSTALL=1
```

Either setting is sufficient. Empty values and `0`, `false`, `no`, `off`
(case-insensitive, surrounding whitespace ignored) leave the veto inactive.
Other nonempty values veto installation, including misspellings. Neither
setting ever grants consent to install. This is a configuration policy, not a
sandbox against an operator modifying their environment. The managed setting
covers KeyLeak's optional discovery-tool installer; it is not a general ban on
all filesystem writes or on programs the operator runs separately.

Packagers should declare dependencies through their package manager and set
the managed-install veto in any wrapper they provide. Keep browser provision
explicit. This change does not silently install browser binaries or change
Playwright's browser compatibility contract.

## Migration note

Before this change, the CLI and `scan_site()` could try to install missing
`subfinder`. Callers relying on that behavior must install it themselves or
explicitly opt in. Setting `KEYLEAK_NO_AUTO_INSTALL=0` alone does not opt in.
Unknown nonempty opt-out values now fail closed instead of being ignored.

The project remains version 0.7.0 / beta in this development change. Do not
republish an existing version. A maintainer must select a new release version
and tag only after reviewing and validating the changes.

## Installed-artifact checks

The `Distribution` CI workflow builds a source distribution and wheel, validates
locked dependencies, and installs the wheel in a separate non-editable virtual
environment. It also rebuilds a wheel from the source distribution on Linux.
It runs `scripts/check_installed_distribution.py` from a temporary directory,
without a checkout on `PYTHONPATH`.

That smoke test checks the entry point and installed-package identity; clean
and synthetic-secret local scans; redaction in JSON and SARIF; and nonzero
failure on missing or oversized scan scope. It performs no live-target scans,
uses no real credentials, and requests KeyLeak's offline mode for scans.
The existing full Python and extension suites remain separate requirements.

To reproduce after building with Poetry, using Python 3.12 or newer:

```sh
poetry check --lock
poetry build
python3 -m venv /tmp/keyleak-wheel-check
/tmp/keyleak-wheel-check/bin/python -m pip install dist/*.whl
/tmp/keyleak-wheel-check/bin/python -m pip check
/tmp/keyleak-wheel-check/bin/python scripts/check_installed_distribution.py
```

The final command creates its own temporary working directory and runs child
interpreters in isolated mode; calling the script from a source checkout is
not sufficient to make a source install pass.

## Still required before a distribution submission

- Audit package-data coverage and the installed runtime/browser paths. Local
  scanning smoke tests do not establish working browser scanning, the web UI,
  the extension helper, or every Python command from a wheel.
- Separate lightweight scanning from Flask and Playwright only after import,
  CLI, wheel/sdist, browser, Docker, and GitHub Action compatibility is tested.
  Mandatory dependencies are intentionally unchanged in this first change.
- Validate browser provisioning and lifecycle without unexpected downloads;
  review the supported Python/platform matrix and reproducible source hashes.
- Prepare and run the actual distribution's package build, audit, and tests;
  submit for upstream review. A personal tap or a locally built package is not
  official archive acceptance. Repository inclusion and default-image
  installation are separate decisions.
- Publish accurate support and adoption evidence. Record public downstream
  integrations with consent and registry counts with their time window and
  source. Do not manufacture usage or claim an ecosyste.ms critical flag.

No distribution formula, archive submission, stable-release declaration,
program application, or download-count inflation is performed by this change.
