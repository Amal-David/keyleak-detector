# Security policy

## Security maintainer

**Amal David ([@Amal-David](https://github.com/Amal-David))** is the security
maintainer of KeyLeak Detector. Responsibilities include private vulnerability
report triage, coordinated disclosure, review of security-sensitive changes and
dependencies, and approval of security fixes and releases.

See [MAINTAINERS.md](MAINTAINERS.md) for project ownership and
[the security model](docs/SECURITY_MODEL.md) for the scanner's trust boundaries,
credential handling, and known limitations. These documents describe project
responsibilities, not external accreditation or program eligibility.

## Report a vulnerability privately

Email **amal@utopianlabs.co** with the subject **KeyLeak security report**.
Do not put vulnerability details, live credentials, customer data, or a working
exploit against a third party in a public issue or pull request.

Include the affected release and component, operating system and Python/browser
versions, impact, and minimal reproduction steps using synthetic data or a
system you are authorized to test. Redact secrets and personal data. For highly
sensitive material, first ask the maintainer to agree on a transfer channel;
do not send it in an initial email attachment.

Maintenance is best-effort; the project does not promise a response deadline or
24-hour incident coverage. The maintainer will coordinate reproduction, fixes,
reporter credit (with consent), and publication with the reporter. Please allow
coordination before publishing details that could put users at risk.

If a live third-party credential is exposed, notify the credential owner through
their security channel and have the authorized owner revoke or rotate it. Do
not test, use, or retain the credential to demonstrate impact.

## Supported releases

Security fixes target the latest published Python release and the latest
published release of each extension distribution channel. Older releases have
no guaranteed backport support; upgrade when a fix becomes available. The
Chrome Web Store release and the unpacked extension release can differ: include
the exact version and installation channel in reports. Unreleased branches are
not a supported distribution channel.

A release remains beta until the maintainer explicitly designates otherwise.
A successful build or a distribution submission does not change that status.

## Security fixes and releases

The maintainer should record affected/fixed versions and safe upgrade guidance
in a GitHub release or security advisory, with coordinated detail and credit.
Reports involving disclosure of sensitive information should remain private
until that coordination is complete. Release approval includes review of
relevant regression tests and package installation checks, not merely source
checkout tests.

## Scope

Report weaknesses in KeyLeak itself, including unintended credential disclosure,
redaction failures, unsafe archive handling, unintended network access, native
host authorization, and supply-chain or installation behavior. Ordinary false
positives can go in a public issue only with synthetic or fully redacted data.
The project does not grant authorization to scan unrelated systems.
