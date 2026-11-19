# Python secret serialization review

Opt into static source checks for credentials on Python dataclasses, attrs classes,
Pydantic models, and class-style NamedTuple definitions:

```bash
keyleak local . --include serialization --packs leak --json
```

Inspired by [Sentry's secret serialization review guidance](https://github.com/getsentry/skills/tree/main/skills/secret-serialization).
The check does not import or execute scanned code. It reports unprotected generated
holders as medium review leads, and direct same-file exposing serializer uses as
high leads. `repr=False` does not protect `asdict`; Pydantic dump exclusion does not
protect repr. Raw `vars`, `__dict__`, and pickle paths bypass field flags and wrappers.
Evidence includes field names and line numbers without copying source values.
Optional Pydantic secret wrappers retain their masking. The exact metadata fields
`token_ttl: int`, `password_min_length: int`, and `cookie_secure: bool` are excluded;
numeric `token` and `password` fields remain in scope. Structural fingerprints support
allowlists when `KEYLEAK_FINDING_FINGERPRINT_KEY` is configured.

This is a bounded Python source review, not proof of runtime disclosure. It resolves
module-level holders, import aliases, direct constructor assignments, and typed
function parameters. It checks explicit repr/dump/raw serializers, object formatting,
and logging arguments. Partial exclusions require a traced unblocked path. Custom
serializers, inherited/imported holders, custom redaction, conditional exclusions,
comprehensions, cross-file/interprocedural flows, and JavaScript/TypeScript need
manual review. Known test, fixture, example, dependency, build, and generated protobuf
paths relative to the scan root are excluded. Existing file limits apply, plus 100,000 AST nodes and 1,000
findings per Python file. Parsing/analysis limits or no eligible Python sources make
coverage incomplete; findings collected before a limit are retained. This check is opt-in and has no browser or extension
bundle counterpart.
