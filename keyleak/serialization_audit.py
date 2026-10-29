"""Static Python credential-holder checks; no source is imported or executed."""

from __future__ import annotations

import ast
import re

from .models import Evidence, Finding


MAX_AST_NODES = 100_000
MAX_FINDINGS = 1000

REFERENCE = "https://github.com/getsentry/skills/tree/main/skills/secret-serialization"
_CREDENTIAL = re.compile(
    r"(?:^|_)(?:secret|token|password|passwd|pwd|api_?key|access_key|private_key|"
    r"signing_key|bearer|credentials?|authorization|auth_header|cookie|session_key|"
    r"dsn|connection_string|hmac)(?:_|$)"
)
_HOLDERS = {
    "dataclasses.dataclass": "dataclass",
    "attrs.define": "attrs", "attrs.frozen": "attrs", "attrs.mutable": "attrs",
    "attr.s": "attrs", "attr.attrs": "attrs",
    "pydantic.BaseModel": "pydantic", "pydantic.BaseSettings": "pydantic",
    "pydantic_settings.BaseSettings": "pydantic",
    "typing.NamedTuple": "namedtuple",
}
_FIELDS = {"dataclasses.field", "attrs.field", "attr.ib", "attr.attrib", "pydantic.Field"}
_DUMPS = {"dataclasses.asdict", "dataclasses.astuple", "attrs.asdict", "attrs.astuple", "attr.asdict", "attr.astuple"}


class SerializationAuditLimitError(ValueError):
    """Retain findings produced before the bounded source review stopped."""

    def __init__(self, findings):
        super().__init__("Python serialization analysis limit reached")
        self.findings = findings


def audit_python_serialization(content: str | bytes, source: str) -> list[Finding]:
    """Find generated holder paths and direct, same-file serializer uses.

    Syntax/complexity failures propagate so callers can mark coverage incomplete.
    Bindings are scope-local and invalidated on reassignment; this is not a
    cross-file or interprocedural dataflow analysis.
    """
    tree = ast.parse(content)
    for count, _ in enumerate(ast.walk(tree)):
        if count >= MAX_AST_NODES:
            raise ValueError("Python serialization AST exceeds review limit")
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    def flag(call, key, value):
        return isinstance(call, ast.Call) and any(
            item.arg == key and isinstance(item.value, ast.Constant) and item.value.value is value
            for item in call.keywords
        )

    holders = {}
    findings = []
    # Only module-level classes are resolved; nested and imported holders need review.
    for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
        decorators = [(item.func if isinstance(item, ast.Call) else item, item) for item in cls.decorator_list]
        kind = next((_HOLDERS[name(item)] for item, _ in decorators if name(item) in _HOLDERS), None)
        if kind is None:
            kind = next((_HOLDERS[name(base)] for base in cls.bases if name(base) in _HOLDERS), None)
        if kind is None:
            continue
        methods = {item.name for item in cls.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        repr_disabled = "__repr__" in methods or any(flag(item, "repr", False) for decorator, item in decorators if name(decorator) in _HOLDERS)
        legacy_attrs = any(
            name(decorator) in {"attr.s", "attr.attrs"} and not flag(item, "auto_attribs", True)
            for decorator, item in decorators
        )
        fields = []
        for field in cls.body:
            if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name):
                field_name, annotation, value = field.target.id, field.annotation, field.value
            elif kind == "attrs" and isinstance(field, ast.Assign) and len(field.targets) == 1 and isinstance(field.targets[0], ast.Name):
                field_name, annotation, value = field.targets[0].id, None, field.value
                if not isinstance(value, ast.Call) or name(value.func) not in _FIELDS:
                    continue
            else:
                continue
            if legacy_attrs and (not isinstance(value, ast.Call) or name(value.func) not in _FIELDS):
                continue
            annotation_name = name(annotation.value if isinstance(annotation, ast.Subscript) else annotation)
            if annotation_name in {"typing.ClassVar", "dataclasses.InitVar"}:
                continue
            if kind == "pydantic" and field_name.startswith("_"):
                continue
            normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", field_name).lower()
            wrapped = name(annotation) in {"pydantic.SecretStr", "pydantic.SecretBytes"}
            if not _CREDENTIAL.search(normalized) and not wrapped:
                continue
            paths = {"repr", "dump"}
            field_call = value if isinstance(value, ast.Call) and name(value.func) in _FIELDS else None
            if repr_disabled or flag(field_call, "repr", False):
                paths.discard("repr")
            if kind == "pydantic" and flag(field_call, "exclude", True):
                paths.discard("dump")
            if wrapped and kind == "pydantic":
                paths.clear()
            fields.append((field_name, field.lineno, paths))
        if fields:
            holders[cls.name] = (kind, fields, methods)

    if not holders:
        return []

    def emit(cls_name, field, path, line, sink=""):
        field_name, field_line, _ = field
        if len(findings) >= MAX_FINDINGS:
            raise SerializationAuditLimitError(findings)
        detail = f"{cls_name}.{field_name}: {path}"
        if sink:
            detail += f" at line {line} ({sink}); holder at line {field_line}"
        findings.append(Finding(
            type="secret_serialization",
            severity="high" if sink else "medium",
            confidence=0.85 if sink else 0.65,
            detector_id="leak.secret_serialization",
            source=source,
            evidence=Evidence(source=source, snippet=detail, line=line, redacted_value=f"{cls_name}.{field_name}"),
            risk_reason=(
                f"A direct same-file {sink} use can expose the credential-bearing field through {path}. "
                if sink else
                f"A credential-bearing field has generated {path} output with no exclusion. "
            ) + "Static review lead; runtime values, control flow, and external disclosure are not verified.",
            remediation=(
                "Replace raw attribute serialization with an explicit allowlist of safe scalar fields; "
                "repr/exclude flags and secret wrappers do not protect raw attribute access."
                if path == "raw attributes" else
                "Block the exposing path: use repr=False for representation, exclude=True for Pydantic dumps, "
                "or an explicit safe dict for dataclass/attrs dumps. Test the actual serializer with a throwaway secret."
            ),
            validation_status="lead", category="leak", references=[REFERENCE],
        ))

    traced = set()

    class SerializerVisitor(ast.NodeVisitor):
        def __init__(self):
            self.bindings = {}
            self.shadowed = set()

        def resolve(self, node):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in self.shadowed:
                return ""
            return name(node)

        def object_class(self, node):
            if isinstance(node, ast.Name):
                return self.bindings.get(node.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in holders and node.func.id not in self.shadowed:
                return node.func.id
            return None

        def check(self, value, path, node, sink, kinds=None):
            cls_name = self.object_class(value)
            if cls_name is None or (kinds and holders[cls_name][0] not in kinds):
                return
            if path == "repr" and sink != "repr" and holders[cls_name][2].intersection({"__str__", "__format__"}):
                return
            for field in holders[cls_name][1]:
                if path == "raw attributes" or path in field[2]:
                    key = (cls_name, field[0], path, node.lineno)
                    if key not in traced:
                        traced.add(key)
                        emit(cls_name, field, path, node.lineno, sink)

        def visit_ClassDef(self, node):
            # Holder methods are not treated as independent serialization sinks.
            return

        def visit_FunctionDef(self, node):
            outer, outer_shadowed = self.bindings, self.shadowed
            self.bindings = {}
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg:
                args.append(node.args.vararg)
            if node.args.kwarg:
                args.append(node.args.kwarg)
            self.shadowed = outer_shadowed | {arg.arg for arg in args}
            for arg in args:
                if isinstance(arg.annotation, ast.Name) and arg.annotation.id in holders:
                    self.bindings[arg.arg] = arg.annotation.id
            for stmt in node.body:
                self.visit(stmt)
            self.bindings, self.shadowed = outer, outer_shadowed

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Assign(self, node):
            self.visit(node.value)
            cls_name = self.object_class(node.value)
            for target in node.targets:
                for item in ast.walk(target):
                    if isinstance(item, ast.Name):
                        self.bindings.pop(item.id, None)
                        self.shadowed.add(item.id)
                if isinstance(target, ast.Name) and cls_name:
                    self.bindings[target.id] = cls_name

        def visit_AnnAssign(self, node):
            if node.value:
                self.visit(node.value)
            if isinstance(node.target, ast.Name):
                cls_name = self.object_class(node.value)
                self.bindings.pop(node.target.id, None)
                self.shadowed.add(node.target.id)
                if cls_name:
                    self.bindings[node.target.id] = cls_name

        def visit_If(self, node):
            self.visit(node.test)
            outer, outer_shadowed = self.bindings.copy(), self.shadowed.copy()
            for stmt in node.body:
                self.visit(stmt)
            body, body_shadowed = self.bindings, self.shadowed
            self.bindings, self.shadowed = outer.copy(), outer_shadowed.copy()
            for stmt in node.orelse:
                self.visit(stmt)
            self.bindings = {key: value for key, value in self.bindings.items() if body.get(key) == value}
            self.shadowed |= body_shadowed

        def visit_For(self, node):
            self.visit(node.iter)
            for item in ast.walk(node.target):
                if isinstance(item, ast.Name):
                    self.bindings.pop(item.id, None)
                    self.shadowed.add(item.id)
            outer = self.bindings.copy()
            for stmt in node.body:
                self.visit(stmt)
            self.bindings = {key: value for key, value in self.bindings.items() if outer.get(key) == value}
            for stmt in node.orelse:
                self.visit(stmt)

        visit_AsyncFor = visit_For

        def visit_Lambda(self, node):
            return

        def visit_ListComp(self, node):
            return

        visit_SetComp = visit_ListComp
        visit_DictComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

        def visit_Call(self, node):
            func = self.resolve(node.func)
            if node.args:
                if func in _DUMPS and len(node.args) == 1 and not node.keywords:
                    kinds = {"dataclass"} if func.startswith("dataclasses.") else {"attrs"}
                    self.check(node.args[0], "dump", node, func, kinds)
                elif func in {"str", "repr", "format"}:
                    self.check(node.args[0], "repr", node, func)
                elif func in {"vars", "pickle.dumps", "pickle.dump"}:
                    self.check(node.args[0], "raw attributes", node, func)
                elif func == "json.dumps" and any(item.arg == "default" and self.resolve(item.value) == "vars" for item in node.keywords):
                    self.check(node.args[0], "raw attributes", node, "json.dumps(default=vars)")
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"model_dump", "model_dump_json", "dict", "json"}:
                    # Per-call includes/excludes can change which fields leave the model.
                    cls_name = self.object_class(node.func.value)
                    if cls_name and node.func.attr not in holders[cls_name][2] and not node.args and not node.keywords:
                        self.check(node.func.value, "dump", node, node.func.attr, {"pydantic"})
                elif node.func.attr == "_asdict" and not node.args and not node.keywords:
                    self.check(node.func.value, "dump", node, "_asdict", {"namedtuple"})
                elif node.func.attr in {"debug", "info", "warning", "error", "exception", "critical"}:
                    for arg in node.args:
                        self.check(arg, "repr", node, "logging object argument")
            self.generic_visit(node)

        def visit_Attribute(self, node):
            if node.attr == "__dict__" and isinstance(node.ctx, ast.Load):
                self.check(node.value, "raw attributes", node, "__dict__")
            self.generic_visit(node)

        def visit_FormattedValue(self, node):
            self.check(node.value, "repr", node, "formatted object")
            self.generic_visit(node)

    try:
        SerializerVisitor().visit(tree)
    except RecursionError as exc:
        raise SerializationAuditLimitError(findings) from exc
    exposed = {(cls_name, field_name) for cls_name, field_name, _, _ in traced}
    for cls_name, (_, fields, _) in holders.items():
        for field in fields:
            # Partial protection needs a traced use of the remaining path.
            if field[2] == {"repr", "dump"} and (cls_name, field[0]) not in exposed:
                emit(cls_name, field, "repr and dump", field[1])
    return findings
