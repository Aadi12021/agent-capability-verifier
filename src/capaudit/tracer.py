"""AST-based capability tracer.

Given Python source, finds `CapabilitySchema(...)` declarations and the
loader functions bound to them via `@SCHEMA.bind`, then statically traces
which config fields flow into which `SinkCategory`.

This module never imports or executes the source it analyzes — it only
parses it with `ast` and walks the resulting tree. That's a deliberate
constraint, not just an implementation detail: a linter over untrusted
loader code must not itself become a code-execution vector by running that
code.

Scope (see docs/capability-schema.md and the README's scope section): this
is an intraprocedural, pattern-based tracer. It follows straight-line
variable assignment chains and direct `config[...]` / `config.get(...)`
accesses; it does not resolve aliasing through attributes, indirect calls,
or control flow, and it does not do interprocedural analysis across
function or module boundaries.

It also detects when a single sink call's argument is built from *more than
one* distinct config field — via string concatenation (`+`), an f-string, or
`os.path.join(...)`, including through one level of variable assignment of
the combined result. These are reported separately as `JointSinkHit`s rather
than `SinkHit`s, since they can't be attributed to any one field.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from capaudit.schema import Capability, CapabilitySchema, SinkCategory

# Dotted call names that are always sinks, mapped to the sink category they
# represent. "open" is special-cased separately because its category depends
# on the mode argument.
_SIMPLE_SINK_TABLE: dict[str, SinkCategory] = {
    "open": SinkCategory.FILE_READ,  # refined by _open_sink_category
    "eval": SinkCategory.CODE_EXEC,
    "exec": SinkCategory.CODE_EXEC,
    "compile": SinkCategory.CODE_EXEC,
    "os.system": SinkCategory.SUBPROCESS,
    "os.popen": SinkCategory.SUBPROCESS,
    "subprocess.run": SinkCategory.SUBPROCESS,
    "subprocess.call": SinkCategory.SUBPROCESS,
    "subprocess.check_call": SinkCategory.SUBPROCESS,
    "subprocess.check_output": SinkCategory.SUBPROCESS,
    "subprocess.Popen": SinkCategory.SUBPROCESS,
    "urllib.request.urlopen": SinkCategory.NETWORK,
    "requests.get": SinkCategory.NETWORK,
    "requests.post": SinkCategory.NETWORK,
    "requests.put": SinkCategory.NETWORK,
    "socket.create_connection": SinkCategory.NETWORK,
}

_WRITE_MODE_CHARS = set("wax+")


@dataclass(frozen=True)
class SinkHit:
    """One place a config field's value was found reaching a sink."""

    field: str
    sink: SinkCategory
    call_description: str
    lineno: int


@dataclass(frozen=True)
class JointSinkHit:
    """One place where a sink call's argument was constructed from more than
    one distinct config field (e.g. via `os.path.join`, string
    concatenation, or an f-string), rather than a single field flowing
    straight through. `fields` names every distinct field found feeding that
    argument."""

    fields: frozenset[str]
    sink: SinkCategory
    call_description: str
    lineno: int


@dataclass(frozen=True)
class LoaderTrace:
    """The trace result for one `@SCHEMA.bind`-decorated loader function."""

    function_name: str
    schema: CapabilitySchema
    sink_hits: tuple[SinkHit, ...] = dataclass_field(default_factory=tuple)
    joint_sink_hits: tuple[JointSinkHit, ...] = dataclass_field(default_factory=tuple)
    undeclared_fields_used: tuple[str, ...] = dataclass_field(default_factory=tuple)


def _dotted_name(node: ast.AST) -> str | None:
    """Resolve a Name/Attribute chain to a dotted string, e.g. "subprocess.run".
    Returns None for anything else (calls, subscripts, etc.)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _direct_field_access(expr: ast.AST, config_param: str) -> str | None:
    """Match `config["field"]` or `config.get("field", ...)` where `config`
    is the loader's config parameter. Does not consult the alias map."""
    if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name) \
            and expr.value.id == config_param:
        return _string_constant(expr.slice)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
            and expr.func.attr == "get" and isinstance(expr.func.value, ast.Name) \
            and expr.func.value.id == config_param and expr.args:
        return _string_constant(expr.args[0])
    return None


def _resolve_field(expr: ast.AST, config_param: str, alias_map: dict[str, str]) -> str | None:
    """Resolve an expression to a config field name, either via a direct
    config access or via a variable already known to alias one."""
    direct = _direct_field_access(expr, config_param)
    if direct is not None:
        return direct
    if isinstance(expr, ast.Name) and expr.id in alias_map:
        return alias_map[expr.id]
    return None


def _build_alias_map(func: ast.FunctionDef, config_param: str) -> dict[str, str]:
    """Fixed-point pass over simple `NAME = <config access or aliased name>`
    assignments in the function body, so chains like `x = config["f"]; y = x`
    both resolve to field "f"."""
    alias_map: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                field = _resolve_field(node.value, config_param, alias_map)
                target = node.targets[0].id
                if field is not None and alias_map.get(target) != field:
                    alias_map[target] = field
                    changed = True
    return alias_map


def _resolve_fields(
    expr: ast.AST,
    config_param: str,
    alias_map: dict[str, str],
    multi_alias_map: dict[str, frozenset[str]],
) -> frozenset[str]:
    """Collect every distinct config field that feeds into `expr`. A plain
    single-field expression (already handled by `_resolve_field`) returns a
    one-element set; string concatenation (`+`), an f-string, and
    `os.path.join(...)` are unpacked recursively so a compound expression
    reports every field it draws on. A name already known (via
    `multi_alias_map`) to alias such a compound expression resolves the same
    way. Anything else this tracer doesn't recognize contributes nothing."""
    single = _resolve_field(expr, config_param, alias_map)
    if single is not None:
        return frozenset({single})

    if isinstance(expr, ast.Name) and expr.id in multi_alias_map:
        return multi_alias_map[expr.id]

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _resolve_fields(expr.left, config_param, alias_map, multi_alias_map) | \
            _resolve_fields(expr.right, config_param, alias_map, multi_alias_map)

    if isinstance(expr, ast.JoinedStr):  # f-string
        fields: set[str] = set()
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                fields |= _resolve_fields(value.value, config_param, alias_map, multi_alias_map)
        return frozenset(fields)

    if isinstance(expr, ast.Call) and _dotted_name(expr.func) == "os.path.join":
        fields = set()
        for arg in expr.args:
            fields |= _resolve_fields(arg, config_param, alias_map, multi_alias_map)
        return frozenset(fields)

    return frozenset()


def _build_multi_alias_map(
    func: ast.FunctionDef, config_param: str, alias_map: dict[str, str]
) -> dict[str, frozenset[str]]:
    """Fixed-point pass tracking `NAME = <compound expression>` assignments,
    so a variable built once from a multi-field expression (e.g.
    `p = os.path.join(a, b)`) is still recognized as drawing on both fields
    when it's later passed to a sink. Names already captured by `alias_map`
    (a plain single-field alias) are left to it, so the two maps don't
    disagree about the same name."""
    multi_map: dict[str, frozenset[str]] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
                if target in alias_map:
                    continue
                fields = _resolve_fields(node.value, config_param, alias_map, multi_map)
                if fields and multi_map.get(target) != fields:
                    multi_map[target] = fields
                    changed = True
    return multi_map


def _all_config_field_accesses(func: ast.FunctionDef, config_param: str) -> set[str]:
    fields: set[str] = set()
    for node in ast.walk(func):
        direct = _direct_field_access(node, config_param) if isinstance(
            node, (ast.Subscript, ast.Call)
        ) else None
        if direct is not None:
            fields.add(direct)
    return fields


def _open_sink_category(call: ast.Call) -> SinkCategory:
    mode: str | None = None
    if len(call.args) >= 2:
        mode = _string_constant(call.args[1])
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = _string_constant(kw.value)
    if mode and any(c in mode for c in _WRITE_MODE_CHARS):
        return SinkCategory.FILE_WRITE
    return SinkCategory.FILE_READ


def _candidate_sink_args(call: ast.Call) -> list[ast.expr]:
    """Positional args, expanding any list literal so e.g.
    `subprocess.run([cmd, tainted_var])` checks each element."""
    exprs: list[ast.expr] = []
    for arg in call.args:
        if isinstance(arg, ast.List):
            exprs.extend(arg.elts)
        else:
            exprs.append(arg)
    return exprs


def _match_sink_hits(
    call: ast.Call,
    config_param: str,
    alias_map: dict[str, str],
    multi_alias_map: dict[str, frozenset[str]],
) -> tuple[list[tuple[str, SinkCategory, str]], list[tuple[frozenset[str], SinkCategory, str]]]:
    hits: list[tuple[str, SinkCategory, str]] = []
    joint_hits: list[tuple[frozenset[str], SinkCategory, str]] = []
    func = call.func
    name = _dotted_name(func)

    def record(expr: ast.expr, category: SinkCategory, desc: str) -> None:
        fields = _resolve_fields(expr, config_param, alias_map, multi_alias_map)
        if len(fields) == 1:
            hits.append((next(iter(fields)), category, desc))
        elif len(fields) >= 2:
            joint_hits.append((fields, category, desc))

    if name in _SIMPLE_SINK_TABLE:
        if name == "open":
            category = _open_sink_category(call)
            candidates = call.args[:1]
        else:
            category = _SIMPLE_SINK_TABLE[name]
            candidates = _candidate_sink_args(call)
        for expr in candidates:
            record(expr, category, f"{name}(...)")
        return hits, joint_hits

    if name == "Template" and call.args:
        record(call.args[0], SinkCategory.TEMPLATE_RENDER, "Template(...)")
        return hits, joint_hits

    if isinstance(func, ast.Attribute) \
            and func.attr in {"read_text", "write_text", "read_bytes", "write_bytes"} \
            and isinstance(func.value, ast.Call) \
            and _dotted_name(func.value.func) == "Path" \
            and func.value.args:
        category = (
            SinkCategory.FILE_WRITE if func.attr.startswith("write") else SinkCategory.FILE_READ
        )
        record(func.value.args[0], category, f"Path(...).{func.attr}()")
        return hits, joint_hits

    return hits, joint_hits


def _find_schema_vars(tree: ast.Module) -> dict[str, CapabilitySchema]:
    schema_vars: dict[str, CapabilitySchema] = {}
    for node in ast.iter_child_nodes(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            continue
        call = node.value
        if not isinstance(call, ast.Call):
            continue
        callee = _dotted_name(call.func)
        if callee is None or callee.split(".")[-1] != "CapabilitySchema":
            continue
        if not call.args or not isinstance(call.args[0], ast.Dict):
            continue
        fields: dict[str, Capability] = {}
        ok = True
        for key_node, val_node in zip(call.args[0].keys, call.args[0].values):
            key = _string_constant(key_node) if key_node is not None else None
            if key is None:
                ok = False
                break
            if not (isinstance(val_node, ast.Attribute)
                    and isinstance(val_node.value, ast.Name)
                    and val_node.value.id == "Capability"):
                ok = False
                break
            try:
                fields[key] = Capability[val_node.attr]
            except KeyError:
                ok = False
                break
        if ok:
            schema_vars[node.targets[0].id] = CapabilitySchema(fields)
    return schema_vars


def _find_bound_loaders(
    tree: ast.Module, schema_vars: dict[str, CapabilitySchema]
) -> list[tuple[ast.FunctionDef, CapabilitySchema]]:
    loaders: list[tuple[ast.FunctionDef, CapabilitySchema]] = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Attribute) and dec.attr == "bind" \
                    and isinstance(dec.value, ast.Name) and dec.value.id in schema_vars:
                loaders.append((node, schema_vars[dec.value.id]))
                break
    return loaders


class CapabilityTracer:
    """Parses Python source and traces config field flows for every
    `@SCHEMA.bind`-decorated loader function it finds."""

    def trace_source(self, source: str, filename: str = "<module>") -> list[LoaderTrace]:
        tree = ast.parse(source, filename=filename)
        schema_vars = _find_schema_vars(tree)
        traces: list[LoaderTrace] = []
        for func, schema in _find_bound_loaders(tree, schema_vars):
            if not func.args.args:
                # Can't trace a loader with no parameter to treat as config.
                traces.append(LoaderTrace(func.name, schema, (), ()))
                continue
            config_param = func.args.args[0].arg
            alias_map = _build_alias_map(func, config_param)
            multi_alias_map = _build_multi_alias_map(func, config_param, alias_map)

            sink_hits: list[SinkHit] = []
            joint_sink_hits: list[JointSinkHit] = []
            for node in ast.walk(func):
                if isinstance(node, ast.Call):
                    hits, joint_hits = _match_sink_hits(
                        node, config_param, alias_map, multi_alias_map
                    )
                    for f_name, category, desc in hits:
                        sink_hits.append(SinkHit(f_name, category, desc, node.lineno))
                    for fields, category, desc in joint_hits:
                        joint_sink_hits.append(JointSinkHit(fields, category, desc, node.lineno))

            accessed = _all_config_field_accesses(func, config_param)
            undeclared = tuple(sorted(accessed - schema.fields.keys()))

            traces.append(
                LoaderTrace(
                    func.name, schema, tuple(sink_hits), tuple(joint_sink_hits), undeclared
                )
            )
        return traces

    def trace_file(self, path: str) -> list[LoaderTrace]:
        with open(path, encoding="utf-8") as f:
            source = f.read()
        return self.trace_source(source, filename=path)
