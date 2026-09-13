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

Since this tracer parses source that could itself be adversarial (not just
the config values it's checking), it applies a few defensive limits before
and during analysis: a max input size checked before `ast.parse()`, a
wall-clock timeout around that same call, and a bound on the recursion/
iteration used to follow attribute chains, compound expressions, and alias
chains. These exist purely so pathological input fails with a clear error
instead of hanging or crashing the process — see `SourceTooLargeError`,
`ParseTimeoutError`, and `TraceDepthExceededError` below, and the README's
scope section for the current default limits.
"""

from __future__ import annotations

import ast
import os
import signal
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from capaudit.schema import (
    Capability,
    CapabilitySchema,
    JointCapability,
    SinkCategory,
    UnknownFieldError,
)

# --- Adversarial-input hardening: limits and exceptions ---
#
# capaudit's own threat model (see the README) is that it never executes the
# source it analyzes -- but ast.parse() and this module's own tree-walking
# still have to run on it, and that source could be attacker-controlled.
# Since nothing here executes untrusted code, the realistic risk is resource
# exhaustion (an absurdly large file, a parse that's pathologically slow, an
# expression or alias chain nested/chained deep enough to blow the Python
# call stack or spin the fixed-point loops below for a very long time), not
# code execution. These constants and exceptions bound that risk.

DEFAULT_MAX_SOURCE_BYTES = 5_000_000
"""No legitimate config-loader source file is anywhere near this large;
treat anything bigger as adversarial/pathological rather than spend time
reading or parsing it."""

DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0
"""Wall-clock budget for a single ast.parse() call. Deliberately-crafted
source (e.g. extreme nesting) can make CPython's own parser pathologically
slow; this bounds how long capaudit will wait for it."""

_MAX_DOTTED_NAME_DEPTH = 150
"""Recursion bound for resolving a Name/Attribute chain (`a.b.c...`). Real
code never nests this deep; this exists so a generated `a.b.b.b...` chain
raises a clear error instead of a RecursionError at an unpredictable depth
(which depends on however much stack the caller already used)."""

_MAX_FIELD_EXPR_DEPTH = 150
"""Recursion bound for `_resolve_fields`'s walk through nested string
concatenation / f-string / os.path.join(...) expressions, for the same
reason as `_MAX_DOTTED_NAME_DEPTH`."""

_MAX_ALIAS_FIXED_POINT_ITERATIONS = 1000
"""Bound on the outer `while changed` loop in `_build_alias_map` and
`_build_multi_alias_map`. Both are fixed-point passes over the whole
function body; a long enough chain of aliases declared in reverse
dependency order forces one additional pass per hop, so an unbounded chain
could otherwise make this loop run (and re-walk the whole function) an
unbounded number of times."""


class SourceTooLargeError(ValueError):
    """Raised when source given to the tracer exceeds the configured size
    limit, before any parsing is attempted."""


class ParseTimeoutError(TimeoutError):
    """Raised when `ast.parse()` did not finish within the configured
    wall-clock timeout."""


class TraceDepthExceededError(RecursionError):
    """Raised when following a field's attribute, compound-expression, or
    alias chain exceeds the tracer's configured depth/iteration bound -- a
    defensive limit against pathologically nested or chained source, not
    something a normal loader should ever hit."""


def check_path_size(path: str, max_bytes: int) -> None:
    """Cheap pre-read guard: reject a file that's already absurdly large on
    disk, before reading the whole thing into memory. Used by `trace_file`
    below and by the CLI, which reads files itself. Silently does nothing if
    the size can't be determined (e.g. the path doesn't exist) -- the
    subsequent read is left to raise its own, more specific error."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > max_bytes:
        raise SourceTooLargeError(
            f"{path}: {size} bytes on disk, exceeding the {max_bytes}-byte "
            f"limit -- refusing to read it"
        )


def _check_source_size(source: str, filename: str, max_bytes: int) -> None:
    size = len(source.encode("utf-8", errors="surrogateescape"))
    if size > max_bytes:
        raise SourceTooLargeError(
            f"{filename}: source is {size} bytes, exceeding the "
            f"{max_bytes}-byte limit -- refusing to parse"
        )


def _parse_with_timeout(
    source: str, filename: str, timeout_seconds: float, parse_fn=None
) -> ast.Module:
    """Runs `ast.parse(source, filename=filename)` under a wall-clock
    deadline on platforms that support `SIGALRM` (POSIX). Falls back to an
    un-timed parse if that's unavailable -- a non-POSIX platform (Windows),
    or a caller running outside the main thread of the main interpreter,
    where `signal.signal()` itself raises -- rather than failing outright;
    the size and depth guards elsewhere still bound the work in that case.

    `parse_fn` is an injection point for tests (a fast, deterministic way to
    simulate a slow parse without needing genuinely pathological input);
    production callers should leave it as `None`, which resolves to
    `ast.parse` at call time."""
    if parse_fn is None:
        parse_fn = ast.parse

    if timeout_seconds <= 0 or not hasattr(signal, "SIGALRM"):
        return parse_fn(source, filename=filename)

    def _on_alarm(signum: int, frame: object) -> None:
        raise ParseTimeoutError(f"parsing {filename} exceeded the {timeout_seconds}s timeout")

    try:
        previous_handler = signal.signal(signal.SIGALRM, _on_alarm)
    except ValueError:
        return parse_fn(source, filename=filename)

    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        return parse_fn(source, filename=filename)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)

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


def _dotted_name(node: ast.AST, _depth: int = 0) -> str | None:
    """Resolve a Name/Attribute chain to a dotted string, e.g. "subprocess.run".
    Returns None for anything else (calls, subscripts, etc.)."""
    if _depth > _MAX_DOTTED_NAME_DEPTH:
        raise TraceDepthExceededError(
            f"attribute access chain exceeds the maximum supported depth "
            f"({_MAX_DOTTED_NAME_DEPTH})"
        )
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value, _depth + 1)
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
    iterations = 0
    while changed:
        iterations += 1
        if iterations > _MAX_ALIAS_FIXED_POINT_ITERATIONS:
            raise TraceDepthExceededError(
                f"alias resolution did not converge within "
                f"{_MAX_ALIAS_FIXED_POINT_ITERATIONS} passes over the "
                f"function body -- the source may be deliberately pathological"
            )
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
    _depth: int = 0,
) -> frozenset[str]:
    """Collect every distinct config field that feeds into `expr`. A plain
    single-field expression (already handled by `_resolve_field`) returns a
    one-element set; string concatenation (`+`), an f-string, and
    `os.path.join(...)` are unpacked recursively so a compound expression
    reports every field it draws on. A name already known (via
    `multi_alias_map`) to alias such a compound expression resolves the same
    way. Anything else this tracer doesn't recognize contributes nothing."""
    if _depth > _MAX_FIELD_EXPR_DEPTH:
        raise TraceDepthExceededError(
            f"expression nesting exceeds the maximum supported depth "
            f"({_MAX_FIELD_EXPR_DEPTH})"
        )

    single = _resolve_field(expr, config_param, alias_map)
    if single is not None:
        return frozenset({single})

    if isinstance(expr, ast.Name) and expr.id in multi_alias_map:
        return multi_alias_map[expr.id]

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _resolve_fields(expr.left, config_param, alias_map, multi_alias_map, _depth + 1) | \
            _resolve_fields(expr.right, config_param, alias_map, multi_alias_map, _depth + 1)

    if isinstance(expr, ast.JoinedStr):  # f-string
        fields: set[str] = set()
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                fields |= _resolve_fields(
                    value.value, config_param, alias_map, multi_alias_map, _depth + 1
                )
        return frozenset(fields)

    if isinstance(expr, ast.Call) and _dotted_name(expr.func) == "os.path.join":
        fields = set()
        for arg in expr.args:
            fields |= _resolve_fields(arg, config_param, alias_map, multi_alias_map, _depth + 1)
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
    iterations = 0
    while changed:
        iterations += 1
        if iterations > _MAX_ALIAS_FIXED_POINT_ITERATIONS:
            raise TraceDepthExceededError(
                f"joint-alias resolution did not converge within "
                f"{_MAX_ALIAS_FIXED_POINT_ITERATIONS} passes over the "
                f"function body -- the source may be deliberately pathological"
            )
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


def _parse_capability_attr(node: ast.AST) -> Capability | None:
    """Match `Capability.SOME_NAME`."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
            and node.value.id == "Capability":
        try:
            return Capability[node.attr]
        except KeyError:
            return None
    return None


def _parse_string_literal_collection(node: ast.AST) -> list[str] | None:
    """Match a set/list/tuple literal made up entirely of string constants,
    e.g. `{"base_dir", "filename"}`."""
    if not isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return None
    values: list[str] = []
    for elt in node.elts:
        s = _string_constant(elt)
        if s is None:
            return None
        values.append(s)
    return values


def _parse_joint_capability_call(node: ast.AST) -> JointCapability | None:
    """Match `JointCapability(fields={...}, capability=Capability.X)`,
    accepting `fields`/`capability` positionally or by keyword."""
    if not isinstance(node, ast.Call):
        return None
    callee = _dotted_name(node.func)
    if callee is None or callee.split(".")[-1] != "JointCapability":
        return None

    fields_node = node.args[0] if len(node.args) >= 1 else None
    capability_node = node.args[1] if len(node.args) >= 2 else None
    for kw in node.keywords:
        if kw.arg == "fields":
            fields_node = kw.value
        elif kw.arg == "capability":
            capability_node = kw.value
    if fields_node is None or capability_node is None:
        return None

    fields = _parse_string_literal_collection(fields_node)
    capability = _parse_capability_attr(capability_node)
    if fields is None or capability is None:
        return None
    try:
        return JointCapability(fields=frozenset(fields), capability=capability)
    except ValueError:
        return None


def _parse_joint_keyword(node: ast.AST) -> list[JointCapability] | None:
    """Match the `joint=[JointCapability(...), ...]` keyword argument.
    Returns None (not "not present") if the list is malformed, so callers
    can tell "no joint=" apart from "unparseable joint=" and abandon the
    whole schema declaration in the latter case rather than silently
    dropping rules the source actually declares."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    rules: list[JointCapability] = []
    for elt in node.elts:
        rule = _parse_joint_capability_call(elt)
        if rule is None:
            return None
        rules.append(rule)
    return rules


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
            capability = _parse_capability_attr(val_node)
            if capability is None:
                ok = False
                break
            fields[key] = capability

        joint_rules: list[JointCapability] = []
        if ok:
            for kw in call.keywords:
                if kw.arg != "joint":
                    continue
                parsed = _parse_joint_keyword(kw.value)
                if parsed is None:
                    ok = False
                else:
                    joint_rules = parsed
                break

        if ok:
            try:
                schema_vars[node.targets[0].id] = CapabilitySchema(fields, joint=joint_rules)
            except (TypeError, UnknownFieldError, ValueError):
                # A `joint=` rule that's syntactically fine but semantically
                # invalid (e.g. references a field not in this same dict) --
                # treat the same as any other unparseable schema.
                pass
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
    `@SCHEMA.bind`-decorated loader function it finds.

    `max_source_bytes` and `parse_timeout_seconds` bound the cost of
    analyzing adversarial source (see the module docstring); the depth/
    iteration limits on the tree-walk itself are fixed module constants,
    not configurable here, since they're an internal safety net rather than
    a tuning knob."""

    def __init__(
        self,
        max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
        parse_timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
    ):
        self.max_source_bytes = max_source_bytes
        self.parse_timeout_seconds = parse_timeout_seconds

    def trace_source(self, source: str, filename: str = "<module>") -> list[LoaderTrace]:
        _check_source_size(source, filename, self.max_source_bytes)
        tree = _parse_with_timeout(source, filename, self.parse_timeout_seconds)
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
        check_path_size(path, self.max_source_bytes)
        with open(path, encoding="utf-8") as f:
            source = f.read()
        return self.trace_source(source, filename=path)
