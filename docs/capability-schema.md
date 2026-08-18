# Capability schema spec (v1)

This document describes the vocabulary `capaudit` uses to express "what a config field is
declared to be" and "what it actually does" — and how a mismatch between the two is defined. It
implements the design in [`src/capaudit/schema.py`](../src/capaudit/schema.py); read that module
for the authoritative enum values.

## The problem this models

The motivating incident (see the [README](../README.md)) had two fields whose declared shape
looked inert — a numeric offset — but whose consuming code actually treated them as a file path
and as a template string, respectively. A schema that only records a Python *type* (`int`, `str`)
can't catch this: both the legitimate offset and the malicious path are, at the type-checker
level, just a string or a number. What's missing isn't a type system — it's a record of *intended
use*, checked against *actual use*.

## Capability

A `Capability` is the maximum intended use of a config field, declared by whoever writes the
loader. Ordered roughly from least to most powerful:

| Capability | Meaning |
|---|---|
| `NONE` | The field must not be consumed by the loader at all. |
| `NUMERIC` | An int/float used only as a number — offset, size, count, timeout. |
| `ENUM` | A string constrained to a fixed, known set of literal choices. |
| `OPAQUE_STRING` | A string used only as an inert label/identifier — never interpreted as a path, command, template, or address. |
| `FILE_PATH` | A string legitimately used to open, read, or write a file. |
| `TEMPLATE` | A string legitimately rendered through a template engine. |
| `COMMAND` | A string legitimately passed to a subprocess or shell invocation. |
| `NETWORK_ADDRESS` | A value legitimately used as a network destination (host, URL, socket address). |

Note there is deliberately no capability that legitimizes direct code execution (`eval`, `exec`,
`compile`) — no v1 schema declaration can mark a field as allowed to reach that sink. If a config
field flows into `eval`/`exec`/`compile`, it is always flagged, regardless of declaration.

## SinkCategory

A `SinkCategory` is a category of operation the static tracer (step 4) looks for as a destination
of a field's value:

| SinkCategory | Example call sites |
|---|---|
| `FILE_READ` | `open(path)`, `Path(path).read_text()` |
| `FILE_WRITE` | `open(path, "w")`, `Path(path).write_text()` |
| `CODE_EXEC` | `eval(x)`, `exec(x)`, `compile(x)` |
| `TEMPLATE_RENDER` | `Template(x).render()`, `jinja_env.from_string(x)` |
| `SUBPROCESS` | `subprocess.run(x)`, `os.system(x)`, `os.popen(x)` |
| `NETWORK` | `socket.connect(x)`, `urllib.request.urlopen(x)` |

## The mismatch rule

Each `Capability` has a fixed set of `SinkCategory` values it's allowed to reach
(`ALLOWED_SINKS` in `schema.py`). A field is flagged when the tracer finds it reaching a sink
category that is **not** in its declared capability's allowed set — including when the field
reaches a sink at all despite being declared `NONE`, `NUMERIC`, `ENUM`, or `OPAQUE_STRING` (all
four allow zero sinks).

This mapping is fixed by the tool in v1, not user-configurable — the point of the schema is to
constrain what a field author can claim, not to let a compromised or careless declaration
re-legitimize a dangerous sink.

## Declaring a schema

```python
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "offset": Capability.NUMERIC,
    "dataset_name": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load_dataset_config(config: dict):
    ...
```

`CapabilitySchema.bind` is a no-op at runtime beyond attaching the schema to the function object.
`capaudit`'s analyzer finds the `@SCHEMA.bind` decorator by parsing the source with `ast`, not by
importing or executing the module under analysis — consistent with this being a static linter, not
a runtime enforcement layer, in v1.

## What's intentionally out of scope for this spec

- **No lattice/ordering between capabilities.** `FILE_PATH`, `TEMPLATE`, `COMMAND`, and
  `NETWORK_ADDRESS` are treated as incomparable, not as gradations of one "power level" — a field
  declared `FILE_PATH` is not implicitly allowed to reach `SUBPROCESS`. Each capability's allowed
  sinks are declared explicitly.
- **No per-field custom sink rules.** All fields sharing a capability share its allowed-sinks set.
- **No cross-field or whole-config reasoning** (e.g. "field A is only dangerous if field B is
  also set"). Each field is evaluated independently in v1.

These may be revisited in a later version; see the README's scope section for the current status
of the tracer and checker built on top of this schema.
