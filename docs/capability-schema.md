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

## Joint (compound) capabilities

Some real bugs don't come from any single field — they come from *combining* two or more fields
that each look inert on their own. A `base_dir` field and a `filename` field might both be
perfectly reasonable as `OPAQUE_STRING`, yet `open(os.path.join(base_dir, filename))` gives an
attacker-controlled `filename` (e.g. `"../../../etc/passwd"`) arbitrary file access — a capability
neither field's individual declaration grants.

`CapabilitySchema` accepts an optional `joint` argument for exactly this: a list of
`JointCapability` rules, each naming a specific set of fields and the `Capability` their
combination is allowed to have:

```python
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {
        "base_dir": Capability.OPAQUE_STRING,
        "filename": Capability.OPAQUE_STRING,
    },
    joint=[
        JointCapability(fields={"base_dir", "filename"}, capability=Capability.FILE_PATH),
    ],
)
```

This declares that `base_dir` and `filename`, *used together*, are allowed to reach whatever
`Capability.FILE_PATH` allows (`FILE_READ`/`FILE_WRITE`) — reusing the existing `Capability`
vocabulary rather than inventing a parallel one, since "what sinks can this reach" is the same
question whether it's asked of one field or a combination. Every field named in a `joint` rule
must also appear in the schema's own per-field `fields` mapping (checked at construction time via
`UnknownFieldError`), so coverage-gap detection for those fields is unaffected.

If the tracer (see below) finds a sink call whose argument is built from more than one distinct
config field, and no `JointCapability` rule names that *exact* combination, the checker reports it
as a **joint mismatch** — a distinct finding category from the single-field `Mismatch`, because the
bug isn't attributable to any one field's declaration being wrong.

A schema built without the `joint` argument (i.e. every schema that predates this feature) behaves
exactly as before — this is purely additive.

### Current matching and detection limits

- **Exact field-set matching only.** A rule for `{"base_dir", "filename"}` does not cover a sink
  additionally fed by a third field, and does not partially apply to a subset.
- **The tracer currently recognizes three ways fields combine into one sink argument:** string
  concatenation (`a + b`), an f-string (`f"{a}/{b}"`), and `os.path.join(...)` — including through
  one level of simple variable assignment (e.g. `p = os.path.join(a, b); open(p)`). It does not
  currently recognize `%`-formatting, `str.format()`, `pathlib.Path(...) / ...`, or fields threaded
  through a helper function across function or module boundaries; those remain false negatives for
  the same reason single-field flows through such patterns already were.
- **No reasoning about combinations of more than two fields' worth of matched patterns beyond what
  those three patterns naturally nest into** — e.g. `f"{a}/{b}/{c}"` is fine (all three fields are
  collected from the one f-string), but a value built from patterns this tracer doesn't recognize
  at all won't contribute to the joint set.

## What's intentionally out of scope for this spec

- **No lattice/ordering between capabilities.** `FILE_PATH`, `TEMPLATE`, `COMMAND`, and
  `NETWORK_ADDRESS` are treated as incomparable, not as gradations of one "power level" — a field
  declared `FILE_PATH` is not implicitly allowed to reach `SUBPROCESS`. Each capability's allowed
  sinks are declared explicitly.
- **No per-field custom sink rules.** All fields sharing a capability share its allowed-sinks set.
- **No whole-config reasoning beyond named joint rules** (e.g. "field A is only dangerous if field
  B is set to a particular value"). Joint capabilities (above) cover fields composing into one sink
  argument together; they don't reason about conditional relationships between fields' *values*.

These may be revisited in a later version; see the README's scope section for the current status
of the tracer and checker built on top of this schema.
