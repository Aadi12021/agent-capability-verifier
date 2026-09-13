"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch: a config field declared ENUM (one
of a small, fixed set of named calculation modes) is passed directly to
`eval()`. No Capability ever legitimizes reaching code execution -- see
docs/capability-schema.md -- so this is flagged regardless of declaration,
but ENUM is a particularly easy one to miss in review: it *reads* as a
closed, safe set of choices, which is exactly why a later "let ops add new
modes without a code change" shortcut is so tempting, and so dangerous.

"calculation_mode" reads, from the schema, as one of a handful of named
modes (e.g. "sum", "average", "max"). The implementation instead evaluates
it as a Python expression, so any value the config happens to contain -- not
just the documented choices -- runs as code.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"calculation_mode": Capability.ENUM})


@SCHEMA.bind
def compute_summary(config: dict):
    calculation_mode = config["calculation_mode"]

    # BUG: 'calculation_mode' is declared ENUM (a fixed set of literal
    # choices) but is never checked against that set before reaching eval.
    return eval(calculation_mode)
