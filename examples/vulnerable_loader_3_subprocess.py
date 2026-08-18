"""
Original example (not a reproduction of any disclosed exploit) demonstrating a
declared-vs-actual capability mismatch: a config field declared ENUM (a
closed set of known choices) is actually passed straight into a subprocess
invocation without ever being validated against that set.

"log_level" reads, from the schema, as one of a small fixed set of levels
(e.g. "debug", "info", "warn"). The implementation forwards it verbatim as an
argument to an external diagnostics tool, so any value the config happens to
contain reaches a shell-adjacent sink — not just the documented choices.
"""

import subprocess

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "log_level": Capability.ENUM,
})


@SCHEMA.bind
def run_diagnostics(config: dict):
    log_level = config["log_level"]

    # BUG: 'log_level' is declared ENUM (a fixed set of literal choices) but
    # is never checked against that set before reaching subprocess.run.
    subprocess.run(["diagnostics-tool", "--level", log_level], check=True)
