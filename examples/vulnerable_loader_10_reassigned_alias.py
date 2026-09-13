"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch that survives a variable rename:
the field is copied into a differently-named local variable before it ever
reaches the sink -- a common refactor artifact (renaming for clarity, or
introducing a local before a conditional), not an attempt to evade
analysis, but a shape the tracer needs to follow correctly rather than lose
track of.

"backup_target" reads, from the schema, as an inert label describing which
named backup profile to use. The implementation copies it into a
differently-named local ("profile") purely for readability, then forwards
that local straight into an external backup tool -- the rename doesn't
change what the field can actually reach.
"""

import subprocess

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"backup_target": Capability.OPAQUE_STRING})


@SCHEMA.bind
def run_backup(config: dict):
    backup_target = config["backup_target"]
    # Renamed purely for readability elsewhere in the function -- the
    # tracer still has to follow it to the field it aliases.
    profile = backup_target

    # BUG: 'backup_target' (via its alias 'profile') is declared
    # OPAQUE_STRING but reaches subprocess.run here.
    subprocess.run(["backup-tool", "--profile", profile], check=True)
