"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch: a config field declared NUMERIC
(a worker identifier) is forwarded, unvalidated, into a subprocess
invocation. Declaring a field NUMERIC is a claim about what the *loader*
does with it, not a runtime type guarantee -- a compromised or malformed
config could hand this field any string at all, and NUMERIC grants no sink
capability whatsoever, so this is flagged regardless of whether today's
config file happens to contain an actual number.

"worker_id" reads, from the schema, as a plain numeric identifier. The
implementation instead splices it straight into an external process
invocation.
"""

import subprocess

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"worker_id": Capability.NUMERIC})


@SCHEMA.bind
def spawn_worker(config: dict):
    worker_id = config["worker_id"]

    # BUG: 'worker_id' is declared NUMERIC but reaches subprocess.run here.
    subprocess.run(["worker-agent", "--id", worker_id], check=True)
