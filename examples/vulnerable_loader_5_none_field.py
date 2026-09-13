"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch on Capability.NONE specifically: a
field declared NONE -- meaning "must not be consumed by this loader at
all" -- is nonetheless read and used.

"debug_dump_path" is reserved for a separate debugging subsystem that reads
it directly from the raw config file; this loader was never meant to touch
it. A later "convenience" change added a debug-dump feature here too,
reusing the same field name and reading it directly -- exactly the kind of
scope creep NONE exists to catch, since the schema explicitly says this
loader shouldn't be looking at this field for any purpose at all.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "dataset_name": Capability.OPAQUE_STRING,
    "debug_dump_path": Capability.NONE,
})


@SCHEMA.bind
def load_dataset_metadata(config: dict):
    dataset_name = config["dataset_name"]
    debug_dump_path = config["debug_dump_path"]

    # BUG: 'debug_dump_path' is declared NONE -- this loader must not
    # consume it at all -- but it's read here anyway and used as a file
    # path.
    with open(debug_dump_path, "w") as f:
        f.write(f"loaded dataset: {dataset_name}\n")

    return {"dataset_name": dataset_name}
