"""
Original example (not a reproduction of any disclosed exploit) demonstrating a
declared-vs-actual capability mismatch: a config field declared NUMERIC is
actually used to open a local file.

Imagine a dataset index format where "offset" is documented as a byte offset
into a shared blob file. The schema below reflects that documented intent.
The implementation, however, was written (or later modified) to treat the
same field as a standalone file path — the kind of drift that's easy to miss
in review because both uses "look like" the field is just data, not a
capability.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "offset": Capability.NUMERIC,
    "record_count": Capability.NUMERIC,
})


@SCHEMA.bind
def load_record_index(config: dict):
    offset = config["offset"]
    record_count = config["record_count"]

    # BUG: 'offset' is declared NUMERIC (a byte offset) but is actually used
    # as a file path here. A config author who sees "offset: numeric" in the
    # schema has no reason to expect this field can read arbitrary files.
    with open(offset) as blob:
        blob.seek(0)
        return blob.read(record_count)
