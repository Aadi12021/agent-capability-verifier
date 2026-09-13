"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch on a *write* path specifically: a
config field declared OPAQUE_STRING is used as the destination of a file
write. Prior examples in this project only demonstrated a mismatched
FILE_READ; a write mismatch is at least as serious (arbitrary file
overwrite/creation) and exercises the tracer's write-mode detection
(`open(..., "w")`) on a field that isn't declared FILE_PATH at all.

"report_label" reads, from the schema, as an inert label attached to a
generated report. The implementation instead uses it directly as the
output file's name.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"report_label": Capability.OPAQUE_STRING})


@SCHEMA.bind
def write_report_stub(config: dict):
    report_label = config["report_label"]

    # BUG: 'report_label' is declared OPAQUE_STRING (an inert label) but is
    # actually used as the destination path of a file write here.
    with open(report_label, "w") as f:
        f.write("report generated\n")
