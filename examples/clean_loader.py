"""
Original example with no declared-vs-actual capability mismatch, used as the
false-positive test case: every field's declared capability matches how the
loader actually uses it.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "manifest_path": Capability.FILE_PATH,
    "batch_size": Capability.NUMERIC,
    "dataset_label": Capability.OPAQUE_STRING,
})


@SCHEMA.bind
def load_manifest(config: dict):
    manifest_path = config["manifest_path"]
    batch_size = config["batch_size"]
    dataset_label = config["dataset_label"]

    # OK: 'manifest_path' is declared FILE_PATH and is used to open a file.
    with open(manifest_path) as f:
        lines = f.readlines()

    # OK: 'batch_size' is declared NUMERIC and is only used as a number.
    batch = lines[:batch_size]

    # OK: 'dataset_label' is declared OPAQUE_STRING and is only used as an
    # inert label attached to the result — never interpreted.
    return {"label": dataset_label, "records": batch}
