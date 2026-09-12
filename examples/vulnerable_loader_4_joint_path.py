"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a *joint*-field capability mismatch: two config fields, each individually
declared as an inert opaque string, combine into a path-traversal primitive.

Imagine a plugin loader where "plugin_dir" documents the fixed,
operator-controlled directory a plugin's assets live under, and "asset_name"
documents which asset within it to serve. Neither field looks dangerous in
isolation: "plugin_dir" reads like a static root path the operator controls,
and "asset_name" reads like a simple, inert label. But the loader builds the
actual path by joining them and never checks that the result stays inside
"plugin_dir" -- so a config-supplied "asset_name" of
"../../../../etc/passwd" reads an arbitrary file on disk, even though no
single field was ever declared FILE_PATH.

v1 of capaudit's checker (single-field-only) cannot see this: neither
"plugin_dir" nor "asset_name" is ever, on its own, the sole thing reaching
open() -- the argument is `os.path.join(plugin_dir, asset_name)`, so a
single-field tracer finds no field at all for that call and stays silent.
v2 traces the join, reports both fields as jointly reaching FILE_READ, and
flags it because the schema below declares no JointCapability rule for
{"plugin_dir", "asset_name"}.
"""

import os

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "plugin_dir": Capability.OPAQUE_STRING,
    "asset_name": Capability.OPAQUE_STRING,
})


@SCHEMA.bind
def load_plugin_asset(config: dict):
    plugin_dir = config["plugin_dir"]
    asset_name = config["asset_name"]

    # BUG: neither field is declared FILE_PATH, and no JointCapability rule
    # covers {"plugin_dir", "asset_name"} together -- but the combination is
    # exactly a file path, with no containment check on "asset_name".
    full_path = os.path.join(plugin_dir, asset_name)
    with open(full_path) as f:
        return f.read()
