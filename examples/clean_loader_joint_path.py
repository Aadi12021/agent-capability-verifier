"""
Original example showing the *correct* way to legitimize the joint-field
pattern that examples/vulnerable_loader_4_joint_path.py gets wrong: the same
shape (a directory field joined with a name field, then opened), but the
schema explicitly declares that combination via a JointCapability rule, so
capaudit's v2 checker stays silent instead of flagging it.

This does not, on its own, make the join safe against path traversal --
declaring a JointCapability rule is a statement that this combination is
*intended* to reach the file system, not a guarantee that the loader also
validates the resulting path. That validation (e.g. checking the resolved
path stays under plugin_dir) is the loader's job; the schema rule is about
capability, not sanitization.
"""

import os

from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {
        "plugin_dir": Capability.OPAQUE_STRING,
        "asset_name": Capability.OPAQUE_STRING,
    },
    joint=[
        JointCapability(fields={"plugin_dir", "asset_name"}, capability=Capability.FILE_PATH),
    ],
)


@SCHEMA.bind
def load_plugin_asset(config: dict):
    plugin_dir = config["plugin_dir"]
    asset_name = config["asset_name"]

    # OK: {"plugin_dir", "asset_name"} is declared, via the JointCapability
    # rule above, as jointly having FILE_PATH's capability.
    full_path = os.path.join(plugin_dir, asset_name)
    with open(full_path) as f:
        return f.read()
