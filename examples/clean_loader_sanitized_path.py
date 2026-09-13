"""
Original example demonstrating that a genuinely sanitized/validated field is
correctly left unflagged -- a precision check, not a recall one.
'config_name' is declared FILE_PATH (the correct capability for how it's
actually used) *and* is validated against an explicit allowlist before
being opened. This confirms two things: ordinary validation code sitting
between the field access and the sink doesn't confuse the tracer's alias
resolution into a spurious mismatch, and a correctly-declared, correctly-
used, additionally-validated field stays silent -- same as an unvalidated
one would, since the validation is defense-in-depth here, not what makes
the declaration correct. (The declaration is correct because FILE_PATH is
genuinely what this field is used as; that's independent of whether it's
also validated.)
"""

from capaudit.schema import Capability, CapabilitySchema

_ALLOWED_CONFIG_NAMES = {"base.yaml", "overrides.yaml"}

SCHEMA = CapabilitySchema({"config_name": Capability.FILE_PATH})


@SCHEMA.bind
def load_named_config(config: dict):
    config_name = config["config_name"]

    if config_name not in _ALLOWED_CONFIG_NAMES:
        raise ValueError(f"unrecognized config name: {config_name!r}")

    # OK: 'config_name' is declared FILE_PATH, matches its actual use, and
    # has additionally been validated against an allowlist above -- neither
    # fact changes the other.
    with open(config_name) as f:
        return f.read()
