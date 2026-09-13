"""
Original example showing a legitimate use of Capability.COMMAND -- no clean
example previously existed for this capability (all prior COMMAND-adjacent
coverage in examples/ was a mismatch). Also shows Capability.ENUM used
safely: validated against its declared set of choices and never forwarded
to any tracked sink, since ENUM's declared capability permits none at all.
"""

import subprocess

from capaudit.schema import Capability, CapabilitySchema

_ALLOWED_LOG_LEVELS = {"debug", "info", "warn", "error"}

SCHEMA = CapabilitySchema({
    "diagnostics_command": Capability.COMMAND,
    "log_level": Capability.ENUM,
})


@SCHEMA.bind
def run_diagnostics_command(config: dict):
    diagnostics_command = config["diagnostics_command"]
    log_level = config["log_level"]

    # OK: 'log_level' is declared ENUM and is only ever compared against
    # its documented set of choices -- never forwarded to any sink, which
    # is the only way a value declared ENUM is allowed to be used.
    if log_level not in _ALLOWED_LOG_LEVELS:
        raise ValueError(f"unknown log level: {log_level!r}")

    # OK: 'diagnostics_command' is declared COMMAND and is used exactly as
    # that capability permits: passed to subprocess.run.
    subprocess.run([diagnostics_command], check=True)
