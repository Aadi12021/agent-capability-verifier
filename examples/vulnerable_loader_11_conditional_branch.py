"""
Original example (not a reproduction of any disclosed exploit) demonstrating
that a config field reaching a dangerous sink on only *some* code paths is
still detected: capaudit's tracer walks the whole function body without
regard to control flow, so a sink nested inside an `if` branch is found the
same way an unconditional one would be. This is a deliberate
over-approximation (sound, not path-sensitive) -- see the README's scope
section -- not a special case that had to be added for this example.

"legacy_mode" is declared OPAQUE_STRING. On the common (non-legacy) path
it's never used as anything but an inert flag. Only when the legacy branch
is taken does it get rendered as a template -- a mismatch that would only
ever fire in production under a specific runtime condition, which is
exactly the kind of bug that's easy to miss in code review.
"""

from jinja2 import Template

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "legacy_mode": Capability.OPAQUE_STRING,
    "use_legacy_renderer": Capability.NUMERIC,
})


@SCHEMA.bind
def render_report(config: dict):
    legacy_mode = config["legacy_mode"]
    use_legacy_renderer = config["use_legacy_renderer"]

    if use_legacy_renderer:
        # BUG: only reached when 'use_legacy_renderer' is truthy, but
        # 'legacy_mode' is declared OPAQUE_STRING and is rendered as a
        # template here.
        return Template(legacy_mode).render()

    return {"mode": legacy_mode}
