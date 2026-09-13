"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a declared-vs-actual capability mismatch reached through an f-string: a
config field declared NUMERIC (a widget identifier) is interpolated into an
f-string that's then rendered as a Jinja2 template. This also exercises the
tracer's f-string handling on a *single*-field case (an f-string mixing a
literal prefix with exactly one field resolves to a plain single-field
`SinkHit`, not a joint one -- joint hits are only for two or more distinct
fields feeding the same sink).

"widget_id" reads, from the schema, as a plain numeric identifier used to
look up a widget. The implementation instead splices it into template
source, so any value the config contains is interpreted as part of a
template rather than as an opaque number.
"""

from jinja2 import Template

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"widget_id": Capability.NUMERIC})


@SCHEMA.bind
def render_widget_snippet(config: dict):
    widget_id = config["widget_id"]

    # BUG: 'widget_id' is declared NUMERIC but is interpolated into
    # template source and rendered here.
    return Template(f"widget_{widget_id}").render()
