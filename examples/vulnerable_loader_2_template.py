"""
Original example (not a reproduction of any disclosed exploit) demonstrating a
declared-vs-actual capability mismatch: a config field declared OPAQUE_STRING
is actually rendered as a Jinja2 template.

"greeting_name" looks, from the schema, like an inert label dropped into a
static message. The implementation instead treats it as template source,
turning any config-supplied value into a code-execution surface via Jinja2's
template language.
"""

from jinja2 import Template

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "greeting_name": Capability.OPAQUE_STRING,
})


@SCHEMA.bind
def render_welcome_message(config: dict):
    greeting_name = config["greeting_name"]

    # BUG: 'greeting_name' is declared OPAQUE_STRING (an inert label) but is
    # actually compiled and rendered as a Jinja2 template here.
    return Template(greeting_name).render()
