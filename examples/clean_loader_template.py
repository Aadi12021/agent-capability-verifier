"""
Original example showing a legitimate use of Capability.TEMPLATE -- no
clean example previously existed for this capability either (the only
prior TEMPLATE-adjacent coverage in examples/ was a mismatch: an
OPAQUE_STRING field wrongly rendered as one).
"""

from jinja2 import Template

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"welcome_template": Capability.TEMPLATE})


@SCHEMA.bind
def render_welcome(config: dict):
    welcome_template = config["welcome_template"]

    # OK: 'welcome_template' is declared TEMPLATE and is used exactly as
    # that capability permits: rendered through the template engine.
    return Template(welcome_template).render()
