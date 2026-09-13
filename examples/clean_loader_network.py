"""
Original example showing a legitimate use of Capability.NETWORK_ADDRESS --
no clean example previously existed for this capability either.
"""

import urllib.request

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"healthcheck_url": Capability.NETWORK_ADDRESS})


@SCHEMA.bind
def ping_healthcheck(config: dict):
    healthcheck_url = config["healthcheck_url"]

    # OK: 'healthcheck_url' is declared NETWORK_ADDRESS and is used exactly
    # as that capability permits: as the destination of a network call.
    return urllib.request.urlopen(healthcheck_url, timeout=5)
