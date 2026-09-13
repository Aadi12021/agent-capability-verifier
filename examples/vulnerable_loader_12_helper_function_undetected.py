"""
Original example (not a reproduction of any disclosed exploit) demonstrating
a REAL declared-vs-actual capability mismatch that capaudit's tracer
currently MISSES, because it does not do interprocedural analysis (see the
README's scope section): the field is passed as an argument into a plain
helper function defined in the same file, and the actual sink is inside
that helper, not inside the `@SCHEMA.bind`-decorated loader itself.

"cache_key" is declared OPAQUE_STRING. The loader hands it to
`_write_cache_entry`, which opens a file named after it -- a genuine
file-write mismatch. capaudit only walks the body of the bound loader
function itself, so it never sees inside `_write_cache_entry` at all, and
stays completely silent here: no mismatch, no coverage gap, nothing. This
file exists to document that gap honestly with a real, working example and
a test that pins down the current (missed) behavior, rather than only
describing the limitation in prose.
"""

from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"cache_key": Capability.OPAQUE_STRING})


def _write_cache_entry(key: str, payload: str) -> None:
    # The actual mismatch: 'key' (the loader's 'cache_key' field, one call
    # away) is used as a file path here. capaudit never looks inside this
    # function, because it only traces the body of the bound loader itself.
    with open(key, "w") as f:
        f.write(payload)


@SCHEMA.bind
def cache_result(config: dict):
    cache_key = config["cache_key"]
    _write_cache_entry(cache_key, "result data")
    return cache_key
