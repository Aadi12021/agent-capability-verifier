"""Property-based tests: instead of asserting specific expected outputs on
hand-picked loaders, these generate randomized (declared capability, actual
sink, access pattern) combinations and check two invariants that must hold
for *any* such combination:

- **Soundness**: if a field actually reaches a sink its declared capability
  doesn't permit, the checker flags it.
- **No false positives**: if a field only reaches sinks its declared
  capability does permit, the checker stays silent for it.

"Actually reaches" and "permits" are both defined against `ALLOWED_SINKS`
(`capaudit.schema`) -- the same table the checker itself is built on -- so
this isn't an independent oracle; it's a way of exercising many more
(capability, sink, access-pattern) combinations than any hand-written test
would, and letting Hypothesis shrink any failure to a minimal reproducing
case. It's deliberately scoped to patterns the tracer already understands --
a direct `config[...]` access, and a chain of simple variable-to-variable
aliases -- rather than the full space of Python syntax; `test_mutation.py`
documents specific patterns outside that scope which are known to be missed.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from capaudit.checker import check_source
from capaudit.schema import ALLOWED_SINKS, Capability, SinkCategory

# Sink categories the generator below knows how to construct a real call
# for. (Every SinkCategory the tracer supports is covered.)
_SINK_TEMPLATES: dict[SinkCategory, str] = {
    SinkCategory.FILE_READ: "open({expr})",
    SinkCategory.FILE_WRITE: 'open({expr}, "w")',
    SinkCategory.CODE_EXEC: "eval({expr})",
    SinkCategory.TEMPLATE_RENDER: "Template({expr}).render()",
    SinkCategory.SUBPROCESS: "subprocess.run([{expr}], check=True)",
    SinkCategory.NETWORK: "urllib.request.urlopen({expr})",
}

_SINK_IMPORTS: dict[SinkCategory, str] = {
    SinkCategory.SUBPROCESS: "import subprocess\n",
    SinkCategory.NETWORK: "import urllib.request\n",
}

_FIELD_NAMES = ["alpha", "bravo", "charlie", "delta", "echo"]

_capability_strategy = st.sampled_from(list(Capability))
_sink_strategy = st.sampled_from(list(_SINK_TEMPLATES.keys()))
_field_name_strategy = st.sampled_from(_FIELD_NAMES)


def _generate_loader_source(
    field_name: str, capability: Capability, sink: SinkCategory, alias_hops: int
) -> str:
    """A schema declaring exactly one field, plus a loader that accesses it
    via `config[field_name]`, then renames it through `alias_hops` further
    variable-to-variable assignments (0 = used directly), before passing
    the final variable to a call matching `sink`."""
    setup_lines = [f'v0 = config["{field_name}"]']
    for i in range(1, alias_hops + 1):
        setup_lines.append(f"v{i} = v{i - 1}")
    final_var = f"v{alias_hops}"

    sink_expr = _SINK_TEMPLATES[sink].format(expr=final_var)
    import_line = _SINK_IMPORTS.get(sink, "")
    body = "\n    ".join(setup_lines)

    return f"""{import_line}from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"{field_name}": Capability.{capability.name}}})

@SCHEMA.bind
def load(config):
    {body}
    return {sink_expr}
"""


def _assert_matches_ground_truth(
    field_name: str, capability: Capability, sink: SinkCategory, source: str
) -> None:
    result = check_source(source)
    field_mismatches = [m for m in result.mismatches if m.field == field_name]
    is_allowed = sink in ALLOWED_SINKS[capability]

    if is_allowed:
        assert field_mismatches == [], (
            f"false positive: field declared {capability} was flagged reaching "
            f"{sink.value}, which ALLOWED_SINKS permits for that capability\n\n{source}"
        )
    else:
        assert len(field_mismatches) == 1, (
            f"unsound: field declared {capability} actually reaches {sink.value}, "
            f"which ALLOWED_SINKS does not permit, but the checker found "
            f"{len(field_mismatches)} mismatch(es) for it instead of exactly 1\n\n{source}"
        )
        assert field_mismatches[0].actual_sink == sink


# --- Scope 1: direct config[...] access straight into the sink ---


@given(field_name=_field_name_strategy, capability=_capability_strategy, sink=_sink_strategy)
@settings(max_examples=200)
def test_soundness_and_precision_for_direct_field_access(field_name, capability, sink):
    source = _generate_loader_source(field_name, capability, sink, alias_hops=0)
    _assert_matches_ground_truth(field_name, capability, sink, source)


# --- Scope 2: the field is renamed through a chain of simple aliases first ---


@given(
    field_name=_field_name_strategy,
    capability=_capability_strategy,
    sink=_sink_strategy,
    alias_hops=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=200)
def test_soundness_and_precision_through_simple_alias_chains(
    field_name, capability, sink, alias_hops
):
    source = _generate_loader_source(field_name, capability, sink, alias_hops)
    _assert_matches_ground_truth(field_name, capability, sink, source)
