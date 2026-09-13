import ast
import time
from pathlib import Path

import pytest

from capaudit.schema import Capability, SinkCategory
from capaudit.tracer import (
    CapabilityTracer,
    ParseTimeoutError,
    SourceTooLargeError,
    TraceDepthExceededError,
    _parse_with_timeout,
    check_path_size,
)

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _trace_source(source: str):
    return CapabilityTracer().trace_source(source)


def test_no_schema_or_loader_yields_no_traces():
    source = """
def not_a_loader(config):
    return config["x"]
"""
    assert _trace_source(source) == []


def test_direct_subscript_field_reaches_open():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["offset"]).read()
"""
    traces = _trace_source(source)
    assert len(traces) == 1
    [hit] = traces[0].sink_hits
    assert hit.field == "offset"
    assert hit.sink == SinkCategory.FILE_READ


def test_get_style_field_access_is_traced():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    offset = config.get("offset")
    return open(offset)
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.field == "offset"


def test_multi_hop_alias_chain_is_traced():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    a = config["offset"]
    b = a
    c = b
    return open(c)
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.field == "offset"
    assert hit.sink == SinkCategory.FILE_READ


def test_open_write_mode_is_file_write():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"path": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    path = config["path"]
    return open(path, "w")
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.FILE_WRITE


def test_open_default_mode_is_file_read():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"path": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["path"])
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.FILE_READ


def test_eval_and_exec_are_code_exec():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"expr": Capability.OPAQUE_STRING})

@SCHEMA.bind
def load(config):
    eval(config["expr"])
    exec(config["expr"])
"""
    [trace] = _trace_source(source)
    assert len(trace.sink_hits) == 2
    assert all(h.sink == SinkCategory.CODE_EXEC for h in trace.sink_hits)


def test_template_constructor_is_template_render():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"msg": Capability.OPAQUE_STRING})

@SCHEMA.bind
def load(config):
    return Template(config["msg"]).render()
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.TEMPLATE_RENDER


def test_subprocess_list_element_is_traced():
    source = """
import subprocess
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"level": Capability.ENUM})

@SCHEMA.bind
def load(config):
    level = config["level"]
    subprocess.run(["tool", "--level", level])
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.field == "level"
    assert hit.sink == SinkCategory.SUBPROCESS


def test_path_read_text_is_file_read():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"p": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return Path(config["p"]).read_text()
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.FILE_READ


def test_path_write_text_is_file_write():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"p": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    Path(config["p"]).write_text("data")
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.FILE_WRITE


def test_field_never_reaching_a_sink_produces_no_hits():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"batch_size": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    batch_size = config["batch_size"]
    return list(range(batch_size))
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()


def test_undeclared_field_access_is_reported():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    offset = config["offset"]
    mystery = config["mystery_field"]
    return offset, mystery
"""
    [trace] = _trace_source(source)
    assert trace.undeclared_fields_used == ("mystery_field",)


def test_network_sink_is_traced():
    source = """
import requests
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"url": Capability.OPAQUE_STRING})

@SCHEMA.bind
def load(config):
    return requests.get(config["url"])
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.NETWORK


# --- Joint (multi-field) sink hits ---


def test_single_field_expression_still_produces_a_plain_sink_hit_not_joint():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"path": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["path"])
"""
    [trace] = _trace_source(source)
    assert trace.joint_sink_hits == ()
    [hit] = trace.sink_hits
    assert hit.field == "path"


def test_os_path_join_of_two_fields_is_a_joint_hit():
    source = """
import os
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "base_dir": Capability.OPAQUE_STRING,
    "filename": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load(config):
    return open(os.path.join(config["base_dir"], config["filename"]))
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"base_dir", "filename"})
    assert joint.sink == SinkCategory.FILE_READ


def test_string_concatenation_of_two_fields_is_a_joint_hit():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "base_dir": Capability.OPAQUE_STRING,
    "filename": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load(config):
    path = config["base_dir"] + "/" + config["filename"]
    return open(path)
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"base_dir", "filename"})


def test_fstring_of_two_fields_is_a_joint_hit():
    source = '''
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "base_dir": Capability.OPAQUE_STRING,
    "filename": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load(config):
    return open(f"{config['base_dir']}/{config['filename']}")
'''
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"base_dir", "filename"})


def test_joint_hit_through_variable_alias_of_compound_expression():
    source = """
import os
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "base_dir": Capability.OPAQUE_STRING,
    "filename": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load(config):
    full_path = os.path.join(config["base_dir"], config["filename"])
    return open(full_path)
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"base_dir", "filename"})
    assert joint.sink == SinkCategory.FILE_READ


def test_three_fields_in_one_fstring_are_all_collected():
    source = '''
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "a": Capability.OPAQUE_STRING,
    "b": Capability.OPAQUE_STRING,
    "c": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load(config):
    return open(f"{config['a']}/{config['b']}/{config['c']}")
'''
    [trace] = _trace_source(source)
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"a", "b", "c"})


def test_schema_with_joint_keyword_is_reconstructed_with_its_joint_rules():
    # The tracer statically reconstructs CapabilitySchema(...) from source;
    # this checks it doesn't silently drop a `joint=` keyword argument.
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"base_dir": Capability.OPAQUE_STRING, "filename": Capability.OPAQUE_STRING},
    joint=[JointCapability(fields={"base_dir", "filename"}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return config["base_dir"]
"""
    [trace] = _trace_source(source)
    assert len(trace.schema.joint_rules) == 1
    [rule] = trace.schema.joint_rules
    assert rule.fields == frozenset({"base_dir", "filename"})
    assert rule.capability == Capability.FILE_PATH


def test_joint_hit_field_still_counts_toward_config_field_accesses():
    # Coverage-gap detection is unaffected by joint-field composition: both
    # fields are still recorded as accessed even though they never resolve
    # to a single-field sink hit.
    source = """
import os
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"base_dir": Capability.OPAQUE_STRING})

@SCHEMA.bind
def load(config):
    return open(os.path.join(config["base_dir"], config["mystery"]))
"""
    [trace] = _trace_source(source)
    assert trace.undeclared_fields_used == ("mystery",)


def test_unbound_function_is_not_traced():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

def load(config):
    return open(config["offset"])
"""
    assert _trace_source(source) == []


# --- Integration: trace the actual example files on disk ---

def test_traces_vulnerable_example_1_path():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_1_path.py"))
    assert trace.function_name == "load_record_index"
    fields_hit = {h.field for h in trace.sink_hits}
    assert "offset" in fields_hit


def test_traces_vulnerable_example_2_template():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_2_template.py"))
    assert trace.function_name == "render_welcome_message"
    assert trace.sink_hits[0].sink == SinkCategory.TEMPLATE_RENDER


def test_traces_vulnerable_example_3_subprocess():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_3_subprocess.py"))
    assert trace.function_name == "run_diagnostics"
    assert trace.sink_hits[0].sink == SinkCategory.SUBPROCESS


def test_traces_clean_example_with_only_expected_hit():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader.py"))
    assert trace.function_name == "load_manifest"
    assert len(trace.sink_hits) == 1
    assert trace.sink_hits[0].field == "manifest_path"
    assert trace.sink_hits[0].sink == SinkCategory.FILE_READ
    assert trace.undeclared_fields_used == ()


def test_traces_vulnerable_example_4_joint_path():
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_4_joint_path.py")
    )
    assert trace.function_name == "load_plugin_asset"
    assert trace.sink_hits == ()  # neither field alone resolves to the sink
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"plugin_dir", "asset_name"})
    assert joint.sink == SinkCategory.FILE_READ


def test_traces_clean_example_joint_path_with_no_findings():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader_joint_path.py"))
    assert trace.function_name == "load_plugin_asset"
    assert trace.sink_hits == ()
    [joint] = trace.joint_sink_hits
    assert joint.fields == frozenset({"plugin_dir", "asset_name"})
    assert len(trace.schema.joint_rules) == 1


def test_traces_vulnerable_example_5_none_field():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_5_none_field.py"))
    assert trace.function_name == "load_dataset_metadata"
    fields_hit = {h.field for h in trace.sink_hits}
    assert "debug_dump_path" in fields_hit
    [hit] = [h for h in trace.sink_hits if h.field == "debug_dump_path"]
    assert hit.sink == SinkCategory.FILE_WRITE


def test_traces_vulnerable_example_6_write():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_6_write.py"))
    assert trace.function_name == "write_report_stub"
    [hit] = trace.sink_hits
    assert hit.field == "report_label"
    assert hit.sink == SinkCategory.FILE_WRITE


def test_traces_vulnerable_example_7_numeric_subprocess():
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_7_numeric_subprocess.py")
    )
    assert trace.function_name == "spawn_worker"
    [hit] = trace.sink_hits
    assert hit.field == "worker_id"
    assert hit.sink == SinkCategory.SUBPROCESS


def test_traces_vulnerable_example_8_enum_eval():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "vulnerable_loader_8_enum_eval.py"))
    assert trace.function_name == "compute_summary"
    [hit] = trace.sink_hits
    assert hit.field == "calculation_mode"
    assert hit.sink == SinkCategory.CODE_EXEC


def test_traces_vulnerable_example_9_numeric_template_fstring():
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_9_numeric_template_fstring.py")
    )
    assert trace.function_name == "render_widget_snippet"
    # A single field inside an f-string is a plain SinkHit, not joint.
    assert trace.joint_sink_hits == ()
    [hit] = trace.sink_hits
    assert hit.field == "widget_id"
    assert hit.sink == SinkCategory.TEMPLATE_RENDER


def test_traces_vulnerable_example_10_reassigned_alias():
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_10_reassigned_alias.py")
    )
    assert trace.function_name == "run_backup"
    [hit] = trace.sink_hits
    assert hit.field == "backup_target"
    assert hit.sink == SinkCategory.SUBPROCESS


def test_traces_vulnerable_example_11_conditional_branch():
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_11_conditional_branch.py")
    )
    assert trace.function_name == "render_report"
    [hit] = trace.sink_hits
    assert hit.field == "legacy_mode"
    assert hit.sink == SinkCategory.TEMPLATE_RENDER


def test_traces_vulnerable_example_12_helper_function_is_a_documented_miss():
    # Pinned-down known limitation: capaudit does no interprocedural
    # analysis, so the real mismatch inside _write_cache_entry is invisible
    # from the bound loader's own body.
    [trace] = CapabilityTracer().trace_file(
        str(EXAMPLES_DIR / "vulnerable_loader_12_helper_function_undetected.py")
    )
    assert trace.function_name == "cache_result"
    assert trace.sink_hits == ()
    assert trace.joint_sink_hits == ()
    assert trace.undeclared_fields_used == ()


def test_traces_clean_example_command():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader_command.py"))
    assert trace.function_name == "run_diagnostics_command"
    assert len(trace.sink_hits) == 1
    assert trace.sink_hits[0].field == "diagnostics_command"
    assert trace.sink_hits[0].sink == SinkCategory.SUBPROCESS


def test_traces_clean_example_network():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader_network.py"))
    assert trace.function_name == "ping_healthcheck"
    [hit] = trace.sink_hits
    assert hit.field == "healthcheck_url"
    assert hit.sink == SinkCategory.NETWORK


def test_traces_clean_example_template():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader_template.py"))
    assert trace.function_name == "render_welcome"
    [hit] = trace.sink_hits
    assert hit.field == "welcome_template"
    assert hit.sink == SinkCategory.TEMPLATE_RENDER


def test_traces_clean_example_sanitized_path():
    [trace] = CapabilityTracer().trace_file(str(EXAMPLES_DIR / "clean_loader_sanitized_path.py"))
    assert trace.function_name == "load_named_config"
    [hit] = trace.sink_hits
    assert hit.field == "config_name"
    assert hit.sink == SinkCategory.FILE_READ


# --- Adversarial-input hardening ---
#
# These feed the tracer deliberately pathological *shapes* of input (very
# deep nesting, a huge generated file, a long alias chain) to confirm it
# fails with a clear, specific exception -- not a hang, not an uncontrolled
# RecursionError/MemoryError/crash. None of this resembles a real disclosed
# exploit; it's about capaudit's own robustness as a static-analysis tool
# that has to parse source it doesn't control.


def test_source_larger_than_configured_limit_is_rejected_before_parsing():
    tracer = CapabilityTracer(max_source_bytes=100)
    with pytest.raises(SourceTooLargeError):
        tracer.trace_source("# " + ("x" * 200) + "\n")


def test_source_at_or_under_the_limit_is_not_rejected():
    tracer = CapabilityTracer(max_source_bytes=1000)
    assert tracer.trace_source("x = 1\n") == []


def test_a_genuinely_huge_generated_file_is_rejected_by_the_default_limit():
    # ~6 MB of harmless, syntactically valid Python -- past the real
    # default limit, not just a threshold lowered for this test.
    huge_source = "x = 1\n" * 1_000_000
    with pytest.raises(SourceTooLargeError):
        CapabilityTracer().trace_source(huge_source)


def test_parse_timeout_raises_when_parsing_is_too_slow():
    def _slow_parse(source, filename=None):
        time.sleep(0.3)
        return ast.parse(source, filename=filename)

    with pytest.raises(ParseTimeoutError):
        _parse_with_timeout("x = 1", "<test>", timeout_seconds=0.05, parse_fn=_slow_parse)


def test_parse_timeout_does_not_fire_for_a_fast_parse():
    tree = _parse_with_timeout("x = 1", "<test>", timeout_seconds=5.0)
    assert isinstance(tree, ast.Module)


def test_capability_tracer_surfaces_a_parse_timeout(monkeypatch):
    def _slow_parse(source, filename=None):
        time.sleep(0.3)
        return ast.parse(source, filename=filename)

    monkeypatch.setattr("capaudit.tracer.ast.parse", _slow_parse)
    tracer = CapabilityTracer(parse_timeout_seconds=0.05)
    with pytest.raises(ParseTimeoutError):
        tracer.trace_source("x = 1")


def test_deeply_nested_attribute_chain_is_rejected_not_crashed():
    # a.b.b.b...() -- a pathologically deep attribute-access chain as a
    # call target, well past any real code's nesting.
    chain = "a" + (".b" * 500)
    source = f"""
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"x": Capability.OPAQUE_STRING}})

@SCHEMA.bind
def load(config):
    return {chain}(config["x"])
"""
    with pytest.raises(TraceDepthExceededError):
        CapabilityTracer().trace_source(source)


def test_deeply_nested_string_concatenation_is_rejected_not_crashed():
    # config["x"] + config["x"] + ... -- a left-nested BinOp chain deep
    # enough to exceed the expression-nesting guard.
    chain = " + ".join(['config["x"]'] * 500)
    source = f"""
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"x": Capability.OPAQUE_STRING}})

@SCHEMA.bind
def load(config):
    return open({chain})
"""
    with pytest.raises(TraceDepthExceededError):
        CapabilityTracer().trace_source(source)


def test_extremely_long_reverse_ordered_alias_chain_is_rejected_not_hung():
    # Declared in reverse dependency order (x[i] = x[i-1] appears *before*
    # x[i-1] is itself resolved), which forces the alias-map fixed point to
    # propagate one step per outer pass -- the actual worst case for this
    # analysis, not a chain that happens to resolve in a single pass.
    n = 1100
    lines = [f"x{i} = x{i - 1}" for i in range(n, 0, -1)]
    lines.append('x0 = config["field"]')
    body = "\n    ".join(lines)
    source = f"""
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"field": Capability.OPAQUE_STRING}})

@SCHEMA.bind
def load(config):
    {body}
    return open(x{n})
"""
    with pytest.raises(TraceDepthExceededError):
        CapabilityTracer().trace_source(source)


def test_normal_short_alias_chain_is_unaffected_by_the_iteration_guard():
    # Regression check: the guard added above must not touch ordinary,
    # short alias chains like the ones already exercised elsewhere in this
    # file (e.g. test_multi_hop_alias_chain_is_traced).
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    a = config["offset"]
    b = a
    c = b
    return open(c)
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.field == "offset"


# --- Coverage: parser robustness on malformed/unusual (but syntactically
# valid) source ---
#
# These found via `pytest --cov=capaudit.tracer --cov-report=term-missing`:
# every branch below is a real, reachable defensive path -- "give up
# gracefully and treat this as not a schema/loader" -- that no well-formed
# example ever exercises. None of them are dead code; each is pinned down
# with a test rather than left unexercised.


def test_check_path_size_ignores_a_path_that_cannot_be_stat_ed():
    # OSError from os.path.getsize (e.g. the path doesn't exist) is
    # swallowed -- the subsequent open()/read() is left to raise its own,
    # more specific error.
    check_path_size("/no/such/path/at/all", max_bytes=10)  # must not raise


def test_parse_with_timeout_disabled_via_non_positive_timeout():
    tree = _parse_with_timeout("x = 1", "<test>", timeout_seconds=0)
    assert isinstance(tree, ast.Module)


def test_parse_with_timeout_falls_back_when_sigalrm_is_unavailable(monkeypatch):
    import signal

    monkeypatch.delattr(signal, "SIGALRM", raising=False)
    tree = _parse_with_timeout("x = 1", "<test>", timeout_seconds=5.0)
    assert isinstance(tree, ast.Module)


def test_parse_with_timeout_falls_back_when_signal_signal_raises_value_error(monkeypatch):
    import signal

    def _raise(*args, **kwargs):
        raise ValueError("signal only works in main thread of the main interpreter")

    monkeypatch.setattr(signal, "signal", _raise)
    tree = _parse_with_timeout("x = 1", "<test>", timeout_seconds=5.0)
    assert isinstance(tree, ast.Module)


def test_dynamic_dict_key_is_not_treated_as_a_field_access():
    # config[some_variable] -- a non-literal subscript -- must not resolve
    # to any field; _string_constant's fallback for a non-Constant node.
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    key = "offset"
    return open(config[key])
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    assert trace.joint_sink_hits == ()


def test_open_mode_passed_as_a_keyword_argument_is_still_recognized():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"path": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["path"], mode="w")
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.sink == SinkCategory.FILE_WRITE


def test_multi_alias_map_iteration_cap_is_enforced_independently():
    # Mirrors test_extremely_long_reverse_ordered_alias_chain_is_rejected_
    # not_hung, but every hop is a *compound* expression (os.path.join),
    # so _build_alias_map never captures any of it and the full fixed-point
    # burden falls on _build_multi_alias_map's own iteration cap.
    n = 1100
    lines = [f'y{i} = os.path.join(y{i - 1}, "x")' for i in range(n, 0, -1)]
    lines.append('y0 = os.path.join(config["field"], "x")')
    body = "\n    ".join(lines)
    source = f"""
import os
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"field": Capability.OPAQUE_STRING}})

@SCHEMA.bind
def load(config):
    {body}
    return open(y{n})
"""
    with pytest.raises(TraceDepthExceededError):
        _trace_source(source)


def test_bound_loader_with_no_parameters_yields_an_empty_trace():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load():
    return 1
"""
    [trace] = _trace_source(source)
    assert trace.sink_hits == ()
    assert trace.joint_sink_hits == ()
    assert trace.undeclared_fields_used == ()


# --- Coverage: malformed CapabilitySchema(...)/JointCapability(...)
# declarations are treated as "no schema found", not a crash ---


def test_schema_assignment_calling_something_else_is_ignored():
    source = """
class NotASchema:
    def __init__(self, fields):
        pass

OTHER = NotASchema({"x": 1})

def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_schema_call_with_no_positional_dict_argument_is_ignored():
    source = """
from capaudit.schema import CapabilitySchema

SCHEMA = CapabilitySchema()

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_schema_dict_with_a_non_string_key_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({1: Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config[1])
"""
    assert _trace_source(source) == []


def test_schema_dict_with_an_unknown_capability_name_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"x": Capability.NOT_A_REAL_CAPABILITY})

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_schema_dict_with_a_non_capability_value_is_ignored():
    source = """
from capaudit.schema import CapabilitySchema

SCHEMA = CapabilitySchema({"x": "numeric"})

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_schema_with_an_unrelated_keyword_argument_is_still_parsed():
    # _find_schema_vars only ever looks for a `joint=` keyword; any other
    # keyword argument to CapabilitySchema(...) is simply not inspected,
    # not treated as making the whole declaration unparseable.
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"x": Capability.NUMERIC}, some_other_kwarg=123)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    [trace] = _trace_source(source)
    [hit] = trace.sink_hits
    assert hit.field == "x"


def test_joint_keyword_that_is_not_a_list_or_tuple_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"x": Capability.NUMERIC, "y": Capability.NUMERIC}, joint=SOME_NAME)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_list_element_that_is_not_a_call_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC}, joint=["not_a_call"]
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_list_element_calling_something_other_than_joint_capability_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC},
    joint=[SomeOtherCall(fields={"x", "y"}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_capability_call_missing_an_argument_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC},
    joint=[JointCapability(fields={"x", "y"})],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_capability_call_with_capability_not_shaped_as_an_attribute_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SOME_VAR = 1

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC},
    joint=[JointCapability(fields={"x", "y"}, capability=SOME_VAR)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_capability_fields_not_a_collection_literal_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC},
    joint=[JointCapability(fields="not_a_set", capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_capability_fields_with_a_non_string_element_is_ignored():
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC, "y": Capability.NUMERIC},
    joint=[JointCapability(fields={1, 2}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_capability_with_fewer_than_two_fields_is_ignored():
    # Syntactically fine, but JointCapability's own __post_init__ rejects a
    # single-field rule -- the ValueError is caught, not propagated.
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC},
    joint=[JointCapability(fields={"x"}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []


def test_joint_rule_referencing_an_undeclared_field_is_ignored_not_crashed():
    # Syntactically fine at every level, but semantically invalid once
    # CapabilitySchema itself validates it (UnknownFieldError) -- the whole
    # schema is treated as unparseable rather than the tracer crashing.
    source = """
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"x": Capability.NUMERIC},
    joint=[JointCapability(fields={"x", "y"}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(config["x"])
"""
    assert _trace_source(source) == []
