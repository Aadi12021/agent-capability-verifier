from pathlib import Path

import pytest

from capaudit.checker import check_file, check_source
from capaudit.schema import Capability, SinkCategory
from capaudit.tracer import SourceTooLargeError, TraceDepthExceededError

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_numeric_field_reaching_open_is_a_mismatch():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["offset"])
"""
    result = check_source(source)
    assert result.has_mismatches
    [mismatch] = result.mismatches
    assert mismatch.field == "offset"
    assert mismatch.declared == Capability.NUMERIC
    assert mismatch.actual_sink == SinkCategory.FILE_READ
    assert result.coverage_gaps == ()


def test_file_path_field_reaching_open_is_not_a_mismatch():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"path": Capability.FILE_PATH})

@SCHEMA.bind
def load(config):
    return open(config["path"])
"""
    result = check_source(source)
    assert result.mismatches == ()


def test_code_exec_is_always_a_mismatch_even_for_no_declared_capability_allows_it():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"expr": Capability.TEMPLATE})

@SCHEMA.bind
def load(config):
    eval(config["expr"])
"""
    result = check_source(source)
    assert result.has_mismatches
    assert result.mismatches[0].actual_sink == SinkCategory.CODE_EXEC


def test_undeclared_field_is_a_coverage_gap_not_a_mismatch():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    offset = config["offset"]
    mystery = config["mystery"]
    return offset, mystery
"""
    result = check_source(source)
    assert result.mismatches == ()
    assert len(result.coverage_gaps) == 1
    assert result.coverage_gaps[0].field == "mystery"


def test_mismatch_describe_is_human_readable():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load(config):
    return open(config["offset"])
"""
    [mismatch] = check_source(source).mismatches
    text = mismatch.describe()
    assert "offset" in text
    assert "numeric" in text
    assert "file_read" in text


# --- JointMismatch: sinks reached via a combination of fields ---


def test_joint_fields_reaching_a_sink_without_a_joint_rule_is_a_joint_mismatch():
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
    result = check_source(source)
    assert result.mismatches == ()  # neither field alone is ever "the" field reaching open()
    assert result.coverage_gaps == ()  # both fields are declared, just not their combination
    assert len(result.joint_mismatches) == 1
    [jm] = result.joint_mismatches
    assert jm.fields == frozenset({"base_dir", "filename"})
    assert jm.actual_sink == SinkCategory.FILE_READ
    assert jm.declared == {
        "base_dir": Capability.OPAQUE_STRING,
        "filename": Capability.OPAQUE_STRING,
    }


def test_declared_joint_rule_legitimizes_the_combination():
    source = """
import os
from capaudit.schema import Capability, CapabilitySchema, JointCapability

SCHEMA = CapabilitySchema(
    {"base_dir": Capability.OPAQUE_STRING, "filename": Capability.OPAQUE_STRING},
    joint=[JointCapability(fields={"base_dir", "filename"}, capability=Capability.FILE_PATH)],
)

@SCHEMA.bind
def load(config):
    return open(os.path.join(config["base_dir"], config["filename"]))
"""
    result = check_source(source)
    assert result.mismatches == ()
    assert result.joint_mismatches == ()


def test_joint_mismatch_describe_is_human_readable():
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
    [jm] = check_source(source).joint_mismatches
    text = jm.describe()
    assert "base_dir" in text
    assert "filename" in text
    assert "file_read" in text


# --- Integration: the plan's core acceptance criterion ---
# the checker must flag every vulnerable example and stay silent on the
# clean one.

def test_flags_vulnerable_example_1_path():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_1_path.py"))
    assert result.has_mismatches
    assert any(m.field == "offset" and m.actual_sink == SinkCategory.FILE_READ
               for m in result.mismatches)


def test_flags_vulnerable_example_2_template():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_2_template.py"))
    assert result.has_mismatches
    assert any(m.field == "greeting_name" and m.actual_sink == SinkCategory.TEMPLATE_RENDER
               for m in result.mismatches)


def test_flags_vulnerable_example_3_subprocess():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_3_subprocess.py"))
    assert result.has_mismatches
    assert any(m.field == "log_level" and m.actual_sink == SinkCategory.SUBPROCESS
               for m in result.mismatches)


def test_stays_silent_on_clean_example():
    result = check_file(str(EXAMPLES_DIR / "clean_loader.py"))
    assert result.mismatches == ()
    assert result.coverage_gaps == ()


def test_flags_vulnerable_example_4_joint_path():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_4_joint_path.py"))
    assert result.mismatches == ()
    assert result.coverage_gaps == ()
    assert len(result.joint_mismatches) == 1
    [jm] = result.joint_mismatches
    assert jm.fields == frozenset({"plugin_dir", "asset_name"})
    assert jm.actual_sink == SinkCategory.FILE_READ


def test_stays_silent_on_clean_example_joint_path():
    result = check_file(str(EXAMPLES_DIR / "clean_loader_joint_path.py"))
    assert result.mismatches == ()
    assert result.joint_mismatches == ()
    assert result.coverage_gaps == ()


def test_v1_single_field_view_misses_the_joint_example_but_v2_catches_it():
    """The concrete before/after this feature adds: a consumer that only
    ever looked at `result.mismatches` -- the entirety of what v1's checker
    exposed -- sees nothing wrong with vulnerable_loader_4_joint_path.py.
    `result.joint_mismatches`, added in v2, does. Same file, same checker
    run; the only difference is which fields of CheckResult get read."""
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_4_joint_path.py"))

    v1_view_flags_it = result.has_mismatches
    v2_view_flags_it = result.has_mismatches or result.has_joint_mismatches

    assert v1_view_flags_it is False
    assert v2_view_flags_it is True


def test_flags_vulnerable_example_5_none_field():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_5_none_field.py"))
    assert result.has_mismatches
    assert any(m.field == "debug_dump_path" and m.declared == Capability.NONE
               and m.actual_sink == SinkCategory.FILE_WRITE for m in result.mismatches)


def test_flags_vulnerable_example_6_write():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_6_write.py"))
    assert result.has_mismatches
    assert any(m.field == "report_label" and m.actual_sink == SinkCategory.FILE_WRITE
               for m in result.mismatches)


def test_flags_vulnerable_example_7_numeric_subprocess():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_7_numeric_subprocess.py"))
    assert result.has_mismatches
    assert any(m.field == "worker_id" and m.declared == Capability.NUMERIC
               and m.actual_sink == SinkCategory.SUBPROCESS for m in result.mismatches)


def test_flags_vulnerable_example_8_enum_eval():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_8_enum_eval.py"))
    assert result.has_mismatches
    assert any(m.field == "calculation_mode" and m.actual_sink == SinkCategory.CODE_EXEC
               for m in result.mismatches)


def test_flags_vulnerable_example_9_numeric_template_fstring():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_9_numeric_template_fstring.py"))
    assert result.has_mismatches
    assert result.joint_mismatches == ()
    assert any(m.field == "widget_id" and m.declared == Capability.NUMERIC
               and m.actual_sink == SinkCategory.TEMPLATE_RENDER for m in result.mismatches)


def test_flags_vulnerable_example_10_reassigned_alias():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_10_reassigned_alias.py"))
    assert result.has_mismatches
    assert any(m.field == "backup_target" and m.actual_sink == SinkCategory.SUBPROCESS
               for m in result.mismatches)


def test_flags_vulnerable_example_11_conditional_branch():
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_11_conditional_branch.py"))
    assert result.has_mismatches
    assert any(m.field == "legacy_mode" and m.actual_sink == SinkCategory.TEMPLATE_RENDER
               for m in result.mismatches)


def test_vulnerable_example_12_helper_function_is_a_documented_known_gap():
    """Pinned-down known limitation, not a passing test of detection: this
    file has a real file-write mismatch that capaudit currently cannot see
    because the sink is behind a plain helper-function call, and this
    project does no interprocedural analysis. If this test ever starts
    failing because the checker *does* flag it, that's good news -- update
    this test (and the file's docstring / examples/README.md) rather than
    treating the failure as a regression."""
    result = check_file(str(EXAMPLES_DIR / "vulnerable_loader_12_helper_function_undetected.py"))
    assert result.mismatches == ()
    assert result.joint_mismatches == ()
    assert result.coverage_gaps == ()


def test_stays_silent_on_clean_example_command():
    result = check_file(str(EXAMPLES_DIR / "clean_loader_command.py"))
    assert result.mismatches == ()
    assert result.joint_mismatches == ()
    assert result.coverage_gaps == ()


def test_stays_silent_on_clean_example_network():
    result = check_file(str(EXAMPLES_DIR / "clean_loader_network.py"))
    assert result.mismatches == ()
    assert result.coverage_gaps == ()


def test_stays_silent_on_clean_example_template():
    result = check_file(str(EXAMPLES_DIR / "clean_loader_template.py"))
    assert result.mismatches == ()
    assert result.coverage_gaps == ()


def test_stays_silent_on_clean_example_sanitized_path():
    result = check_file(str(EXAMPLES_DIR / "clean_loader_sanitized_path.py"))
    assert result.mismatches == ()
    assert result.coverage_gaps == ()


# --- Adversarial-input hardening, at the checker's public API ---


def test_check_source_respects_a_custom_max_source_bytes():
    with pytest.raises(SourceTooLargeError):
        check_source("x = 1\n" * 100, max_source_bytes=50)


def test_check_file_rejects_an_oversized_file(tmp_path):
    module = tmp_path / "huge.py"
    module.write_text("x = 1\n" * 1_000_000)  # ~6 MB, over the 5 MB default
    with pytest.raises(SourceTooLargeError):
        check_file(str(module))


def test_check_source_surfaces_a_trace_depth_error_gracefully():
    chain = "a" + (".b" * 500)
    source = f"""
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({{"x": Capability.OPAQUE_STRING}})

@SCHEMA.bind
def load(config):
    return {chain}(config["x"])
"""
    with pytest.raises(TraceDepthExceededError):
        check_source(source)
