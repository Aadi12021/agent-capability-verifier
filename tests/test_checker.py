from pathlib import Path

from capaudit.checker import check_file, check_source
from capaudit.schema import Capability, SinkCategory

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
