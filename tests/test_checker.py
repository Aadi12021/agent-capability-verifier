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
