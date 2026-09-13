"""Mutation testing: takes the underlying vulnerabilities in existing
example loaders and re-expresses them with a different surface structure
-- renamed variables, an added layer of indirection, reordered statements,
or a different-but-equivalent way of constructing the same sink call --
while preserving the exact same declared-vs-actual capability mismatch.

The checker should still flag every mutant. A mutant that slips through
uncaught is a real brittleness finding in the tracer's pattern matching,
not a new vulnerability class -- see the "KNOWN GAP" tests below for ones
this actually found. None of these mutate toward, or resemble, any real
disclosed exploit; they're structural variations on this project's own
original toy examples.

`vulnerable_loader_12_helper_function_undetected.py` is deliberately
excluded from mutation here: it's already a documented, pinned-down miss
(see test_checker.py), so mutating it wouldn't test anything -- the base
case already isn't flagged.
"""

from capaudit.checker import check_source


def _has_mismatch(source: str) -> bool:
    result = check_source(source)
    return bool(result.mismatches or result.joint_mismatches)


# --- Renamed variables ---


def test_mutant_renamed_variables_vulnerable_loader_1_path():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "offset": Capability.NUMERIC,
    "record_count": Capability.NUMERIC,
})

@SCHEMA.bind
def load_record_index(config: dict):
    byte_offset = config["offset"]
    num_records = config["record_count"]
    with open(byte_offset) as blob:
        blob.seek(0)
        return blob.read(num_records)
"""
    assert _has_mismatch(source)


def test_mutant_renamed_variable_vulnerable_loader_6_write():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"report_label": Capability.OPAQUE_STRING})

@SCHEMA.bind
def write_report_stub(config: dict):
    output_path = config["report_label"]
    with open(output_path, "w") as f:
        f.write("report generated\\n")
"""
    assert _has_mismatch(source)


# --- Added indirection (extra alias hops) ---


def test_mutant_added_indirection_vulnerable_loader_7_numeric_subprocess():
    source = """
import subprocess
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"worker_id": Capability.NUMERIC})

@SCHEMA.bind
def spawn_worker(config: dict):
    worker_id = config["worker_id"]
    wid = worker_id
    subprocess.run(["worker-agent", "--id", wid], check=True)
"""
    assert _has_mismatch(source)


def test_mutant_two_extra_alias_hops_vulnerable_loader_10_reassigned_alias():
    source = """
import subprocess
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"backup_target": Capability.OPAQUE_STRING})

@SCHEMA.bind
def run_backup(config: dict):
    backup_target = config["backup_target"]
    step1 = backup_target
    profile = step1
    subprocess.run(["backup-tool", "--profile", profile], check=True)
"""
    assert _has_mismatch(source)


def test_mutant_indirection_through_a_compound_alias_vulnerable_loader_9():
    # The f-string is built in its own variable first, one extra hop
    # removed from the sink call, instead of inline inside Template(...).
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"widget_id": Capability.NUMERIC})

@SCHEMA.bind
def render_widget_snippet(config: dict):
    widget_id = config["widget_id"]
    snippet_source = f"widget_{widget_id}"
    return Template(snippet_source).render()
"""
    assert _has_mismatch(source)


# --- Reordered statements ---


def test_mutant_reordered_statements_vulnerable_loader_5_none_field():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "dataset_name": Capability.OPAQUE_STRING,
    "debug_dump_path": Capability.NONE,
})

@SCHEMA.bind
def load_dataset_metadata(config: dict):
    debug_dump_path = config["debug_dump_path"]
    dataset_name = config["dataset_name"]
    with open(debug_dump_path, "w") as f:
        f.write(f"loaded dataset: {dataset_name}\\n")
    return {"dataset_name": dataset_name}
"""
    assert _has_mismatch(source)


def test_mutant_reordered_statements_vulnerable_loader_11_conditional_branch():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "legacy_mode": Capability.OPAQUE_STRING,
    "use_legacy_renderer": Capability.NUMERIC,
})

@SCHEMA.bind
def render_report(config: dict):
    use_legacy_renderer = config["use_legacy_renderer"]
    legacy_mode = config["legacy_mode"]
    if use_legacy_renderer:
        return Template(legacy_mode).render()
    return {"mode": legacy_mode}
"""
    assert _has_mismatch(source)


# --- Different but equivalent sink construction ---


def test_mutant_template_via_intermediate_variable_vulnerable_loader_2():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"greeting_name": Capability.OPAQUE_STRING})

@SCHEMA.bind
def render_welcome_message(config: dict):
    greeting_name = config["greeting_name"]
    tmpl = Template(greeting_name)
    return tmpl.render()
"""
    assert _has_mismatch(source)


def test_mutant_fstring_instead_of_os_path_join_vulnerable_loader_4():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({
    "plugin_dir": Capability.OPAQUE_STRING,
    "asset_name": Capability.OPAQUE_STRING,
})

@SCHEMA.bind
def load_plugin_asset(config: dict):
    plugin_dir = config["plugin_dir"]
    asset_name = config["asset_name"]
    full_path = f"{plugin_dir}/{asset_name}"
    with open(full_path) as f:
        return f.read()
"""
    assert _has_mismatch(source)


def test_mutant_eval_via_intermediate_variable_vulnerable_loader_8():
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"calculation_mode": Capability.ENUM})

@SCHEMA.bind
def compute_summary(config: dict):
    calculation_mode = config["calculation_mode"]
    expr = calculation_mode
    return eval(expr)
"""
    assert _has_mismatch(source)


# --- KNOWN GAPS this mutation pass found: document, don't paper over ---
#
# Each of these preserves the exact same underlying mismatch as an already-
# detected example, re-expressed in a way that's common enough in real code
# (not a contrived evasion attempt) but that the tracer's pattern matching
# does not currently recognize. Filed as pinned-down, expected failures
# rather than silently dropped or "fixed" without discussion -- see the
# mutation-testing report for the reasoning.


def test_known_gap_subprocess_arg_list_built_in_a_variable():
    """_candidate_sink_args only expands a LIST LITERAL passed directly as
    the call argument (`subprocess.run([cmd, tainted])`); it does not
    resolve a bare variable that holds a list built one statement earlier
    (`args = [cmd, tainted]; subprocess.run(args)`) -- a completely
    ordinary refactor (extract a variable for readability) that currently
    defeats detection entirely."""
    source = """
import subprocess
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"log_level": Capability.ENUM})

@SCHEMA.bind
def run_diagnostics(config: dict):
    log_level = config["log_level"]
    args = ["diagnostics-tool", "--level", log_level]
    subprocess.run(args, check=True)
"""
    assert not _has_mismatch(source), (
        "if this now fails, the gap was fixed -- update this test (and the "
        "mutation-testing report) rather than reverting the fix"
    )


def test_known_gap_open_called_with_keyword_argument():
    """The `open` sink only inspects `call.args[:1]` (the first positional
    argument); `open(file=offset)` -- a keyword argument, valid Python and
    not unusual style -- has zero positional args, so the field is never
    checked at all."""
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load_record_index(config: dict):
    offset = config["offset"]
    return open(file=offset)
"""
    assert not _has_mismatch(source), (
        "if this now fails, the gap was fixed -- update this test (and the "
        "mutation-testing report) rather than reverting the fix"
    )


def test_known_gap_pathlib_open_method_not_recognized():
    """The Path-aware sink matching only recognizes
    `Path(...).read_text/write_text/read_bytes/write_bytes(...)`; it does
    not recognize `Path(...).open()`, an equally common, equally real way
    to open a file via pathlib."""
    source = """
from capaudit.schema import Capability, CapabilitySchema

SCHEMA = CapabilitySchema({"offset": Capability.NUMERIC})

@SCHEMA.bind
def load_record_index(config: dict):
    offset = config["offset"]
    return Path(offset).open()
"""
    assert not _has_mismatch(source), (
        "if this now fails, the gap was fixed -- update this test (and the "
        "mutation-testing report) rather than reverting the fix"
    )
