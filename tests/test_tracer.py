from pathlib import Path

from capaudit.schema import Capability, SinkCategory
from capaudit.tracer import CapabilityTracer

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
