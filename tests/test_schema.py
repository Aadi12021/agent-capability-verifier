import pytest

from capaudit.schema import (
    ALLOWED_SINKS,
    Capability,
    CapabilitySchema,
    SinkCategory,
    UnknownFieldError,
)


def test_every_capability_has_an_allowed_sinks_entry():
    assert set(ALLOWED_SINKS.keys()) == set(Capability)


def test_narrow_capabilities_allow_no_sinks():
    for capability in (Capability.NONE, Capability.NUMERIC, Capability.ENUM,
                       Capability.OPAQUE_STRING):
        assert ALLOWED_SINKS[capability] == frozenset()


def test_code_exec_is_never_an_allowed_sink():
    for sinks in ALLOWED_SINKS.values():
        assert SinkCategory.CODE_EXEC not in sinks


def test_file_path_allows_file_read_and_write_only():
    assert ALLOWED_SINKS[Capability.FILE_PATH] == frozenset(
        {SinkCategory.FILE_READ, SinkCategory.FILE_WRITE}
    )


def test_schema_rejects_non_capability_values():
    with pytest.raises(TypeError):
        CapabilitySchema({"offset": "numeric"})


def test_capability_of_known_field():
    schema = CapabilitySchema({"offset": Capability.NUMERIC})
    assert schema.capability_of("offset") is Capability.NUMERIC


def test_capability_of_unknown_field_raises():
    schema = CapabilitySchema({"offset": Capability.NUMERIC})
    with pytest.raises(UnknownFieldError):
        schema.capability_of("path")


def test_allowed_sinks_reflects_declared_capability():
    schema = CapabilitySchema({"template_name": Capability.TEMPLATE})
    assert schema.allowed_sinks("template_name") == frozenset(
        {SinkCategory.TEMPLATE_RENDER}
    )


def test_is_allowed_true_and_false_cases():
    schema = CapabilitySchema({
        "offset": Capability.NUMERIC,
        "path": Capability.FILE_PATH,
    })
    assert schema.is_allowed("path", SinkCategory.FILE_READ) is True
    assert schema.is_allowed("offset", SinkCategory.FILE_READ) is False


def test_bind_attaches_schema_to_function_and_returns_it():
    schema = CapabilitySchema({"offset": Capability.NUMERIC})

    @schema.bind
    def load(config):
        return config

    assert load.__capaudit_schema__ is schema
    assert load({"offset": 1}) == {"offset": 1}
