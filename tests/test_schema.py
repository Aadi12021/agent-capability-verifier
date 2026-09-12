import pytest

from capaudit.schema import (
    ALLOWED_SINKS,
    Capability,
    CapabilitySchema,
    JointCapability,
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


# --- JointCapability / joint rules ---


def test_joint_capability_requires_two_or_more_fields():
    with pytest.raises(ValueError):
        JointCapability(fields={"only_one"}, capability=Capability.FILE_PATH)


def test_joint_capability_normalizes_fields_to_a_frozenset():
    rule = JointCapability(fields=["base_dir", "filename"], capability=Capability.FILE_PATH)
    assert rule.fields == frozenset({"base_dir", "filename"})


def test_schema_without_joint_argument_behaves_exactly_as_before():
    schema = CapabilitySchema({"offset": Capability.NUMERIC})
    assert schema.joint_rules == ()
    assert schema.joint_allowed_sinks(frozenset({"offset"})) == frozenset()


def test_schema_rejects_joint_rule_referencing_undeclared_field():
    with pytest.raises(UnknownFieldError):
        CapabilitySchema(
            {"base_dir": Capability.OPAQUE_STRING},
            joint=[
                JointCapability(
                    fields={"base_dir", "filename"}, capability=Capability.FILE_PATH
                )
            ],
        )


def test_schema_rejects_non_joint_capability_values_in_joint_list():
    with pytest.raises(TypeError):
        CapabilitySchema(
            {"base_dir": Capability.OPAQUE_STRING, "filename": Capability.OPAQUE_STRING},
            joint=[("base_dir", "filename")],  # type: ignore[list-item]
        )


def test_joint_allowed_sinks_matches_exact_field_set():
    schema = CapabilitySchema(
        {"base_dir": Capability.OPAQUE_STRING, "filename": Capability.OPAQUE_STRING},
        joint=[JointCapability(fields={"base_dir", "filename"}, capability=Capability.FILE_PATH)],
    )
    assert schema.joint_allowed_sinks(frozenset({"base_dir", "filename"})) == frozenset(
        {SinkCategory.FILE_READ, SinkCategory.FILE_WRITE}
    )
    fields = frozenset({"base_dir", "filename"})
    assert schema.is_joint_allowed(fields, SinkCategory.FILE_READ) is True


def test_joint_allowed_sinks_empty_when_no_rule_declared():
    schema = CapabilitySchema(
        {"base_dir": Capability.OPAQUE_STRING, "filename": Capability.OPAQUE_STRING}
    )
    fields = frozenset({"base_dir", "filename"})
    assert schema.joint_allowed_sinks(fields) == frozenset()
    assert schema.is_joint_allowed(fields, SinkCategory.FILE_READ) is False


def test_joint_rule_does_not_match_a_superset_or_subset_field_combination():
    schema = CapabilitySchema(
        {
            "a": Capability.OPAQUE_STRING,
            "b": Capability.OPAQUE_STRING,
            "c": Capability.OPAQUE_STRING,
        },
        joint=[JointCapability(fields={"a", "b"}, capability=Capability.FILE_PATH)],
    )
    assert schema.is_joint_allowed(frozenset({"a", "b", "c"}), SinkCategory.FILE_READ) is False
    assert schema.is_joint_allowed(frozenset({"a"}), SinkCategory.FILE_READ) is False
    assert schema.is_joint_allowed(frozenset({"a", "b"}), SinkCategory.FILE_READ) is True
