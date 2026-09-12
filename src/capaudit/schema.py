"""Capability schema: declares what a config field is allowed to be used for.

A `CapabilitySchema` maps each config field name to a `Capability` — the
*maximum* power that field is declared to have. The static tracer (later
steps) determines which `SinkCategory` a field's value actually reaches in
the loader code. A field is flagged when it reaches a sink category not
present in its declared capability's `ALLOWED_SINKS` entry.

This module is data-only: `Capability`, `SinkCategory`, and `ALLOWED_SINKS`
are also the vocabulary the AST tracer and mismatch checker (steps 4-5) are
built against, so the sink taxonomy lives here rather than being duplicated.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

F = TypeVar("F", bound=Callable)


class Capability(Enum):
    """The declared capability of a config field, from least to most powerful."""

    NONE = "none"
    """Field must not be consumed at all — reaching any sink is a mismatch."""

    NUMERIC = "numeric"
    """An int/float used only as a number (e.g. an offset, size, count)."""

    ENUM = "enum"
    """A string constrained to a fixed set of literal choices."""

    OPAQUE_STRING = "opaque_string"
    """A string used only as an inert label or identifier — never
    interpreted as a path, command, template, or address."""

    FILE_PATH = "file_path"
    """A string legitimately used to open/read/write a file."""

    TEMPLATE = "template"
    """A string legitimately rendered as a template (e.g. Jinja2)."""

    COMMAND = "command"
    """A string legitimately passed to a subprocess/shell invocation."""

    NETWORK_ADDRESS = "network_address"
    """A string/tuple legitimately used as a network destination."""


class SinkCategory(Enum):
    """A category of dangerous operation the tracer looks for as a
    destination of a config field's value."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    CODE_EXEC = "code_exec"
    TEMPLATE_RENDER = "template_render"
    SUBPROCESS = "subprocess"
    NETWORK = "network"


# The set of sink categories each capability is permitted to reach. A
# capability not listed here, or a sink category absent from its set, means
# reaching that sink is a mismatch and should be flagged.
#
# NOTE: CODE_EXEC (eval/exec/compile) has no corresponding Capability — no
# v1 schema declaration legitimizes a config field reaching direct code
# execution, so it is never in an allowed set.
ALLOWED_SINKS: dict[Capability, frozenset[SinkCategory]] = {
    Capability.NONE: frozenset(),
    Capability.NUMERIC: frozenset(),
    Capability.ENUM: frozenset(),
    Capability.OPAQUE_STRING: frozenset(),
    Capability.FILE_PATH: frozenset({SinkCategory.FILE_READ, SinkCategory.FILE_WRITE}),
    Capability.TEMPLATE: frozenset({SinkCategory.TEMPLATE_RENDER}),
    Capability.COMMAND: frozenset({SinkCategory.SUBPROCESS}),
    Capability.NETWORK_ADDRESS: frozenset({SinkCategory.NETWORK}),
}


class UnknownFieldError(KeyError):
    """Raised when a schema is asked about a field it does not declare."""


@dataclass(frozen=True)
class JointCapability:
    """Declares that a specific combination of two or more fields, used
    *together*, is allowed to reach the sinks in `capability`'s
    `ALLOWED_SINKS` entry — even though none of those fields' own declared
    (per-field) capabilities would permit it alone.

    This models real bugs where individually-innocuous fields compose into
    something more powerful: e.g. a `base_dir` field and a `filename` field,
    each a plain opaque string on their own, become a path-traversal
    primitive the moment a loader does
    `open(os.path.join(base_dir, filename))`. A schema can legitimize that
    exact combination by declaring
    `JointCapability(fields={"base_dir", "filename"}, capability=Capability.FILE_PATH)`
    — reusing the existing `Capability` vocabulary rather than introducing a
    separate one, since "what sinks can this reach" is the same question for
    a joint combination as it is for a single field.

    `fields` names the *exact* combination the rule covers — a rule for
    `{"base_dir", "filename"}` does not also cover a sink additionally fed by
    a third field. See docs/capability-schema.md for the current matching
    rules and limits.
    """

    fields: frozenset[str]
    capability: Capability

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", frozenset(self.fields))
        if len(self.fields) < 2:
            raise ValueError(
                "a JointCapability rule must name 2 or more fields, got "
                f"{sorted(self.fields)!r}"
            )


class CapabilitySchema:
    """Maps config field names to their declared `Capability`, plus
    (optionally) a set of `JointCapability` rules for field combinations.

    Usage::

        SCHEMA = CapabilitySchema({
            "offset": Capability.NUMERIC,
            "dataset_name": Capability.OPAQUE_STRING,
        })

        @SCHEMA.bind
        def load_dataset_config(config: dict):
            ...

    `bind` is a no-op at runtime beyond attaching metadata to the function;
    capaudit's static analyzer discovers the schema-to-loader association by
    parsing the `@SCHEMA.bind` decorator syntactically, not by importing or
    executing the module under analysis.

    The optional `joint` argument is purely additive: a schema built without
    it behaves exactly as before, and every field named in a `JointCapability`
    rule must also be declared (individually) in `fields`, so per-field
    coverage-gap detection is unaffected.
    """

    def __init__(
        self,
        fields: dict[str, Capability],
        joint: Sequence[JointCapability] = (),
    ):
        for name, capability in fields.items():
            if not isinstance(capability, Capability):
                raise TypeError(
                    f"field {name!r}: expected a Capability, got {capability!r}"
                )
        self.fields: dict[str, Capability] = dict(fields)

        for rule in joint:
            if not isinstance(rule, JointCapability):
                raise TypeError(f"expected a JointCapability, got {rule!r}")
            unknown = rule.fields - self.fields.keys()
            if unknown:
                raise UnknownFieldError(
                    "joint capability rule references field(s) not declared "
                    f"in this schema: {sorted(unknown)!r}"
                )
        self.joint_rules: tuple[JointCapability, ...] = tuple(joint)

    def bind(self, func: F) -> F:
        func.__capaudit_schema__ = self  # type: ignore[attr-defined]
        return func

    def capability_of(self, field_name: str) -> Capability:
        try:
            return self.fields[field_name]
        except KeyError:
            raise UnknownFieldError(
                f"field {field_name!r} is not declared in this schema"
            ) from None

    def allowed_sinks(self, field_name: str) -> frozenset[SinkCategory]:
        return ALLOWED_SINKS[self.capability_of(field_name)]

    def is_allowed(self, field_name: str, sink: SinkCategory) -> bool:
        return sink in self.allowed_sinks(field_name)

    def joint_allowed_sinks(self, fields: frozenset[str]) -> frozenset[SinkCategory]:
        """Sinks allowed when exactly this set of fields jointly reaches a
        sink, per any declared `JointCapability` rule for that exact
        combination. Empty if no rule covers it — including when a rule
        exists for a subset or superset of `fields` but not this exact set."""
        fields = frozenset(fields)
        for rule in self.joint_rules:
            if rule.fields == fields:
                return ALLOWED_SINKS[rule.capability]
        return frozenset()

    def is_joint_allowed(self, fields: frozenset[str], sink: SinkCategory) -> bool:
        return sink in self.joint_allowed_sinks(fields)
