"""Mismatch checker: compares each traced sink hit against what the field's
declared Capability actually allows, and separately surfaces config fields a
loader reads that its schema never declared at all.

This is the layer that turns a `LoaderTrace` (step 4) into the two kinds of
finding a user of `capaudit` acts on:

- `Mismatch`: the field reached a sink its declared capability doesn't
  permit — the core "declared vs. actual capability" bug class this tool
  targets.
- `CoverageGap`: the loader used a field the schema never mentions at all,
  so no capability check could be performed for it. This isn't itself a
  capability mismatch, but it means the schema is incomplete and the field
  in question wasn't checked — surfaced separately so a clean report can't
  be mistaken for "every field was checked."
"""

from __future__ import annotations

from dataclasses import dataclass

from capaudit.schema import Capability, SinkCategory
from capaudit.tracer import CapabilityTracer, LoaderTrace


@dataclass(frozen=True)
class Mismatch:
    function_name: str
    field: str
    declared: Capability
    actual_sink: SinkCategory
    call_description: str
    lineno: int

    def describe(self) -> str:
        return (
            f"{self.function_name}: field {self.field!r} declared "
            f"{self.declared.value}, but reaches {self.actual_sink.value} "
            f"via {self.call_description} at line {self.lineno}"
        )


@dataclass(frozen=True)
class CoverageGap:
    function_name: str
    field: str

    def describe(self) -> str:
        return (
            f"{self.function_name}: field {self.field!r} is read from the "
            f"config but is not declared in its schema — not checked"
        )


@dataclass(frozen=True)
class CheckResult:
    mismatches: tuple[Mismatch, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()

    @property
    def has_mismatches(self) -> bool:
        return bool(self.mismatches)


def _check_traces(traces: list[LoaderTrace]) -> CheckResult:
    mismatches: list[Mismatch] = []
    gaps: list[CoverageGap] = []
    for trace in traces:
        for hit in trace.sink_hits:
            if not trace.schema.is_allowed(hit.field, hit.sink):
                mismatches.append(
                    Mismatch(
                        function_name=trace.function_name,
                        field=hit.field,
                        declared=trace.schema.capability_of(hit.field),
                        actual_sink=hit.sink,
                        call_description=hit.call_description,
                        lineno=hit.lineno,
                    )
                )
        for field in trace.undeclared_fields_used:
            gaps.append(CoverageGap(trace.function_name, field))
    return CheckResult(tuple(mismatches), tuple(gaps))


def check_source(source: str, filename: str = "<module>") -> CheckResult:
    traces = CapabilityTracer().trace_source(source, filename=filename)
    return _check_traces(traces)


def check_file(path: str) -> CheckResult:
    traces = CapabilityTracer().trace_file(path)
    return _check_traces(traces)
