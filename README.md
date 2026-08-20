# agent-capability-verifier

[![CI](https://github.com/Aadi12021/agent-capability-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Aadi12021/agent-capability-verifier/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**A defensive static-analysis linter for Python config loaders.** It checks whether a config
schema's *declared* field types match what the code that consumes those fields can *actually* do —
and flags the gap.

This is not a scanner, prober, or exploit tool. It never executes untrusted code, never makes
network requests, and never touches any system other than the source files you point it at. It
reads code and an accompanying schema declaration, builds a static data-flow graph, and reports
mismatches. That's the entire threat model.

## Why this exists

In July 2026, an autonomous agent compromised a Hugging Face dataset pipeline by exploiting a
mismatch between what a config field was *declared* to be and what the loader code *actually* did
with it. An HDF5 "external raw storage" field was declared as a numeric offset but was read as a
local file path; a related field was declared as inert but was rendered through a Jinja2 template
engine, yielding arbitrary code execution. Both vectors bypassed the existing outbound-URL
allowlist entirely, because that allowlist only inspected network fetches — not local file reads
or local template rendering triggered by trusted-looking config data.

Full technical timeline: https://huggingface.co/blog/agent-intrusion-technical-timeline

That incident is the motivating example for this project, not a spec to replicate. Every example
and test case in this repository is original code written to demonstrate the general bug
*class* — a config field whose declared capability is narrower than its actual capability — not a
reproduction of Hugging Face's disclosed proof-of-concept or payloads. If you're looking for
details of the original incident, read the Hugging Face writeup linked above; this repo doesn't
reproduce it.

## What this tool does

Given:
1. A **capability schema** — a declaration of what each config field is allowed to be (e.g.
   `numeric`, `opaque_string`, `none`), and
2. A **loader function** — Python code that reads config values and does something with them,

the tool statically traces which config fields flow into which dangerous sinks (`open()`,
`exec`/`eval`, `subprocess.*`, template rendering, socket/network calls, etc.) and flags any field
that reaches a sink more powerful than its schema declares.

Example: a field declared `numeric` that ends up passed to `open()` as a path, or interpolated
into a `Template(...).render()` call, is flagged — regardless of whether anything "bad" happens
to be in the config file today. The point is to catch the *capability* mismatch before an
attacker-controlled value ever reaches it.

See [docs/capability-schema.md](docs/capability-schema.md) for the full capability/sink taxonomy
and how to declare a schema.

`capaudit` also separately reports **coverage gaps** — config fields a loader reads that its
schema never declared at all, so no capability check could be performed for them. These don't fail
a run by default (pass `--strict` to make them fail CI too), but they're printed so a clean run
can't be mistaken for "every field was checked."

## Quick start

```bash
pip install -e .
capaudit examples/clean_loader.py
# capaudit: no capability mismatches found (1 file(s) checked)

capaudit examples/
# MISMATCH  examples/vulnerable_loader_1_path.py:30  load_record_index: field 'offset' declared numeric, but reaches file_read via open(...) at line 30
# MISMATCH  examples/vulnerable_loader_2_template.py:27  render_welcome_message: field 'greeting_name' declared opaque_string, but reaches template_render via Template(...) at line 27
# MISMATCH  examples/vulnerable_loader_3_subprocess.py:28  run_diagnostics: field 'log_level' declared enum, but reaches subprocess via subprocess.run(...) at line 28
```

Exit code is `0` for a clean run, `1` if any mismatch is found (or, with `--strict`, if any
coverage gap is found), `2` for a tool error (bad path, syntax error in the target file).

## What this tool does NOT do (v1 scope — read this before relying on it)

This is a v1, and its coverage is intentionally narrow. It is **not** a general security scanner
and should not be treated as one. Specifically, v1:

- **Only analyzes Python.** No support for other languages.
- **Is purely static (AST-based).** It does not execute any code under analysis, and it does not
  reason about runtime values — dynamic dispatch, `getattr`/`setattr` indirection, monkeypatching,
  and similar patterns can hide a real data flow from the tracer and produce a false negative.
- **Tracks a fixed, hardcoded set of sink types** (file I/O, exec/eval, subprocess, template
  rendering, sockets). Any dangerous sink not in that list will not be detected.
- **Does not do full interprocedural or cross-file analysis.** Flows that pass through several
  layers of function calls, especially across module boundaries, may not be fully traced in v1.
- **Does not resolve aliasing, decorators, or metaprogramming precisely.** These can both hide
  real flows (false negatives) and produce spurious ones (false positives).
- **Does not detect every bug class in the original incident.** It targets the
  declared-vs-actual-capability mismatch specifically, not the full space of deserialization or
  supply-chain vulnerabilities.
- **Is a linter over code you provide, not a scanner of third-party systems.** It never fetches,
  connects to, or probes anything outside the files given to it.

Treat a clean run as "no mismatches of this specific class were found by this specific set of
static rules," not as a general clean bill of health.

## Responsible disclosure

If you find a security issue in a project *because* of output from this tool, follow that
project's own responsible-disclosure process — this tool does not grant you authorization to test
systems you don't own or have permission to test. If you find a bug in this tool itself, see
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## Status

`v0.1.0` — the design described above is implemented end to end (schema, tracer, checker, CLI) and
covered by tests, but the project is young: APIs may still change, and the scope limitations above
are real, not boilerplate. Read them before relying on a clean run.

## Project layout

```
src/capaudit/     # the tool itself: schema.py, tracer.py, checker.py, cli.py
docs/             # capability schema spec
examples/         # original toy loaders: vulnerable + clean, for testing and demonstration
tests/            # test suite
docker/           # isolated sandbox used to run analysis and tests, no network egress
```

## Development

All analysis and tests run inside an isolated Docker sandbox with no network egress — see
[docker/README.md](docker/README.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, the
lint/type-check/test commands CI runs, and guidelines for adding sinks, capabilities, or examples.

## License

Apache License 2.0. See [LICENSE](LICENSE).
