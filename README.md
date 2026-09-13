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

### Cross-field (joint) reasoning

Some real bugs don't come from any single field — they come from *combining* two or more fields
that each look inert on their own. `capaudit` also traces this: when a single sink call's argument
is built from more than one distinct config field — via string concatenation, an f-string, or
`os.path.join(...)` — it reports which fields jointly feed that sink, and flags the combination as
a **joint mismatch** unless the schema declares a `JointCapability` rule naming that exact
combination (see [docs/capability-schema.md](docs/capability-schema.md#joint-compound-capabilities)).
This catches bugs like a `base_dir` field and a `filename` field that individually look like
harmless strings but together let a loader read an arbitrary file — a class of bug the original
single-field-only tracer couldn't see at all, because it simply found no field attributable to a
compound expression and stayed silent.

## Quick start

```bash
pip install -e .
capaudit examples/clean_loader.py
# capaudit: no capability mismatches found (1 file(s) checked)

capaudit examples/
# MISMATCH  examples/vulnerable_loader_1_path.py:30  load_record_index: field 'offset' declared numeric, but reaches file_read via open(...) at line 30
# MISMATCH  examples/vulnerable_loader_2_template.py:27  render_welcome_message: field 'greeting_name' declared opaque_string, but reaches template_render via Template(...) at line 27
# MISMATCH  examples/vulnerable_loader_3_subprocess.py:28  run_diagnostics: field 'log_level' declared enum, but reaches subprocess via subprocess.run(...) at line 28
# JOINT-MISMATCH  examples/vulnerable_loader_4_joint_path.py:44  load_plugin_asset: fields 'asset_name' (opaque_string), 'plugin_dir' (opaque_string) jointly reach file_read via open(...) at line 44, and no joint capability rule covers this combination
```

Exit code is `0` for a clean run, `1` if any mismatch is found (or, with `--strict`, if any
coverage gap is found), `2` for a tool error (bad path, syntax error, or one of the adversarial-
input limits below, in the target file).

## Robustness against adversarial input

`capaudit` never executes the source it analyzes (see "What this tool does" above) — but that
source could itself be adversarial, not just the config values it's checking, and `ast.parse()`
plus this tool's own tree-walk still have to run on it. Since nothing here executes untrusted
code, the realistic risk is resource exhaustion, not code execution, so three defensive limits are
built in and enforced before/during analysis of every file:

- **Max input size: 5 MB.** Checked both on disk (before a file is even read into memory) and on
  the source string itself (before `ast.parse()`), so an absurdly large file is rejected rather
  than fully read or parsed. Raises `SourceTooLargeError`.
- **Parse timeout: 5 seconds.** A wall-clock deadline around the `ast.parse()` call, since
  deliberately-crafted source (e.g. extreme nesting) can make CPython's own parser pathologically
  slow. Raises `ParseTimeoutError`. Enforced via `SIGALRM` on POSIX; on platforms or contexts
  where that's unavailable (Windows, or a non-main thread) it falls back to an un-timed parse
  rather than failing outright — the size and depth limits still bound the work in that case.
  `capaudit.tracer.DEFAULT_PARSE_TIMEOUT_SECONDS` / `DEFAULT_MAX_SOURCE_BYTES` are constructor
  arguments on `CapabilityTracer` (and passthrough keyword arguments on `check_source`/
  `check_file`) if you need to tune them.
- **Depth/iteration limit: 150 / 1000.** A pathologically deep attribute chain (`a.b.b.b...`) or
  nested expression (`x + x + x + ...`) is capped at 150 levels of recursion, and the fixed-point
  passes that resolve variable-alias chains are capped at 1000 iterations over the function body.
  Both raise `TraceDepthExceededError` with a clear message instead of either hitting Python's own
  `RecursionError` at an unpredictable depth or spinning for a very long time on a long enough
  chain declared in the right (adversarial) order.

All three are checked before capaudit ever executes any code from the target file (it never does
that anyway) — they exist purely so pathological input fails fast and clearly, at the CLI (a
`capaudit: refusing to read/analyze ...` message and exit code `2`, the same treatment as a syntax
error) and at the Python API (a specific, catchable exception from `capaudit.tracer`).

## What this tool does NOT do (scope — read this before relying on it)

Its coverage is intentionally narrow. It is **not** a general security scanner and should not be
treated as one. Specifically:

- **Requires opt-in annotation — it does not scan arbitrary code.** `capaudit` only ever analyzes a
  loader function that's explicitly decorated `@SCHEMA.bind` for an explicitly declared
  `CapabilitySchema(...)`. Point it at a codebase that has never adopted either of those — which is
  every codebase that isn't this project or doesn't use `capaudit`'s API — and it will report zero
  mismatches on every file, not because the code is clean, but because there's nothing for it to
  recognize as a schema-bound loader in the first place. See "Real-world sanity check" below, where
  running it against three unmodified open-source projects confirmed exactly this.
- **Assumes a loader's config is its first parameter, accessed as `config[...]`/`config.get(...)`.**
  A real function that takes config across several named parameters instead of one dict (common in
  practice — see the real-world sanity check below) doesn't fit this shape at all; adopting
  `capaudit` on it would mean restructuring the function's signature, not just adding a schema.
- **Only analyzes Python.** No support for other languages.
- **Is purely static (AST-based).** It does not execute any code under analysis, and it does not
  reason about runtime values — dynamic dispatch, `getattr`/`setattr` indirection, monkeypatching,
  and similar patterns can hide a real data flow from the tracer and produce a false negative.
- **Tracks a fixed, hardcoded set of sink types** (file I/O, exec/eval, subprocess, template
  rendering, sockets). Any dangerous sink not in that list will not be detected.
- **Does not do full interprocedural or cross-file analysis.** Flows that pass through several
  layers of function calls, especially across module boundaries, may not be fully traced.
- **Does not resolve aliasing, decorators, or metaprogramming precisely.** These can both hide
  real flows (false negatives) and produce spurious ones (false positives).
- **Sink-argument matching is pattern-based, not a general call-argument evaluator, and both
  mutation testing and the real-world sanity check (below) found real gaps in it:** a list built in
  its own variable before being passed to a subprocess call (`args = [cmd, tainted];
  subprocess.run(args)`, as opposed to the literal `subprocess.run([cmd, tainted])`) is not traced;
  `open(file=path)` isn't either, since only positional arguments to `open()` are inspected; nor is
  `Path(...).open()`, since the Path-aware matching only recognizes `.read_text`/`.write_text`/
  `.read_bytes`/`.write_bytes`. Template-render detection is narrower still: it only recognizes a
  bare `Template(...)` constructor call, not the `Environment`-based usage (`env.from_string(...)`,
  `env.get_template(...)`) that's arguably the *more* common real-world way to use Jinja2 — see
  `tests/test_mutation.py`'s `test_known_gap_*` tests for all of these, pinned down with a working
  example each. None of these are contrived evasions — they're ordinary refactors or equally common
  alternate spellings — so treat "no mismatch" as "no mismatch found via a recognized pattern," not
  proof the field never reaches a dangerous sink some other syntactically-equivalent way.
- **Cross-field reasoning is narrow and pattern-based, not general.** It only recognizes a sink
  argument built from string concatenation (`+`), an f-string, or `os.path.join(...)` — including
  through one level of variable assignment of the combined result. It does **not** recognize
  `%`-formatting, `str.format()`, `pathlib.Path(...) / ...`, or fields combined via a helper
  function across function/module boundaries. A declared `JointCapability` rule also matches only
  the *exact* field combination observed at a sink — a rule for `{base_dir, filename}` does not
  cover a sink additionally fed by a third field. See
  [docs/capability-schema.md](docs/capability-schema.md#joint-compound-capabilities) for the full
  list of current matching/detection limits.
- **Does not detect every bug class in the original incident.** It targets the
  declared-vs-actual-capability mismatch specifically (single-field and joint), not the full space
  of deserialization or supply-chain vulnerabilities.
- **Is a linter over code you provide, not a scanner of third-party systems.** It never fetches,
  connects to, or probes anything outside the files given to it.
- **The adversarial-input limits above are deliberately conservative, not tuned to any specific
  workload.** A legitimately huge generated config-loader file, an unusually slow-to-parse but
  benign file, or a genuinely long (if pointless) alias chain would also be rejected — that's a
  false "won't analyze" rather than a false negative, and the limits are overridable at the Python
  API (`CapabilityTracer`/`check_source`/`check_file` constructor and keyword arguments) if you hit
  one legitimately.

Treat a clean run as "no mismatches of this specific class were found by this specific set of
static rules," not as a general clean bill of health.

## Real-world sanity check

`capaudit`'s own test suite only exercises code written specifically to exercise it. To check
whether its output is reasonable on code nobody wrote for that purpose, it was run (read-only,
no execution, no network access to anything of theirs, via a shallow git clone) against the
unmodified public source of three small, permissively-licensed projects that do real config-driven
data loading: [cookiecutter](https://github.com/cookiecutter/cookiecutter) (BSD-3),
[python-dotenv](https://github.com/theskumar/python-dotenv) (BSD-3), and
[dynaconf](https://github.com/dynaconf/dynaconf) (MIT).

**Result: zero mismatches, zero coverage gaps, across all 533 files.** That's expected, not a
clean bill of health for `capaudit` or for them — see the opt-in-annotation bullet above: none of
the three declares a `CapabilitySchema` or uses `@SCHEMA.bind`, so there was nothing for the tracer
to recognize as a bound loader anywhere, in any of them. This is the most important finding of the
exercise: **capaudit is architecturally unable to produce output on a codebase that hasn't already
adopted its API**, which is worth knowing before pointing it at anything and expecting Bandit- or
Semgrep-style findings.

Two more things came out of it:

- **cookiecutter's own test fixtures produced 2 `capaudit: syntax error` tool errors** (out of
  ~535 files) on `tests/hooks-abort-render/hooks/{pre,post}_gen_project.py` — these have a `.py`
  extension but are actually Jinja2 template source (`{% if cookiecutter.abort_pre_gen == "yes" %}`
  is not valid Python), so `ast.parse()` correctly rejects them. Not a bug in `capaudit`, but real,
  if minor, noise: it walks every `*.py` file it finds with no way to know some of them are
  templates wearing a Python extension.
- **Neither cookiecutter's `generate_file()` nor python-dotenv's `set_key()`** — real functions
  that do exactly the path-construction and template-rendering `capaudit` is designed to check —
  take their config as a single first `dict` parameter; both spread it across several named
  parameters instead. Adapting the real logic of `generate_file()` (BSD-3) into `capaudit`'s
  expected shape to see whether checking it would produce a sensible result surfaced the
  `Environment().from_string(...)` gap folded into the scope bullet above: the adapted example's
  config field genuinely reaches template rendering, declared narrower than that, and `capaudit`
  stays silent — pinned down as
  `test_known_gap_jinja2_environment_from_string_not_recognized_as_template_render` in
  `tests/test_mutation.py`.

## Responsible disclosure

If you find a security issue in a project *because* of output from this tool, follow that
project's own responsible-disclosure process — this tool does not grant you authorization to test
systems you don't own or have permission to test. If you find a bug in this tool itself, see
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## Status

`v0.2.0` — the design described above, including cross-field (joint) reasoning, is implemented end
to end (schema, tracer, checker, CLI) and covered by tests, and the Docker sandbox's isolation
properties have been verified. The project is still young: APIs may still change, and the scope
limitations above are real, not boilerplate. Read them before relying on a clean run.

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
