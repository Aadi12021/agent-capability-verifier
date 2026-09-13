# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-09-13

### Added
- Issue templates (bug report, sink/capability request) and a PR checklist template.
- **Cross-field (joint) capability reasoning.** A schema can now declare, via
  `JointCapability`, that a named combination of two or more fields is allowed to reach a
  sink even though none of the fields' individual declarations would permit it alone
  (`src/capaudit/schema.py`). The tracer detects sink arguments built from more than one
  config field — via string concatenation, an f-string, or `os.path.join(...)` — and
  reports them as `JointSinkHit`s (`src/capaudit/tracer.py`). The checker flags an
  unguarded combination as a `JointMismatch`, distinct from the existing single-field
  `Mismatch` (`src/capaudit/checker.py`), and the CLI prints these as `JOINT-MISMATCH`
  lines. New example pair `vulnerable_loader_4_joint_path.py` /
  `clean_loader_joint_path.py` demonstrates the bug class (two individually-innocuous
  fields joined into a path-traversal primitive) and its fix. Purely additive: a schema
  built without `joint=` behaves exactly as before. See
  [docs/capability-schema.md](docs/capability-schema.md#joint-compound-capabilities) and
  the README's scope section for what this currently does and does not detect.

### Fixed
- `ruff check .` and `mypy`, run with no extra flags, failed inside the Docker sandbox
  because `/workspace` is root-owned and the non-root `sandbox` user couldn't write a cache
  there. `docker/Dockerfile` now sets `RUFF_CACHE_DIR`/`MYPY_CACHE_DIR` to writable paths
  under `/tmp`; verified by running both tools plain and confirming the caches land there.

### Verified
- Docker sandbox (`docker/`) built and its isolation properties exercised for the first time
  (2026-09-08): image builds, full test suite runs inside the container (`47 passed`), network
  egress and DNS both fail from inside, container runs as non-root (uid 1000) with all Linux
  capabilities dropped and `NoNewPrivs` set. Evidence table in `docker/README.md`.

## [0.1.0] - 2026-08-19

### Added
- Capability schema spec and `Capability`/`SinkCategory` model (`src/capaudit/schema.py`).
- AST-based static tracer that follows config fields into dangerous sinks
  (`src/capaudit/tracer.py`).
- Mismatch checker with a false-positive/false-negative test suite
  (`src/capaudit/checker.py`).
- `capaudit` CLI, wired up end to end (`src/capaudit/cli.py`).
- Original example loaders (vulnerable and clean) demonstrating the bug class.
- Docker sandbox (`docker/`) with no network egress for isolated analysis and test runs.
- SECURITY.md, CONTRIBUTING.md, and a CI gate running `ruff` and `mypy` alongside `pytest`.
- README badges (CI, license, Python version).
