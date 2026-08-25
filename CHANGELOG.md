# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Issue templates (bug report, sink/capability request) and a PR checklist template.

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
