# Contributing

Thanks for considering a contribution. This project is young (`v0.1.0`) and its scope is
deliberately narrow — see the README's "What this tool does NOT do" section before proposing a
large feature; a PR that quietly expands scope (e.g. adding runtime execution, or turning this
into a network scanner) will be declined regardless of code quality, because it breaks the
project's core threat model.

## Setup

```bash
git clone https://github.com/Aadi12021/agent-capability-verifier
cd agent-capability-verifier
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
pytest -v          # full test suite must pass
ruff check .        # lint
mypy                 # type-check src/capaudit
```

All three run in CI on every PR; a failing check blocks merge.

## Adding a new sink or capability

The sink taxonomy (`SinkCategory`) and capability vocabulary (`Capability`) live in
`src/capaudit/schema.py`, with the allowed-sinks mapping right next to them. If you're adding a
new dangerous call pattern for the tracer to recognize (`src/capaudit/tracer.py`,
`_SIMPLE_SINK_TABLE` and `_match_sink_hits`), please also:

1. Add a case to `tests/test_tracer.py` covering the new pattern in isolation.
2. Add a case to `tests/test_checker.py` if the change affects what counts as a mismatch.
3. Update `docs/capability-schema.md` if you're changing the taxonomy itself, not just adding a
   call-site pattern for an existing `SinkCategory`.

## Adding an example loader

New examples in `examples/` must be **original code you wrote**, demonstrating the general
declared-vs-actual-capability bug class — not a reproduction of any real, disclosed exploit or
proof-of-concept. See the note at the top of `examples/README.md`.

## Reporting a security issue in capaudit itself

Don't open a public issue — see [SECURITY.md](SECURITY.md).
