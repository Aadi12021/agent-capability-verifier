**What this changes and why**

<!-- Keep it to what a reviewer needs. Link an issue if there is one. -->

**Checklist**

- [ ] `pytest -v` passes locally
- [ ] `ruff check .` passes locally
- [ ] `mypy` passes locally
- [ ] If this adds/changes a sink, capability, or the tracer's matching logic: tests were added to
      `tests/test_tracer.py` and/or `tests/test_checker.py` covering the new behavior
- [ ] If this adds an example loader: it's original code, not a reproduction of any disclosed
      exploit or proof-of-concept (see `examples/README.md`)
- [ ] If this changes scope (new language support, new analysis mode, runtime execution of
      analyzed code, etc.): this was discussed in an issue first — see CONTRIBUTING.md
