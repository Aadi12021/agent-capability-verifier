# Security policy

## Reporting a vulnerability in capaudit itself

If you find a security issue in this tool's own code (for example, a way the analyzer could be
tricked into executing something from the source it's reading, despite the "never import or
execute the target" design constraint), please report it privately rather than opening a public
issue:

- Open a [GitHub security advisory](../../security/advisories/new) for this repository, or
- Email the maintainer directly (see the `authors` field in `pyproject.toml` for current contact
  info).

Please include a minimal reproduction and, if relevant, which part of the pipeline (schema
declaration parsing, the AST tracer, or the CLI) is affected. We'll acknowledge reports as quickly
as we can and credit reporters in the fix, unless you'd prefer otherwise.

## Reporting a vulnerability that capaudit found in *your* code

capaudit is a linter, not an authorization to test anything. If a capaudit run flags a mismatch in
a project you don't own or maintain, follow *that project's* responsible-disclosure process to
report it — this repository has no bearing on your authorization to test, scan, or disclose issues
in third-party software.

## Supported versions

This project is pre-1.0 (`v0.1.0`). Security fixes land on `main` and the latest tagged release;
there is no long-term-support branch yet.
