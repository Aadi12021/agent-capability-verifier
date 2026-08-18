import argparse
import sys
from pathlib import Path

from capaudit import __version__
from capaudit.checker import check_source

_EXCLUDED_DIR_NAMES = {"__pycache__", ".git", ".venv", "venv", "node_modules"}


def _collect_python_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(
            p for p in path.rglob("*.py")
            if not any(part in _EXCLUDED_DIR_NAMES for part in p.parts)
        )
    return []


def _run(path: Path, strict: bool) -> int:
    files = _collect_python_files(path)
    if not files:
        print(f"capaudit: no Python files found at {path}", file=sys.stderr)
        return 2

    any_mismatch = False
    any_gap = False
    any_error = False

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8")
        except OSError as e:
            print(f"capaudit: error reading {file_path}: {e}", file=sys.stderr)
            any_error = True
            continue
        try:
            result = check_source(source, filename=str(file_path))
        except SyntaxError as e:
            print(f"capaudit: syntax error in {file_path}: {e}", file=sys.stderr)
            any_error = True
            continue

        for mismatch in result.mismatches:
            print(f"MISMATCH  {file_path}:{mismatch.lineno}  {mismatch.describe()}")
            any_mismatch = True
        for gap in result.coverage_gaps:
            print(f"COVERAGE  {file_path}  {gap.describe()}")
            any_gap = True

    if not any_mismatch and not any_gap and not any_error:
        print(f"capaudit: no capability mismatches found ({len(files)} file(s) checked)")

    if any_error:
        return 2
    if any_mismatch:
        return 1
    if strict and any_gap:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="capaudit",
        description=(
            "Static linter: flags config fields whose declared capability schema "
            "is narrower than what the consuming code actually does with them."
        ),
    )
    parser.add_argument("path", nargs="?", help="Python file or directory to analyze")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "also exit non-zero if any coverage gaps are found (fields the "
            "loader reads that its schema never declared)"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.path is None:
        parser.print_help()
        return 1

    path = Path(args.path)
    if not path.exists():
        print(f"capaudit: path not found: {path}", file=sys.stderr)
        return 2

    return _run(path, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
