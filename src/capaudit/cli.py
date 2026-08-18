import argparse
import sys

from capaudit import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="capaudit",
        description=(
            "Static linter: flags config fields whose declared capability schema "
            "is narrower than what the consuming code actually does with them."
        ),
    )
    parser.add_argument("path", nargs="?", help="Python file or directory to analyze")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.path is None:
        parser.print_help()
        return 1

    print(f"capaudit: analysis engine not yet implemented (target: {args.path})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
