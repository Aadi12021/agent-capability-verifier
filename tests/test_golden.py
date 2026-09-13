"""Golden-file regression tests: for every example loader, the checker's
full output (every mismatch, joint mismatch, and coverage gap it finds) is
locked in as a golden `.txt` file under `tests/golden/`. Any future change
that alters checker behavior on an *existing* example -- a new finding, a
lost one, a changed sink or line number -- fails this test loudly instead
of drifting silently, and requires a deliberate, reviewed regeneration of
the golden file rather than a silent behavior change slipping through.

Golden content is built from each finding's `.describe()` text, which never
embeds the file's path, so these are independent of the invocation's
working directory and of `EXAMPLES_DIR`'s absolute location.

To add a new example or intentionally change an existing one's expected
output, regenerate with:

    CAPAUDIT_UPDATE_GOLDENS=1 pytest tests/test_golden.py

then review the diff in `tests/golden/` before committing it -- an
unreviewed regeneration defeats the entire point of this test.
"""

import os
from pathlib import Path

import pytest

from capaudit.checker import CheckResult, check_file

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

_UPDATE = os.environ.get("CAPAUDIT_UPDATE_GOLDENS") == "1"


def _render_section(title: str, described: list[str]) -> list[str]:
    lines = [f"{title}:"]
    lines.extend(described if described else ["(none)"])
    lines.append("")
    return lines


def _render(result: CheckResult) -> str:
    lines: list[str] = []
    lines += _render_section("MISMATCHES", [m.describe() for m in result.mismatches])
    lines += _render_section("JOINT MISMATCHES", [m.describe() for m in result.joint_mismatches])
    lines += _render_section("COVERAGE GAPS", [g.describe() for g in result.coverage_gaps])
    return "\n".join(lines)


def _example_files() -> list[Path]:
    return sorted(EXAMPLES_DIR.glob("*.py"))


@pytest.mark.parametrize("example_path", _example_files(), ids=lambda p: p.name)
def test_golden_output(example_path: Path):
    result = check_file(str(example_path))
    actual = _render(result)
    golden_path = GOLDEN_DIR / f"{example_path.stem}.txt"

    if _UPDATE:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(actual)
        pytest.skip(f"regenerated {golden_path}")

    assert golden_path.exists(), (
        f"no golden file for {example_path.name}. If this is a new example, "
        f"generate one with: CAPAUDIT_UPDATE_GOLDENS=1 pytest tests/test_golden.py "
        f"-- then review it before committing."
    )
    expected = golden_path.read_text()
    assert actual == expected, (
        f"checker output for {example_path.name} no longer matches its golden file. "
        f"If this is an intentional, reviewed behavior change, regenerate with "
        f"CAPAUDIT_UPDATE_GOLDENS=1 pytest tests/test_golden.py and commit the diff; "
        f"otherwise this is a regression."
    )


def test_every_example_file_has_a_golden_file():
    # Catches the inverse mistake: a golden file left behind for an example
    # that no longer exists, or committed code adding an example without
    # ever running the golden generator on it.
    example_stems = {p.stem for p in _example_files()}
    golden_stems = {p.stem for p in GOLDEN_DIR.glob("*.txt")}
    assert example_stems == golden_stems, (
        f"examples/ and tests/golden/ are out of sync -- "
        f"examples without a golden file: {sorted(example_stems - golden_stems)}; "
        f"golden files without an example: {sorted(golden_stems - example_stems)}"
    )
