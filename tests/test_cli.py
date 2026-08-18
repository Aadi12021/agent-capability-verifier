from pathlib import Path

import pytest

from capaudit.cli import main

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_no_args_prints_help_and_exits_nonzero(capsys):
    exit_code = main([])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "usage" in captured.out.lower()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "0.1" in captured.out


def test_nonexistent_path_exits_2(capsys):
    exit_code = main(["/no/such/path/anywhere.py"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "not found" in captured.err.lower()


def test_clean_example_exits_0(capsys):
    exit_code = main([str(EXAMPLES_DIR / "clean_loader.py")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "no capability mismatches found" in captured.out
    assert "MISMATCH" not in captured.out


def test_vulnerable_example_exits_1_and_prints_mismatch(capsys):
    exit_code = main([str(EXAMPLES_DIR / "vulnerable_loader_1_path.py")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "MISMATCH" in captured.out
    assert "offset" in captured.out


def test_directory_target_aggregates_across_files(capsys):
    exit_code = main([str(EXAMPLES_DIR)])
    captured = capsys.readouterr()
    assert exit_code == 1  # the vulnerable examples in this dir must be flagged
    assert captured.out.count("MISMATCH") >= 3  # one per vulnerable example


def test_coverage_gap_alone_does_not_fail_by_default(tmp_path, capsys):
    module = tmp_path / "gap_only.py"
    module.write_text(
        "from capaudit.schema import Capability, CapabilitySchema\n"
        "SCHEMA = CapabilitySchema({'offset': Capability.NUMERIC})\n"
        "@SCHEMA.bind\n"
        "def load(config):\n"
        "    offset = config['offset']\n"
        "    mystery = config['mystery']\n"
        "    return offset, mystery\n"
    )
    exit_code = main([str(module)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "COVERAGE" in captured.out


def test_strict_flag_fails_on_coverage_gap(tmp_path, capsys):
    module = tmp_path / "gap_only.py"
    module.write_text(
        "from capaudit.schema import Capability, CapabilitySchema\n"
        "SCHEMA = CapabilitySchema({'offset': Capability.NUMERIC})\n"
        "@SCHEMA.bind\n"
        "def load(config):\n"
        "    offset = config['offset']\n"
        "    mystery = config['mystery']\n"
        "    return offset, mystery\n"
    )
    exit_code = main(["--strict", str(module)])
    assert exit_code == 1


def test_syntax_error_reports_and_exits_2(tmp_path, capsys):
    module = tmp_path / "broken.py"
    module.write_text("def load(config:\n    this is not valid python\n")
    exit_code = main([str(module)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "syntax error" in captured.err.lower()
