from capaudit.cli import main


def test_no_args_prints_help_and_exits_nonzero(capsys):
    exit_code = main([])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "usage" in captured.out.lower()


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "0.1.0" in captured.out
