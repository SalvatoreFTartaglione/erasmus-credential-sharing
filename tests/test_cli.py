import pytest

from credential_sharing.cli import main, parse_selection


def test_parse_selection():
    assert parse_selection("3, 1;2 2", 5) == [1, 2, 3]
    for bad in ("", "0", "6", "a", ";;"):
        with pytest.raises(ValueError):
            parse_selection(bad, 5)


def test_demo_runs_and_rejects_every_attack(capsys):
    assert main(["--demo", "--quiet"]) == 0
    output = capsys.readouterr().out
    assert "ACCEPTED (vulnerable!)" not in output
    assert output.count("rejected at") == 6
