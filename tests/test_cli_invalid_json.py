"""A malformed JSON file must give a clean error and exit code 2, not a traceback (yunaremaia/acc-mcp#58)."""

import argparse

import pytest

from acc_mcp.cli import cmd_check, cmd_inspect, cmd_snapshot


@pytest.fixture
def bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not valid json", encoding="utf-8")
    return path


def test_inspect_reports_invalid_json(bad_json, capsys):
    assert cmd_inspect(argparse.Namespace(tools_file=str(bad_json))) == 2
    assert "Invalid JSON" in capsys.readouterr().err


def test_snapshot_reports_invalid_json(bad_json, capsys):
    args = argparse.Namespace(tools_file=str(bad_json), output=None)

    assert cmd_snapshot(args) == 2
    assert "Invalid JSON" in capsys.readouterr().err


def test_check_reports_invalid_tools_json(tmp_path, bad_json, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[]", encoding="utf-8")
    args = argparse.Namespace(baseline=str(baseline), tools_file=str(bad_json), policy=None)

    assert cmd_check(args) == 2
    assert "Invalid JSON" in capsys.readouterr().err


def test_check_reports_invalid_baseline_json(tmp_path, bad_json, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text("[]", encoding="utf-8")
    args = argparse.Namespace(baseline=str(bad_json), tools_file=str(tools), policy=None)

    assert cmd_check(args) == 2
    assert "Invalid JSON" in capsys.readouterr().err
