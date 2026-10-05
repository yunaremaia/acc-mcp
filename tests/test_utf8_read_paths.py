"""Non-ASCII configuration files must load under a non-UTF-8 locale (issue #52).

Runs the real CLI in a subprocess with a pinned non-UTF-8 locale, because
in-process tests inherit the ambient (UTF-8) locale and can never see the bug.
"""

import json
import os
import subprocess
import sys

import pytest

TOOLS = [
    {
        "name": "buscar_fatura",
        "inputSchema": {
            "type": "object",
            "properties": {"data": {"description": "Janela — início e fim"}},
        },
    },
    {"name": "支払い_確認", "inputSchema": {"type": "object", "properties": {}}},
]

# A YAML policy with a non-ASCII tool name and a non-ASCII comment; both are
# valid YAML/UTF-8 and must load on any host.
POLICY_YAML = """# política padrão — acentuação em comentário
risk_overrides:
  支払い_確認: low
block_critical: true
"""

ASCII_LOCALE_ENV = {
    # Only stdout/stderr rendering is forced to UTF-8: the bug under test is the
    # default encoding of open(), which stays the locale's (ascii) here.
    "PYTHONIOENCODING": "utf-8",
    "PYTHONUTF8": "0",
    "PYTHONCOERCECLOCALE": "0",
    "LC_ALL": "C",
    "LANG": "C",
}


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, **ASCII_LOCALE_ENV}
    return subprocess.run(
        [sys.executable, "-m", "acc_mcp.cli", *args],
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture
def tools_file(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(TOOLS, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.fixture
def policy_file(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return path


def test_ascii_locale_is_actually_non_utf8():
    """Guard: the repro only means anything if the child locale is not UTF-8."""
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import locale, sys;"
            " print(locale.getpreferredencoding(False), sys.flags.utf8_mode)",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, **ASCII_LOCALE_ENV},
    )
    assert out.stdout.split() == ["ANSI_X3.4-1968", "0"]


def test_inspect_reads_non_ascii_tools(tools_file):
    result = run_cli("inspect", str(tools_file))
    assert result.returncode == 0, result.stderr
    assert "UnicodeDecodeError" not in result.stderr


def test_validate_policy_reads_non_ascii_policy(policy_file):
    result = run_cli("--validate-policy", str(policy_file))
    assert result.returncode == 0, result.stdout + result.stderr


def test_check_reads_non_ascii_baseline_snapshot(tools_file, tmp_path):
    baseline = {t["name"]: {"risk": {"level": "low"}} for t in TOOLS}
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline, ensure_ascii=False), encoding="utf-8")

    result = run_cli("check", "--baseline", str(baseline_path), str(tools_file))
    assert result.returncode == 0, result.stderr
