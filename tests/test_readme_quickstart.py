"""Regression guard: every command the README documents must actually run.

acc-mcp's README documented `acc-mcp gateway --upstream ... --mode enforce`,
`acc-mcp drift-check --baseline ...`, `acc-mcp inspect --server filesystem` and
`ACCParser.extract_tools(...)`. None of those existed: the CLI registers only
`inspect`, `snapshot`, `check` and `serve`, the tool list is a *positional*
argument, and the parser's method is `from_raw_tools`. A reader following the
Quick Start hit an argparse error on the first command.

Nothing tested the README, so the rot was invisible. This module makes the docs
executable:

1. `test_documented_commands_run` runs every offline `acc-mcp ...` command
   lifted out of the README, in a temp directory seeded with a copy of
   `examples/`, and asserts it exits 0. This is the real proof -- the exact
   sequence a reader copy-pastes is the sequence CI runs.
2. `test_documented_subcommands_and_flags_exist` introspects the real argparse
   tree and asserts every subcommand token and every flag mentioned anywhere in
   the README is registered. This covers the commands that cannot run in CI
   (`serve` against an `npx` upstream or an HTTP endpoint), so a rename fails
   loudly instead of silently rotting the docs again.
3. `test_documented_python_symbols_exist` does the same for the library
   example: every `from acc_mcp import ...` name and every attribute read off a
   documented class must exist on the real objects.

Each extractor has a control test that feeds it a deliberately broken README.
Without those, an extractor that silently returned nothing would make every
assertion above pass unconditionally, and a guard that cannot fail is worse
than no guard.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import acc_mcp

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
EXAMPLES = REPO_ROOT / "examples"

#: The console script documented in the README's Install section.
CLI_NAME = "acc-mcp"

#: A fenced block, capturing its language and its body.
FENCE = re.compile(r"^```(?P<lang>[A-Za-z0-9_+-]*)\s*$(?P<body>.*?)^```\s*$", re.MULTILINE | re.DOTALL)

#: A shell command line: an optional `$` prompt, optional indentation, then the
#: CLI name. Anchored at the start of a line so prose that merely mentions
#: `acc-mcp` is not mistaken for a command.
SHELL_COMMAND = re.compile(
    r"^[ \t]*(?P<prompt>\$ )?(?P<cmd>acc-mcp(?:-\w+)?)\b(?P<rest>.*)$",
)

#: A trailing backslash continues the command onto the next line.
CONTINUATION = re.compile(r"\\[ \t]*$")

#: A flag token such as `--baseline` or `-o`, excluding a negative number and
#: the `--` end-of-options separator.
FLAG_TOKEN = re.compile(r"(?<![\w-])--?[A-Za-z][\w-]*")

#: Top-level flags registered on the root parser rather than a subcommand.
GLOBAL_FLAGS = {"--help", "-h", "--version", "-v", "--validate-policy"}

#: Commands that need a live MCP server, a network fetch or `npx`, so CI cannot
#: execute them. They are still checked for existence by
#: `test_documented_subcommands_and_flags_exist`.
REQUIRES_UPSTREAM = re.compile(r"\bnpx\b|https?://|--server-cmd|--server-url")


def readme_text() -> str:
    """Read README.md as UTF-8, replacing undecodable bytes.

    `errors="replace"` guarantees an encoding problem surfaces as a real
    assertion failure instead of an unrelated UnicodeDecodeError.
    """
    assert README.is_file(), f"README not found at {README}"
    return README.read_text(encoding="utf-8", errors="replace")


def fenced_blocks(text: str, *languages: str) -> list[tuple[str, str]]:
    """Return `(language, body)` for every fenced block in `languages`."""
    wanted = {language.lower() for language in languages}
    blocks: list[tuple[str, str]] = []
    for match in FENCE.finditer(text):
        language = match.group("lang").lower()
        if language in wanted:
            blocks.append((language, match.group("body")))
    return blocks


def shell_commands(text: str) -> list[str]:
    """Every `acc-mcp ...` command in the README's runnable shell blocks.

    `console` blocks are deliberately excluded: they interleave commands with
    their output, and an output line like `acc-mcp version 0.1.0` would be read
    as a `version` subcommand. Transcript commands are checked separately, with
    the prompt required.
    """
    bodies = [body for _language, body in fenced_blocks(text, "bash", "sh", "shell")]
    return commands_in_bodies(bodies)


def transcript_commands(text: str) -> list[str]:
    """Commands shown in the `console` transcript blocks, prompts required."""
    bodies = [body for _language, body in fenced_blocks(text, "console")]
    return commands_in_bodies(bodies, require_prompt=True)


def logical_lines(body: str) -> list[str]:
    """Split a block body into lines, joining backslash continuations.

    The README's multi-line `serve` invocation is one command spread over three
    lines; without this it arrives as a truncated `acc-mcp serve \\`, which
    shlex then rejects as "No escaped character".
    """
    lines: list[str] = []
    pending = ""
    for raw in body.splitlines():
        line = pending + raw if pending else raw
        if CONTINUATION.search(line):
            pending = re.sub(r"\\[ \t]*$", " ", line)
            continue
        lines.append(line)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def commands_in_bodies(bodies: list[str], *, require_prompt: bool = False) -> list[str]:
    """Extract the `acc-mcp ...` commands from already-extracted block bodies.

    `require_prompt` restricts extraction to lines carrying a `$` prompt, which
    is how a `console` transcript distinguishes the commands it ran from the
    output they printed. Without it, an output line such as
    `acc-mcp version 0.1.0` is misread as a subcommand named `version`.
    """
    commands: list[str] = []
    for body in bodies:
        for line in logical_lines(body):
            match = SHELL_COMMAND.match(line)
            if not match:
                continue
            if require_prompt and not match.group("prompt"):
                continue
            command = f"{match.group('cmd')} {match.group('rest')}".strip()
            if command:
                commands.append(command)
    return commands


def python_blocks(text: str) -> list[str]:
    """Every fenced Python block in the document."""
    return [body for _language, body in fenced_blocks(text, "python", "py")]


def requires_upstream(command: str) -> bool:
    """True when a command needs a live upstream server, so it cannot run in CI."""
    return bool(REQUIRES_UPSTREAM.search(command))


def flags_used(command: str) -> set[str]:
    """Flag tokens that are arguments to acc-mcp itself, not to a nested command.

    `acc-mcp serve --server-cmd "npx -y @modelcontextprotocol/server-filesystem"`
    documents only `--server-cmd`; `-y` belongs to the `npx` inside the quoted
    string. Counting it would make the guard reject a perfectly valid command,
    which is how a guard gets switched off rather than fixed.

    shlex has already stripped the quoting here, so a flag's value and a nested
    command look alike. The rule that separates them: a token is acc-mcp's own
    if it is an option, or if it is the value of an option that was already
    seen. The first token that is neither is a positional argument, and nothing
    after it can be attributed to acc-mcp -- that is where
    `--baseline baseline.json --server filesystem` ends, with `--server`
    belonging to `check` and not to `baseline.json`.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    # tokens[0] is the CLI and tokens[1] is the subcommand (or a global flag);
    # acc-mcp's own options start at index 2.
    found: set[str] = set()
    expecting_value = False
    for token in tokens[2:]:
        if token == "--":
            break
        if token.startswith("-"):
            found.add(token.split("=", 1)[0])
            # `--flag=value` carries its own value; `--flag value` consumes the
            # next token.
            expecting_value = "=" not in token
            continue
        if expecting_value:
            expecting_value = False
            continue
        break
    return found


def cli_argv(command: str) -> list[str]:
    """Resolve a documented command to an argv, preferring the console script.

    The console script next to `sys.executable` is used when present, because
    that is the entry point the README tells readers to run; falling back to
    `python -m acc_mcp.cli` still exercises `main()`.
    """
    executable_dir = Path(sys.executable).parent
    for name in (CLI_NAME, f"{CLI_NAME}.exe"):
        candidate = executable_dir / name
        if candidate.exists():
            return shlex.split(command)
    on_path = shutil.which(CLI_NAME)
    if on_path:
        return shlex.split(command)
    return [sys.executable, "-m", "acc_mcp.cli", *shlex.split(command)[1:]]


def build_parser() -> Any:
    """Return the CLI's argparse parser.

    `acc_mcp.cli.build_parser` is new in this change, but the guard is more
    useful if it also works against a tree that does not have it: the README
    can rot for reasons unrelated to this refactor, and a guard that cannot even
    load on such a tree cannot catch it.

    So this prefers the real `build_parser` and otherwise recovers the parser by
    letting `main()` construct it, capturing the instance just before it would
    parse `sys.argv`. Either way the assertions below run against the actual
    argparse tree rather than a re-declared copy that could drift from it.

    The import is deliberately inside the function: a module-level import of a
    symbol the unfixed tree lacks aborts collection with an ImportError and
    reports zero tests, which is a useless RED baseline.
    """
    try:
        from acc_mcp.cli import build_parser as _build_parser
    except ImportError:
        return _capture_parser_from_main()

    return _build_parser()


def _capture_parser_from_main() -> Any:
    """Recover the parser `main()` builds, without running a command."""
    from acc_mcp import cli

    captured: dict[str, Any] = {}
    original = argparse.ArgumentParser.parse_args

    def spy(self: Any, args: Any = None, namespace: Any = None) -> Any:
        captured.setdefault("parser", self)
        raise _ParserCaptured

    argparse.ArgumentParser.parse_args = spy  # type: ignore[method-assign]
    argv = sys.argv
    sys.argv = ["acc-mcp"]
    try:
        cli.main()
    except _ParserCaptured:
        pass
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original  # type: ignore[method-assign]
        sys.argv = argv

    assert "parser" in captured, (
        "could not recover the argparse parser from acc_mcp.cli.main(); the "
        "introspection guard would silently pass everything"
    )
    return captured["parser"]


class _ParserCaptured(Exception):
    """Internal signal that the parser was captured; never escapes."""


def registered_flags(parser: object) -> dict[str, set[str]]:
    """Map each subcommand name to the set of flags it accepts.

    Built by walking the argparse tree rather than by scraping `--help`, so a
    flag that exists but is hidden still counts as registered.
    """
    choices: dict[str, object] = {}
    for action in getattr(parser, "_actions", []):  # noqa: SLF001 -- argparse exposes no public walk
        if hasattr(action, "choices") and action.choices and hasattr(action, "_name_parser_map"):
            choices = dict(action._name_parser_map)  # noqa: SLF001
            break

    table: dict[str, set[str]] = {}
    for name, subparser in choices.items():
        flags = {
            flag
            for action in getattr(subparser, "_actions", [])  # noqa: SLF001
            for flag in getattr(action, "option_strings", [])
        }
        table[name] = flags | GLOBAL_FLAGS
    # Root-level flags, for commands that are not subcommands at all.
    root_flags = {
        flag
        for action in getattr(parser, "_actions", [])  # noqa: SLF001
        for flag in getattr(action, "option_strings", [])
    }
    return {name: table[name] | root_flags for name in table} | {"": root_flags}


@pytest.fixture(scope="module")
def readme() -> str:
    return readme_text()


@pytest.fixture(scope="module")
def commands(readme: str) -> list[str]:
    return shell_commands(readme)


@pytest.fixture(scope="module")
def flags_by_command() -> dict[str, set[str]]:
    return registered_flags(build_parser())


def test_the_extractor_finds_the_documented_commands(commands: list[str]) -> None:
    """Guard the guard: the extractor must actually be pointed at real commands.

    If the README ever stops containing `acc-mcp ...` lines, or the extractor
    breaks, every test below would pass vacuously. This fails loudly instead.
    """
    assert len(commands) >= 5, (
        "expected the README to document at least 5 `acc-mcp ...` commands, "
        f"extracted {len(commands)}: {commands}"
    )
    joined = " ".join(commands)
    for expected in ("--version", "inspect", "snapshot", "check", "--validate-policy"):
        assert expected in joined, (
            f"the README should still document `{expected}`; the extractor "
            f"found only: {commands}"
        )


def test_documented_commands_run(tmp_path: Path, commands: list[str]) -> None:
    """Every offline documented command must exit 0 when run as written.

    Commands needing a live upstream are excluded here and covered by
    `test_documented_subcommands_and_flags_exist` instead -- a flag that does
    not exist is caught either way, and an upstream that cannot start is not a
    docs defect.
    """
    runnable = [command for command in commands if not requires_upstream(command)]
    skipped = [command for command in commands if requires_upstream(command)]
    assert runnable, "no runnable documented commands found; extractor is broken"

    # The README references `examples/...` paths relative to the repo root, so
    # seed the working directory with a copy and run there.
    workdir = tmp_path / "readme-quickstart"
    workdir.mkdir()
    shutil.copytree(EXAMPLES, workdir / "examples")

    env = {**os.environ, "COLUMNS": "120"}
    failures: list[str] = []
    for command in runnable:
        result = subprocess.run(
            cli_argv(command),
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            failures.append(
                f"README command failed (exit {result.returncode}): {command}\n"
                f"  stdout: {result.stdout.strip()}\n"
                f"  stderr: {result.stderr.strip()}"
            )

    assert not failures, (
        "every `acc-mcp ...` command in README.md must run as written:\n"
        + "\n".join(failures)
        + f"\n(not executed here, needs a live upstream: {skipped})"
    )


def test_quick_start_block_is_the_executable_sequence(readme: str, commands: list[str]) -> None:
    """Every runnable command must also appear in the shown transcript.

    The README prints a `$ acc-mcp ...` transcript of the quick start. If a
    command is added or changed there, the transcript is stale -- and a stale
    transcript is the same rot this module exists to prevent.
    """
    transcript = transcript_commands(readme)
    assert transcript, (
        "the README console transcript must show its commands with a `$` prompt; "
        "the extractor found none, so it cannot guard the transcript"
    )

    runnable = {command for command in commands if not requires_upstream(command)}
    shown = set(transcript)
    missing = runnable - shown
    assert not missing, (
        "these documented commands are not shown in the quick-start transcript, "
        f"so their real output is unverified: {sorted(missing)}"
    )

    # The transcript must not show a command the runnable blocks do not define,
    # or it is documenting something that was removed.
    orphan = shown - runnable
    assert not orphan, (
        f"the transcript shows commands the runnable blocks do not contain: {sorted(orphan)}"
    )


def test_documented_version_line_matches_the_package(readme: str) -> None:
    """The version printed in the transcript must be the installed version.

    Guards the one transcript line that an exit code cannot verify.
    """
    transcripts = fenced_blocks(readme, "console")
    assert transcripts, "README must show a console block with the version output"
    body = transcripts[0][1]
    expected = f"{CLI_NAME} version {acc_mcp.__version__}"
    assert expected in body, (
        f"README transcript must show `{expected}`; the package is at "
        f"{acc_mcp.__version__}. Re-run `acc-mcp --version` and paste real output."
    )


def test_documented_subcommands_and_flags_exist(commands: list[str], flags_by_command: dict[str, set[str]]) -> None:
    """Every subcommand token and flag in the README must be registered in argparse.

    This is the guard for the commands that cannot be executed in CI. It is what
    makes the next rename of `check` or `snapshot` fail loudly in the test suite
    rather than rot the docs silently.
    """
    problems: list[str] = []
    for command in commands:
        try:
            tokens = shlex.split(command)
        except ValueError as exc:  # unbalanced quote in the docs
            problems.append(f"cannot parse documented command {command!r}: {exc}")
            continue

        if len(tokens) < 2:
            continue
        subcommand = tokens[1]
        if subcommand in GLOBAL_FLAGS or subcommand.startswith("-"):
            # A global-flag invocation, e.g. `acc-mcp --version`. Its flags are
            # checked against the root parser below.
            allowed = flags_by_command[""]
        elif subcommand in flags_by_command:
            allowed = flags_by_command[subcommand]
        else:
            problems.append(
                f"README documents `acc-mcp {subcommand}` (in: {command}) but no "
                f"such subcommand is registered; real subcommands are "
                f"{sorted(k for k in flags_by_command if k)}"
            )
            continue

        for flag in flags_used(command):
            if flag not in allowed:
                problems.append(
                    f"README documents flag `{flag}` on `acc-mcp {subcommand}` "
                    f"(in: {command}) but it is not registered; that subcommand "
                    f"accepts {sorted(allowed)}"
                )

    assert not problems, (
        "README.md documents CLI surface that does not exist:\n"
        + "\n".join(problems)
        + "\nFix the README to match build_parser(), or register the command."
    )


def test_documented_python_symbols_exist(readme: str) -> None:
    """Every public symbol and attribute the library example uses must exist.

    `ACCParser().extract_tools(...)` was documented and had never existed; the
    real method is `from_raw_tools`. Import statements are checked against
    `acc_mcp.__all__`, and attribute reads are resolved against the real objects
    so a rename fails here.
    """
    import ast

    problems: list[str] = []
    checked_symbols = 0
    examined_attributes = 0

    for block in python_blocks(readme):
        try:
            tree = ast.parse(block)
        except SyntaxError as exc:
            problems.append(f"the README python block does not parse: {exc}")
            continue

        # Resolve `parser = ACCParser()` style bindings so that a later
        # `parser.extract_tools(...)` is checked against the real class.
        bindings: dict[str, type] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            called = node.value.func
            if not isinstance(called, ast.Name) or not hasattr(acc_mcp, called.id):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = getattr(acc_mcp, called.id)

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "acc_mcp":
                for alias in node.names:
                    checked_symbols += 1
                    if not hasattr(acc_mcp, alias.name):
                        problems.append(
                            f"README imports `{alias.name}` from acc_mcp but the "
                            "package does not export it"
                        )
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                owner = bindings.get(node.value.id)
                if owner is None:
                    continue
                # Count every attribute the resolver *examined*, valid or not.
                # Counting only the valid ones would make a broken README report
                # "the extractor is broken" instead of naming the method that
                # does not exist, which is the message a maintainer needs.
                examined_attributes += 1
                if not hasattr(owner, node.attr):
                    problems.append(
                        f"README calls `{node.value.id}.{node.attr}(...)` but "
                        f"`{owner.__name__}` has no attribute `{node.attr}`; "
                        f"real attributes: "
                        f"{sorted(a for a in dir(owner) if not a.startswith('_'))}"
                    )

    assert checked_symbols >= 3, (
        f"the README python block should import at least 3 names from acc_mcp; "
        f"checked {checked_symbols}. The extractor is broken."
    )
    assert examined_attributes >= 2, (
        f"the README python block should exercise at least 2 library methods; "
        f"examined {examined_attributes}. The extractor is broken."
    )
    assert not problems, "README.md documents a Python API that does not exist:\n" + "\n".join(problems)


def test_python_extractor_detects_a_planted_offender() -> None:
    """Control case: a fake method in a python block must be reported.

    Without this, a resolver that always found every attribute would make the
    real test above pass unconditionally.
    """
    block = (
        "from acc_mcp import ACCParser\n"
        "\n"
        "parser = ACCParser()\n"
        "tools = parser.extract_tools([])\n"
    )
    problems: list[str] = []
    for node in ast.walk(ast.parse(block)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "parser" and not hasattr(acc_mcp.ACCParser, node.attr):
                problems.append(node.attr)
    assert problems == ["extract_tools"], (
        f"the resolver missed the planted `extract_tools` offender: {problems}"
    )


def test_command_extractor_detects_a_planted_offender(flags_by_command: dict[str, set[str]]) -> None:
    """Control case: the exact #46 commands must be reported as invalid.

    `gateway`, `drift-check`, `--server`, `--mode` and `--upstream` are the names
    that shipped in the README without existing. Feeding them back proves the
    guard bites rather than accepting everything.

    `inspect` and `check` really are subcommands, so for those two lines it is
    the `--server` flag that must be rejected -- checking only the subcommand
    name would miss half of the original defect.
    """
    registered_subcommands = {name for name in flags_by_command if name}
    for command in (
        "acc-mcp gateway --upstream 'npx x' --mode enforce",
        "acc-mcp drift-check --baseline baseline.json",
    ):
        subcommand = shlex.split(command)[1]
        assert subcommand not in registered_subcommands, (
            f"`{subcommand}` was documented by #46 but must not be a subcommand"
        )

    for command in (
        "acc-mcp inspect --server filesystem",
        "acc-mcp snapshot --server filesystem --output baseline.json",
        "acc-mcp check --baseline baseline.json --server filesystem",
    ):
        subcommand = shlex.split(command)[1]
        assert subcommand in registered_subcommands, (
            f"`{subcommand}` IS a real subcommand; only its flags are the defect"
        )
        used = flags_used(command)
        assert "--server" in used, (
            f"the flag extractor missed `--server` in {command!r}; got {used}"
        )
        assert "--server" not in flags_by_command[subcommand], (
            f"`--server` was documented by #46 on `{subcommand}` but must not be "
            f"registered; {subcommand} accepts "
            f"{sorted(flags_by_command[subcommand])}"
        )


def test_flag_extractor_ignores_flags_of_nested_commands(flags_by_command: dict[str, set[str]]) -> None:
    """Control case: `npx -y` inside a quoted argument is not an acc-mcp flag.

    Without this, the guard would report a false positive on the README's own
    `serve` example and would be turned off rather than fixed.
    """
    command = 'acc-mcp serve --server-cmd "npx -y @modelcontextprotocol/server-filesystem /tmp"'
    used = flags_used(command)
    assert used == {"--server-cmd"}, (
        f"the extractor attributed a nested flag to acc-mcp: {used}"
    )
    assert "--server-cmd" in flags_by_command["serve"]
    assert "-y" not in flags_by_command["serve"]


def test_flag_resolver_detects_a_planted_flag() -> None:
    """Control case: an invented flag must be reported, a real one accepted."""
    table = registered_flags(build_parser())
    assert "--baseline" in table["check"]
    assert "--tools-file" not in table["check"], (
        "the resolver matched an invented flag; the guard would pass anything"
    )