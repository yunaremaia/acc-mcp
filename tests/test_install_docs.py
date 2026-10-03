"""Regression guard: the README must not promise a PyPI install that fails.

`acc-mcp` is not published on PyPI (https://pypi.org/pypi/acc-mcp/json returns
404), yet an earlier revision of this README led its Quick Start with

    pip install acc-mcp

as the first command a reader was told to run. That command cannot work: pip
reports "Could not find a version that satisfies the requirement acc-mcp (from
versions: none)". Every other README in this family had already been corrected
to install from Git, which meant the defect was invisible -- the class of bug
was not guarded anywhere, so it could return at any time.

This guard is network-free on purpose. A test that asked PyPI whether the name
resolves would pass in CI and fail at 3am when the index is unreachable, and it
would also pass the moment the name is claimed by a third party, which is a
different bug from the one being guarded here. Instead the contract asserted is
the one this repository controls: **every bare `pip install <name>` line must
name a distribution the README explicitly declares it does not have yet.** A
README that wants to stop carrying the "Not on PyPI yet" note has to delete the
note and the bare install line in the same commit, which is a reviewable change.

The `test_the_guard_detects_a_planted_offender` test at the bottom feeds this
module's own extractor a deliberately bad README. Without it, an extractor
broken into always returning an empty list would make every assertion below
trivially true -- a guard that cannot fail is worse than no guard at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: The distribution this repository builds. Read from pyproject.toml rather than
#: hardcoded so renaming the project cannot leave the guard auditing a stale name.
DISTRIBUTION = "acc-mcp"

#: The note that makes a bare `pip install <name>` honest. Matched
#: case-insensitively because it is prose, not an identifier.
UNPUBLISHED_NOTE = "not on pypi yet"

#: A bare install line: `pip install acc-mcp`, with optional pip flags, version
#: pins, extras and a trailing inline comment. The negative lookahead on the
#: package position is what rejects the three legitimate forms below.
BARE_INSTALL = re.compile(
    r"""^\s*(?:\$ )?                 # optional shell prompt
        pip3?\s+install\s+         # the install verb
        (?![-.\w]*git\+)           # reject `git+https://...` (installs from Git)
        (?![-.\w]*https?://)       # reject a bare URL
        (?![-.\w]*file://)         # reject a local path/URL scheme
        (?P<target>[A-Za-z0-9][\w.*-]*)  # the package name being installed
    """,
    re.VERBOSE,
)

#: Install forms that are correct as written and must never be flagged: an
#: editable/local install (`pip install -e ".[dev]"`), and any option flag.
LEGITIMATE_PREFIXES = ("-e", "--editable", "-r", "--requirement", "-c", "--constraint")


def _read_text(path: Path) -> str:
    """Read a repo file as UTF-8, replacing undecodable bytes.

    The encoding is explicit because these Markdown files are read on every
    platform; `errors="replace"` guarantees an encoding problem surfaces as a
    real assertion failure instead of an unrelated UnicodeDecodeError.
    """
    return path.read_text(encoding="utf-8", errors="replace")


def _is_legitimate_install(line: str) -> bool:
    """True when an install line targets a local checkout or a requirements file."""
    stripped = line.strip().lstrip("$ ").strip()
    tail = re.sub(r"^\s*pip3?\s+install\s+", "", stripped)
    if not tail:
        return True
    first = tail.split()[0]
    return first.startswith(LEGITIMATE_PREFIXES)


def bare_install_offenders(text: str) -> list[tuple[int, str]]:
    """Return `(line_number, line)` for every bare `pip install <name>`.

    A "bare" install names a package on its own, with no git URL, no URL scheme,
    and no editable/requirements flag. Those are exactly the lines that resolve
    against a package index, and therefore the only ones that can be wrong.
    """
    offenders: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if "pip install" not in line and "pip3 install" not in line:
            continue
        match = BARE_INSTALL.match(line)
        if not match:
            continue
        if _is_legitimate_install(line):
            continue
        offenders.append((number, line.strip()))
    return offenders


def declares_unpublished(text: str, distribution: str) -> bool:
    """True when the docs carry the explicit note naming this distribution.

    The distribution name must appear inside the note block itself, not merely
    somewhere in the file. A README can easily contain both an unrelated
    "Not on PyPI yet" note and a bare install line; searching the whole
    document would let the unrelated note license the bare install.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if UNPUBLISHED_NOTE not in line.lower():
            continue
        # Walk the contiguous blockquote this note lives in, so a wrapped note
        # that names the distribution on its second line still counts.
        start = index
        while start > 0 and lines[start - 1].lstrip().startswith(">"):
            start -= 1
        end = index
        while end + 1 < len(lines) and lines[end + 1].lstrip().startswith(">"):
            end += 1
        block = "\n".join(lines[start : end + 1]).lower()
        if distribution.lower() in block:
            return True
    return False


@pytest.fixture(scope="module")
def readme_text() -> str:
    assert README.is_file(), f"README not found at {README}"
    return _read_text(README)


def test_pyproject_declares_the_audited_distribution() -> None:
    """Guard the guard: the audited name must match what pyproject builds."""
    declared = re.search(r'^name\s*=\s*"([^"]+)"', _read_text(PYPROJECT), re.MULTILINE)
    assert declared, "pyproject.toml must declare a [project] name"
    assert declared.group(1) == DISTRIBUTION, (
        f"this guard audits `{DISTRIBUTION}` but pyproject.toml builds "
        f"`{declared.group(1)}`; update DISTRIBUTION to match"
    )


def test_readme_has_a_bare_install_to_audit(readme_text: str) -> None:
    """The extractor must be pointed at the file it claims to police.

    If the README ever documents only git/editable installs this test fails and
    asks whether the guard is still the right shape -- rather than the whole
    file passing vacuously because the extractor found nothing.
    """
    assert README.read_text(encoding="utf-8", errors="replace"), "README must not be empty"
    git_installs = [
        line for line in readme_text.splitlines() if "pip install git+" in line
    ]
    assert git_installs, (
        "README must document at least one `pip install git+...` line; without "
        "one there is no install path for the guard to police"
    )


def test_no_bare_install_without_the_unpublished_note(readme_text: str) -> None:
    """Every bare `pip install <name>` needs the explicit 'Not on PyPI yet' note.

    This is the assertion the original defect violated: the README led with a
    bare `pip install acc-mcp` and carried no note explaining that the package
    cannot be fetched that way.
    """
    offenders = bare_install_offenders(readme_text)
    unbacked = [
        f"README.md:{number}: {line}"
        for number, line in offenders
        if not declares_unpublished(readme_text, DISTRIBUTION)
    ]
    assert not unbacked, (
        f"README.md offers a bare `pip install {DISTRIBUTION}` (or another bare "
        "install) without the explicit 'Not on PyPI yet' note. That package is "
        "not on PyPI, so the command fails with 'No matching distribution "
        "found'. Install from Git, or add the note:\n" + "\n".join(unbacked)
    )


def test_the_distribution_is_actually_documented_as_unpublished(readme_text: str) -> None:
    """This repo is not on PyPI, so the README must say so."""
    assert declares_unpublished(readme_text, DISTRIBUTION), (
        f"README.md must carry the explicit '{UNPUBLISHED_NOTE}' note for "
        f"`{DISTRIBUTION}`: the package does not exist on PyPI (404), so "
        "installing by name is impossible and the docs must not imply otherwise"
    )


def test_readme_is_written_in_english(readme_text: str) -> None:
    """Public docs are an English artifact.

    A guard here is cheap because the failure is loud: a Portuguese README is
    unreachable for most of the audience and was shipped in this repo.
    """
    portuguese_markers = (
        "## o que faz",
        "## instalação",
        "## instalacao",
        "## uso",
        "## exemplo",
        "## limitações",
        "## licenca",
        "## licença",
        "simulador local",
        "não executa",
    )
    found = [m for m in portuguese_markers if m in readme_text.lower()]
    assert not found, (
        "README.md is a public artifact and must be in English; found "
        f"Portuguese content: {found}"
    )


def test_the_guard_detects_a_planted_offender() -> None:
    """Control case: a bad README must make the guard fail.

    Without this, an extractor that always returned an empty list would make
    every other test in this file pass unconditionally -- a guard that cannot
    fail is worse than no guard.
    """
    bad_readme = (
        "# demo\n\n"
        "## Quick Start\n\n"
        "```bash\n"
        "pip install acc-mcp\n"
        "acc-mcp gateway --upstream 'npx foo'\n"
        "```\n"
    )
    assert not declares_unpublished(bad_readme, DISTRIBUTION), (
        "a README with no note must not be treated as declaring the package "
        "unpublished"
    )
    offenders = bare_install_offenders(bad_readme)
    assert offenders, "the extractor missed a planted bare `pip install acc-mcp`"
    assert offenders[0][1] == "pip install acc-mcp", (
        f"extractor misreported the planted offender as {offenders[0][1]!r}"
    )


def test_the_guard_accepts_the_corrected_readme() -> None:
    """Control case: the corrected shape must produce zero offenders.

    Proves the guard is specific rather than simply rejecting every install
    line -- a from-git and an editable install are both correct as written.
    """
    good_readme = (
        "# demo\n\n"
        "## Install\n\n"
        "```bash\n"
        "pip install git+https://github.com/yunaremaia/acc-mcp.git\n"
        "```\n\n"
        "> **Not on PyPI yet.** `acc-mcp` has no PyPI release, so install from "
        "Git for now.\n\n"
        "```bash\n"
        'pip install -e ".[dev]"\n'
        "```\n"
    )
    assert bare_install_offenders(good_readme) == [], (
        "the guard flagged a legitimate from-git/editable install: "
        f"{bare_install_offenders(good_readme)}"
    )
    assert declares_unpublished(good_readme, DISTRIBUTION), (
        "the corrected README shape must be recognised as declaring the "
        "package unpublished"
    )


def test_note_for_another_tool_does_not_satisfy_this_guard() -> None:
    """Control case: the note must name *this* distribution.

    A README that carries a 'Not on PyPI yet' note about some other tool would
    otherwise pass while still promising an install that cannot work.
    """
    text = (
        "# demo\n\n"
        "```bash\n"
        "pip install acc-mcp\n"
        "```\n\n"
        "> **Not on PyPI yet.** Some other tool has no release.\n"
    )
    assert not declares_unpublished(text, DISTRIBUTION), (
        "a note about an unrelated tool must not license a bare install of "
        f"`{DISTRIBUTION}`"
    )