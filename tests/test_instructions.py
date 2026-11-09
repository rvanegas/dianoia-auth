"""CLAUDE.md stays within the cap every project shares, per technosophia's `ts instructions check`.

A thin wrapper rather than a reimplementation, so the cap lives in one place. It runs the
script by path, `$TECHNOSOPHIA` or ~/src/technosophia, since a test does not rely on PATH.
"""

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TECHNOSOPHIA = Path(os.environ.get("TECHNOSOPHIA", Path.home() / "src" / "technosophia"))


def test_claude_md_is_within_the_cap():
    run = subprocess.run([TECHNOSOPHIA / "bin" / "instructions", "check"], cwd=REPO,
                         env={**os.environ, "TS_ROOT": str(REPO)}, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr + run.stdout


def test_planning_holds_its_invariants():
    run = subprocess.run([TECHNOSOPHIA / "bin" / "note", "check"], cwd=REPO,
                         env={**os.environ, "TS_ROOT": str(REPO)}, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr + run.stdout
