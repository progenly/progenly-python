"""Guard against the packaged ``__version__`` drifting from pyproject's version
(they were out of sync once: pyproject 0.4.0 vs ``__version__`` 0.3.0).

pyproject is parsed with a tiny regex rather than tomllib so the test runs
unchanged on Python 3.9/3.10 (no stdlib tomllib) through 3.13.
"""
import re
from pathlib import Path

import progenly


def _pyproject_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', text)
    assert m, "could not find version in pyproject.toml"
    return m.group(1)


def test_version_matches_pyproject():
    assert progenly.__version__ == _pyproject_version()
