"""Shared single-pass secret grep.

secret_scanner and config_harvester used to each re-walk the same directory tree
with the same alternation — 2-3x the disk traversal, brutal over a webshell. This
runs the broad grep ONCE per (session, dir-set) and memoizes the parsed lines, so
the second consumer is free. Not a Module (no @register) — just a helper.
"""
from __future__ import annotations

import re
import shlex

from ...patterns import GREP_ALTERNATION

_GREP_LINE = re.compile(r"^(.*?):(\d+):(.*)$")

_EXCLUDES = (
    "--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor "
    "--exclude-dir=site-packages --exclude-dir=__pycache__ --exclude-dir=dist "
    "--exclude-dir=build --exclude-dir=assets --exclude-dir=debugbar "
    "--exclude-dir=cache --exclude=*.min.js --exclude=*.min.css"
)

_cache: dict = {}


def grep_pass(session, dirs, timeout: int = 120, cap: int = 400):
    """Return parsed (path, lineno, content) tuples from one broad grep over
    ``dirs``. Memoized by (session_id, dir-set) so repeat callers don't re-walk."""
    key = (getattr(session, "session_id", id(session)), frozenset(dirs))
    if key in _cache:
        return _cache[key]
    dir_args = " ".join(shlex.quote(d) for d in dirs)
    cmd = (f"grep -rEni --binary-files=without-match {_EXCLUDES} "
           f"-e {shlex.quote(GREP_ALTERNATION)} {dir_args} 2>/dev/null | head -n {cap}")
    rows = []
    for line in session.exec(cmd, timeout=timeout).stdout.splitlines():
        m = _GREP_LINE.match(line)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3)))
    _cache[key] = rows
    return rows


def clear_cache() -> None:
    """Drop the cache (e.g. between runs on the same long-lived session)."""
    _cache.clear()
