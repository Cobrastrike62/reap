"""Helpers shared by the enumeration modules (processes / cron_jobs /
init_services / system_snapshot).

Two things every enumerator wants and shouldn't reinvent:

* :func:`sections` — split one marker-delimited probe into labeled blocks, so a
  full inventory costs a *single* round-trip. Cheap over SSH, and it matters over
  a raw reverse/bind shell where each command is a slow sentinel-framed exchange.
* :func:`writable_targets` — given paths pulled out of cron/service definitions,
  return the subset the current user can write (the privesc-relevant ones). It is
  the writability, not the mere reference, that turns a service/cron into a
  finding — so this does the filtering the collectors rank on.

Probe scripts MUST NOT end in a newline: the raw-shell adapter appends
``; printf <sentinel>`` to the command, and a trailing newline would produce a
lone ``; printf`` line (a shell syntax error). Build them with ``.strip()``.
"""
from __future__ import annotations

import shlex

from ..transport.base import Session


def sections(text: str) -> dict[str, str]:
    """Split ``@@NAME@@``-delimited probe output into ``{NAME: block}``.

    Mirrors ``fingerprint._sections`` — a lone ``@@`` or a marker mid-line is
    ignored so a section body that happens to print ``@@`` doesn't confuse it.
    """
    out: dict[str, str] = {}
    cur: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@@") and s.endswith("@@") and len(s) > 4:
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = s.strip("@"), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


# Pseudo-filesystems whose writable nodes are not privesc handles — /dev/null &
# friends are world-writable by design and litter cron/service redirects.
_PSEUDO_FS = ("/dev/", "/proc/", "/sys/", "/run/")


def writable_targets(session: Session, paths, limit: int = 60,
                     ignore_prefixes: tuple = _PSEUDO_FS) -> set[str]:
    """Of ``paths``, return those writable by the current user.

    One single-line command (``[ -w P ] && echo P; ...``) rather than a heredoc
    or a ``for`` loop, so it survives the raw-shell channel too; each path is
    shell-quoted so spaces don't split the test. Pseudo-fs paths are dropped
    (``/dev/null`` is writable but meaningless), then de-duplicated and capped.
    """
    uniq = list(dict.fromkeys(
        p for p in paths if p and not p.startswith(ignore_prefixes)))[:limit]
    if not uniq:
        return set()
    probe = "; ".join(
        f'[ -w {shlex.quote(p)} ] && printf "%s\\n" {shlex.quote(p)}' for p in uniq
    )
    out = session.exec(probe, timeout=30).stdout
    return {ln.strip() for ln in out.splitlines() if ln.strip()}
