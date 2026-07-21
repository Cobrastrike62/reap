"""Interesting files & permissions (linpeas 'interesting perms' pass).

The privesc-by-permission sweep: what can *you* write, and what do you own where
you shouldn't. Note the framing —

* "writable by root" is not a check (root writes everything); the signal is what
  the **current, unprivileged** user can write, and the gold is a **root-owned
  file the current user can write**;
* "owned by root" is most of the filesystem (noise); the useful cuts are files
  the current user owns in **system locations** and the root-owned-writable
  intersection above.

Scoped and fast by default (a curated set of roots + ``$PATH``), pruning the
pseudo-filesystems; set ``REAP_ENUM_FULLFS=1`` to sweep the whole tree like
linpeas (slower, noisier — think twice over a raw shell). Running as root the
whole sweep is meaningless, so it is skipped with a note.

``enum`` shows all four cuts; ``collect`` persists the two that are direct privesc
handles — a writable ``$PATH`` directory and a root-owned file you can write.
"""
from __future__ import annotations

import os

from ...models import EnumSection, Finding
from .._probe import sections
from ..base import Module, register

# Curated roots for the scoped sweep. WRITE_ROOTS: places worth checking for
# writability; OWN_ROOTS: places you should not normally own files (so /tmp,
# /home and /dev/shm are excluded — your own files there are expected noise).
_WRITE_ROOTS = ("/etc /opt /srv /var/www /var/tmp /tmp /dev/shm /home /root "
                "/usr/local /var/backups /var/spool /var/mail")
_OWN_ROOTS = "/etc /opt /srv /var/www /usr/local /root /var/backups /var/spool"
_PRUNE = (r"\( -path /proc -o -path /sys -o -path /dev -o -path /run "
          r"-o -path /snap \) -prune")
_CAP = 80  # per-section result cap


def _probe_script(fullfs: bool) -> str:
    wr = "/" if fullfs else _WRITE_ROOTS
    ow = "/" if fullfs else _OWN_ROOTS
    return "\n".join([
        "echo '@@UID@@'; id -u",
        # Writable $PATH entries — a command-hijack primitive (skip as root, and
        # skip $HOME-rooted entries: your own ~/.local/bin being writable is not
        # privesc — only a *system* PATH dir you can write is).
        "echo '@@PATHW@@'",
        '[ "$(id -u)" != 0 ] && { IFS=:; for d in $PATH; do '
        '[ -d "$d" ] && [ -w "$d" ] || continue; '
        'case "$d" in "$HOME"|"$HOME"/*) ;; *) printf "%s\\n" "$d";; esac; '
        'done; }',
        # Root-owned files the current user can write — the escalation gold.
        "echo '@@ROOTWRITE@@'",
        rf'[ "$(id -u)" != 0 ] && find {wr} {_PRUNE} -o '
        rf'\( -uid 0 -writable -type f -print \) 2>/dev/null | head -n {_CAP}',
        # World-writable regular files and non-sticky dirs (skip symlinks/sticky).
        "echo '@@WORLDW@@'",
        rf'find {wr} {_PRUNE} -o \( -perm -0002 ! -type l '
        rf'\( -type f -o \( -type d ! -perm -1000 \) \) -print \) '
        rf'2>/dev/null | head -n {_CAP}',
        # Files the current user owns in system locations (outside $HOME).
        "echo '@@OWN@@'",
        rf'find {ow} {_PRUNE} -o \( -user "$(id -un)" ! -path "$HOME/*" '
        rf'-type f -print \) 2>/dev/null | head -n {_CAP}',
        "echo '@@END@@'",
    ])


@register
class InterestingFiles(Module):
    name = "interesting_files"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def _survey(self, session):
        fullfs = bool(os.environ.get("REAP_ENUM_FULLFS"))
        # A full-tree sweep needs a much larger window than the scoped default.
        timeout = 180 if fullfs else 60
        return sections(session.exec(_probe_script(fullfs), timeout=timeout).stdout)

    def _is_root(self, sec) -> bool:
        return sec.get("UID", "").strip() == "0"

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        sec = self._survey(session)
        if self._is_root(sec):
            return [EnumSection(
                title="Interesting files & permissions",
                lines=["(running as root — every path is writable; "
                       "privesc-by-permission checks are moot)"])]
        scope = "full /" if os.environ.get("REAP_ENUM_FULLFS") else "scoped roots"
        return [
            EnumSection(
                title=f"Writable directories in $PATH  [{scope}]",
                lines=sec.get("PATHW", "").splitlines(),
                hint="drop a binary named like a command here to hijack it when a "
                     "higher-priv user or process runs that command"),
            EnumSection(
                title="Root-owned files you can write",
                lines=sec.get("ROOTWRITE", "").splitlines(),
                hint="if a root cron/service/login path reads or runs one of these, "
                     "editing it is direct privesc (captured by 'run')"),
            EnumSection(
                title="World-writable files & dirs",
                lines=sec.get("WORLDW", "").splitlines(),
                hint="anyone can modify these; interesting if something trusted "
                     "consumes them"),
            EnumSection(
                title="Files you own in system locations",
                lines=sec.get("OWN", "").splitlines()),
        ]

    # -- collect (persist the two privesc handles) -----------------------------
    def collect(self, session):
        sec = self._survey(session)
        if self._is_root(sec):
            return []
        findings: list[Finding] = []
        for d in sec.get("PATHW", "").splitlines():
            d = d.strip()
            if d:
                findings.append(Finding(
                    type="misconfig", severity="high",
                    title=f"Writable directory in $PATH: {d}",
                    detail="drop a binary named like a command run by a higher-priv "
                           "user/process here to hijack it.",
                    source_module=self.name))
        for p in sec.get("ROOTWRITE", "").splitlines():
            p = p.strip()
            if p:
                findings.append(Finding(
                    type="misconfig", severity="high",
                    title=f"Root-owned file writable by you: {p}",
                    detail="a root-owned file you can modify — if a root cron / service "
                           "/ login path reads or executes it, that is privesc.",
                    source_module=self.name))
        return findings
