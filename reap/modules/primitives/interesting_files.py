"""Interesting files & permissions (linpeas 'interesting perms' pass).

The privesc-by-permission sweep — what can *you*, an unprivileged user, actually
touch? "writable by root" is a non-check (root writes everything); the signal is a
**root-owned thing a non-root user can influence**:

* a root-owned file you can write outright;
* a root-owned file that is **group-writable and you are in that group**;
* a root-owned file inside a **directory you can write** (non-sticky) — you can
  rename it away and drop your own in its place;
* a writable ``$PATH`` directory (command hijack); and the loud ones — a writable
  ``/etc/passwd`` / ``/etc/shadow`` / ``/etc/sudoers``.

Plus readable SSH private keys (reuse for lateral movement / another user's shell).

Scoped and fast by default (curated roots + ``$PATH``); ``REAP_ENUM_FULLFS=1``
sweeps the whole tree. Skipped entirely as root (the whole thing is moot then).
``enum`` shows every cut and flags the exploitable ones; ``collect`` persists the
direct privesc handles.
"""
from __future__ import annotations

import os

from ...models import EnumFlag, EnumSection, Finding
from .._probe import sections
from .._triage import critical_file
from ..base import Module, register

_WRITE_ROOTS = ("/etc /opt /srv /var/www /var/tmp /tmp /dev/shm /home /root "
                "/usr/local /var/backups /var/spool /var/mail")
_OWN_ROOTS = "/etc /opt /srv /var/www /usr/local /root /var/backups /var/spool"
_PRUNE = (r"\( -path /proc -o -path /sys -o -path /dev -o -path /run "
          r"-o -path /snap \) -prune")
_CAP = 80


def _probe_script(fullfs: bool) -> str:
    wr = "/" if fullfs else _WRITE_ROOTS
    ow = "/" if fullfs else _OWN_ROOTS
    hr = "/" if fullfs else "/home /root"
    non_root = '[ "$(id -u)" != 0 ] &&'
    return "\n".join([
        "echo '@@UID@@'; id -u",
        "echo '@@MYGROUPS@@'; id -Gn 2>/dev/null",
        # writable $PATH entries (skip $HOME- and mount-rooted — not privesc)
        "echo '@@PATHW@@'",
        f'{non_root} {{ IFS=:; for d in $PATH; do [ -d "$d" ] && [ -w "$d" ] || continue; '
        'case "$d" in "$HOME"|"$HOME"/*|/mnt/*|/media/*) ;; '
        '*) printf "%s\\n" "$d";; esac; done; }',
        # root-owned files you can write outright
        "echo '@@ROOTWRITE@@'",
        rf'{non_root} find {wr} {_PRUNE} -o \( -uid 0 -writable -type f -print \) '
        rf'2>/dev/null | head -n {_CAP}',
        # root-owned files that are group-writable (filtered to your groups below)
        "echo '@@ROOTGRPW@@'",
        rf"{non_root} find {wr} {_PRUNE} -o \( -uid 0 -perm -020 -type f "
        rf"-printf '%g|%p\n' \) 2>/dev/null | head -n {_CAP}",
        # root-owned files inside a non-sticky directory you can write (replaceable)
        "echo '@@ROOTDIRW@@'",
        rf'{non_root} find {wr} {_PRUNE} -o \( -type d -writable ! -perm -1000 '
        rf'-print \) 2>/dev/null | head -n 50 | while IFS= read -r d; do '
        rf'find "$d" -maxdepth 1 -uid 0 ! -path "$d" 2>/dev/null; done | head -n {_CAP}',
        # readable SSH private keys
        "echo '@@SSHKEYS@@'",
        rf'find {hr} -maxdepth 4 -type f \( -name id_rsa -o -name id_dsa '
        rf'-o -name id_ecdsa -o -name id_ed25519 \) -readable 2>/dev/null | head -n 30',
        # world-writable (kept for completeness; not summarized)
        "echo '@@WORLDW@@'",
        rf'find {wr} {_PRUNE} -o \( -perm -0002 ! -type l \( -type f -o '
        rf'\( -type d ! -perm -1000 \) \) -print \) 2>/dev/null | head -n {_CAP}',
        # files you own in system locations
        "echo '@@OWN@@'",
        rf'find {ow} {_PRUNE} -o \( -user "$(id -un)" ! -path "$HOME/*" -type f '
        rf'-print \) 2>/dev/null | head -n {_CAP}',
        "echo '@@END@@'",
    ])


@register
class InterestingFiles(Module):
    name = "interesting_files"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def _survey(self, session):
        fullfs = bool(os.environ.get("REAP_ENUM_FULLFS"))
        return sections(session.exec(_probe_script(fullfs),
                                     timeout=180 if fullfs else 75).stdout)

    @staticmethod
    def _is_root(sec) -> bool:
        return sec.get("UID", "").strip() == "0"

    @staticmethod
    def _my_groups(sec) -> set:
        return set(sec.get("MYGROUPS", "").split())

    def _grpw_mine(self, sec):
        """(group, path) pairs of root-owned group-writable files in *your* groups."""
        mine = self._my_groups(sec)
        out = []
        for line in sec.get("ROOTGRPW", "").splitlines():
            grp, _, path = line.partition("|")
            if path and grp in mine:
                out.append((grp, path))
        return out

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        sec = self._survey(session)
        if self._is_root(sec):
            return [EnumSection(
                title="Interesting files & permissions",
                lines=["(running as root — every path is writable; "
                       "privesc-by-permission checks are moot)"])]
        scope = "full /" if os.environ.get("REAP_ENUM_FULLFS") else "scoped roots"
        pathw = sec.get("PATHW", "").splitlines()
        rootw = sec.get("ROOTWRITE", "").splitlines()
        grpw = self._grpw_mine(sec)
        dirw = sec.get("ROOTDIRW", "").splitlines()
        keys = sec.get("SSHKEYS", "").splitlines()
        worldw = sec.get("WORLDW", "").splitlines()
        own = sec.get("OWN", "").splitlines()
        home = (os.environ.get("HOME") or "").rstrip("/")

        def rootw_flags():
            out = []
            for p in rootw[:20]:
                p = p.strip()
                if not p:
                    continue
                crit = critical_file(p)
                out.append(EnumFlag(text=p, level="alert",
                                    reason=crit or "root-owned and you can write it"))
            return out

        def key_flags():
            out = []
            for k in keys[:20]:
                k = k.strip()
                if not k:
                    continue
                mine = home and k.startswith(home + "/")
                out.append(EnumFlag(
                    text=k, level="notice" if mine else "alert",
                    reason="your SSH private key (reuse for lateral)" if mine
                    else "readable SSH private key (not yours) — reuse for another shell"))
            return out

        return [
            EnumSection(
                title=f"Writable directories in $PATH  [{scope}]", lines=pathw,
                hint="drop a binary named like a command run by a higher-priv user here",
                flags=[EnumFlag(text=d.strip(), level="alert",
                                reason="writable $PATH dir — command-hijack primitive")
                       for d in pathw[:15] if d.strip()]),
            EnumSection(
                title="Root-owned files you can write", lines=rootw,
                hint="if a root cron/service/login path reads or runs one, editing it "
                     "is direct privesc (captured by 'run')",
                flags=rootw_flags()),
            EnumSection(
                title="Root-owned files writable via your group",
                lines=[f"{g}  {p}" for g, p in grpw],
                hint="root owns these but they're group-writable and you're in the group",
                flags=[EnumFlag(text=p, level="alert",
                                reason=f"root-owned & group-writable via your '{g}' group")
                       for g, p in grpw[:20]]),
            EnumSection(
                title="Root-owned files in a directory you can write", lines=dirw,
                hint="you can't write the file, but you own its dir — rename it away "
                     "and drop your own",
                flags=[EnumFlag(text=p.strip(), level="alert",
                                reason="root-owned, but you can write its directory → replace it")
                       for p in dirw[:20] if p.strip()]),
            EnumSection(
                title="Readable SSH private keys", lines=keys, flags=key_flags()),
            EnumSection(
                title="World-writable files & dirs", lines=worldw,
                hint="anyone can modify these; noisy, so not summarized — skim for "
                     "one a trusted process consumes"),
            EnumSection(
                title="Files you own in system locations", lines=own,
                flags=[EnumFlag(text=p.strip(), level="notice",
                                reason="you own this in a system location")
                       for p in own[:15] if p.strip()]),
        ]

    # -- collect (persist the direct privesc handles) --------------------------
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
                           "user/process here to hijack it.", source_module=self.name))
        for p in sec.get("ROOTWRITE", "").splitlines():
            p = p.strip()
            if p:
                crit = critical_file(p)
                findings.append(Finding(
                    type="misconfig", severity="high",
                    title=f"Root-owned file writable by you: {p}",
                    detail=(crit or "a root-owned file you can modify — privesc if a "
                            "root cron/service/login path reads or runs it."),
                    source_module=self.name))
        for g, p in self._grpw_mine(sec):
            findings.append(Finding(
                type="misconfig", severity="high",
                title=f"Root-owned file group-writable via {g}: {p}",
                detail=f"root owns it but it's group-writable and you're in '{g}' — "
                       "you can modify it.", source_module=self.name))
        for p in sec.get("ROOTDIRW", "").splitlines():
            p = p.strip()
            if p:
                findings.append(Finding(
                    type="misconfig", severity="high",
                    title=f"Root-owned file in a dir you can write: {p}",
                    detail="you can rename this root-owned file away and drop your own "
                           "in its place.", source_module=self.name))
        return findings
