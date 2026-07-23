"""Process inventory (linpeas `ps` view).

``enumerate`` dumps the full process list for situational awareness. ``collect``
keeps only the loud, actionable classes so the findings list stays ranked:

* a secret on a command line — passwords passed as args are world-readable via
  ``/proc/<pid>/cmdline`` / ``ps``, a classic cred leak;
* a root-owned process whose executable lives under a user-writable path
  (``/tmp``, ``/dev/shm``, ``/home`` ...), i.e. a likely privesc handle.

The full list is screen-only on purpose (a busy host has hundreds of rows).
"""
from __future__ import annotations

import re

from ...models import Credential, EnumFlag, EnumSection, Finding
from ...patterns import inline_cmdline_secret, mask, scan_line
from .._triage import interesting_bin, interesting_path
from ..base import Module, register

# `-ww` = don't truncate long command lines (that is where the secrets hide);
# `-o user=,pid=,args=` = no header, just the three columns we parse. Fall back
# to BSD-style `ps aux` on busybox/odd userlands.
_PS_PRIMARY = "ps -eww -o user=,pid=,args= 2>/dev/null"
_PS_FALLBACK = "ps aux 2>/dev/null"

_MAX_ROWS = 250  # screen cap for the enumerate() dump

# Executables running out of these read/write-by-user roots are worth a look.
_WRITABLE_ROOTS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/run/user/")

# Kernel threads (`[kworker/0]`) — noise; drop from the dump.
_KTHREAD = re.compile(r"^\[.*\]$")
# Password-bearing switches on a command line that scan_line's KEY= shapes miss
# (e.g. a bare `--password Secret`). Values are vetted by inline_cmdline_secret so
# a `-passwd /path/to/file` reference isn't mistaken for a literal secret.
_CMD_PW = re.compile(r"(?i)(?:--?password|--?passwd|--?pass|--?pw)[=\s]+(\S+)")


@register
class Processes(Module):
    name = "processes"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    # -- shared collection -----------------------------------------------------
    def _rows(self, session):
        """Return [(user, pid, args)] from the richest `ps` we can get."""
        out = session.exec(_PS_PRIMARY, timeout=25).out
        rows, fallback = [], False
        if not out.strip():
            out = session.exec(_PS_FALLBACK, timeout=25).out
            fallback = True
        for line in out.splitlines():
            if not line.strip():
                continue
            if fallback:  # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                parts = line.split(None, 10)
                if len(parts) < 11 or parts[1].upper() == "PID":
                    continue
                rows.append((parts[0], parts[1], parts[10]))
            else:
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                rows.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
        return rows

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        rows = [r for r in self._rows(session) if not _KTHREAD.match(r[2].strip())]
        lines = [f"{u:<12.12} {pid:>7} {args}" for u, pid, args in rows[:_MAX_ROWS]]
        if len(rows) > _MAX_ROWS:
            lines.append(f"... ({len(rows) - _MAX_ROWS} more; refine with grep)")
        flags = []
        for user, pid, args in rows:
            fl = self._flag_row(user, pid, args)
            if fl:
                flags.append(fl)
            if len(flags) >= 40:
                break
        return [EnumSection(
            title="Processes",
            lines=lines or ["(ps returned nothing)"],
            hint="flagged: non-system paths, interpreters/tools, secrets on the "
                 "command line (root-owned + writable ones are captured by 'run')",
            flags=flags,
        )]

    def _has_secret(self, args):
        if any(f.credential for f in scan_line(args, "cmdline")):
            return True
        return any(inline_cmdline_secret(m.group(1)) for m in _CMD_PW.finditer(args))

    def _flag_row(self, user, pid, args):
        label = f"{user} {pid} {args}".strip()
        if len(label) > 140:
            label = label[:137] + "..."
        if self._has_secret(args):
            return EnumFlag(text=label, level="alert",
                            reason="secret on the command line")
        ip = interesting_path(args)
        if ip:
            root = user == "root"
            return EnumFlag(text=label, level="alert" if root else "notice",
                            reason=f"runs from {ip}{' as root' if root else ''} "
                                   "(outside the base system)")
        ib = interesting_bin(args.split()[0] if args.split() else "")
        if ib:
            kind = "operator/attacker tool" if ib[0] == "tool" else "interpreter/app"
            return EnumFlag(text=label, level="notice", reason=f"{ib[1]} — {kind}")
        return None

    # -- collect (persist actionable subset) -----------------------------------
    def collect(self, session):
        findings: list[Finding] = []
        for user, pid, args in self._rows(session):
            if not args or _KTHREAD.match(args.strip()):
                continue
            src = f"process pid {pid} ({user})"
            scanned = scan_line(args, src)
            for f in scanned:
                f.severity = "high"
                f.source_module = self.name
                f.title = f"Secret on command line: {f.title}"
                findings.append(f)
            # Only fall back to switch-matching when scan_line's KEY= shapes found
            # nothing (a bare `--password secret` has no '=' for scan_line to see).
            if not any(f.credential for f in scanned):
                for m in _CMD_PW.finditer(args):
                    val = m.group(1)
                    if not inline_cmdline_secret(val):
                        continue
                    findings.append(Finding(
                        type="credential", severity="high",
                        title=f"Password on command line (pid {pid})",
                        detail=f"{user}: {args.split()[0][:60]} … {mask(val)}",
                        credential=Credential(kind="password", secret=val, source=src,
                                              metadata={"via": "cmdline", "pid": pid}),
                        source_module=self.name))
                    break
            # First few tokens catch both `/tmp/x` and `python /tmp/x.py` forms.
            if user == "root" and any(
                    t.startswith(_WRITABLE_ROOTS) for t in args.split()[:3]):
                findings.append(Finding(
                    type="misconfig", severity="medium",
                    title=f"Root process from writable path (pid {pid})",
                    detail=f"{args[:200]} — if you can write the target, you may "
                           f"influence a root-run process.",
                    source_module=self.name))
        return findings
