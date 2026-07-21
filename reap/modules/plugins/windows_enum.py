r"""Windows service / scheduled-task / process inventory (winpeas-style).

The Windows counterpart to the Linux ``processes`` / ``init_services`` primitives.
``enumerate`` dumps services (with their logon account + binary path), non-disabled
scheduled tasks, and processes with full command lines. ``collect`` persists:

* **unquoted service paths** with a space — the classic Windows privesc (a writable
  intermediate dir lets an attacker plant ``C:\Program.exe``);
* secrets on a process command line.

Everything is best-effort over PowerShell; a channel without PowerShell just yields
empty sections. Delimiters are single-quoted so the outer ``-c "..."`` stays clean
across cmd / WinRM / webshell transports.
"""
from __future__ import annotations

import re

from ...models import Credential, EnumSection, Finding
from ...patterns import inline_cmdline_secret, mask, scan_line
from ..base import Module, register

_PS = "powershell -nop -c "

# Structured (pipe-delimited) queries for collect() — reliable to parse.
_SVC_ROWS = _PS + '"Get-CimInstance Win32_Service | ForEach-Object { $_.Name + \'|\' + $_.StartName + \'|\' + $_.PathName }"'
_PROC_ROWS = _PS + '"Get-CimInstance Win32_Process | ForEach-Object { [string]$_.ProcessId + \'|\' + $_.CommandLine }"'

# Pretty (Format-Table) queries for enumerate() — for the operator's eyes.
_SVC_TABLE = _PS + '"Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName | Format-Table -AutoSize | Out-String -Width 400"'
_TASK_TABLE = _PS + '"Get-ScheduledTask | Where-Object {$_.State -ne \'Disabled\'} | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize | Out-String -Width 300"'
_PROC_TABLE = _PS + '"Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Format-Table -AutoSize | Out-String -Width 500"'

_CMD_PW = re.compile(r"(?i)(?:/|--?)(?:password|passwd|pass|pw)[:=\s]+(\S+)")


def _lines(text: str) -> list[str]:
    return [ln for ln in (text or "").splitlines() if ln.strip()]


def _unquoted_service_path(pathname: str) -> bool:
    """True if an unquoted binary path contains a space before `.exe` — plantable."""
    p = (pathname or "").strip()
    if not p or p.startswith('"'):
        return False
    low = p.lower()
    if low.startswith("c:\\windows"):        # system dirs: rarely user-writable
        return False
    idx = low.find(".exe")
    return idx != -1 and " " in p[:idx]


@register
class WindowsEnum(Module):
    name = "windows_enum"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows"

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        return [
            EnumSection(title="Services",
                        lines=_lines(session.sh(_SVC_TABLE, timeout=60)),
                        hint="unquoted paths with spaces + non-standard logon "
                             "accounts are privesc leads ('run' flags unquoted paths)"),
            EnumSection(title="Scheduled tasks",
                        lines=_lines(session.sh(_TASK_TABLE, timeout=60))),
            EnumSection(title="Processes",
                        lines=_lines(session.sh(_PROC_TABLE, timeout=60)),
                        hint="secrets on command lines are captured by 'run'"),
        ]

    # -- collect (persist actionable subset) -----------------------------------
    def collect(self, session):
        findings: list[Finding] = []

        for row in _lines(session.sh(_SVC_ROWS, timeout=60)):
            parts = row.split("|", 2)
            if len(parts) < 3:
                continue
            name, account, path = parts
            if _unquoted_service_path(path):
                findings.append(Finding(
                    type="misconfig", severity="medium",
                    title=f"Unquoted service path: {name}",
                    detail=f"{path.strip()} (runs as {account.strip() or '?'}) — check "
                           f"whether an intermediate dir is writable, then plant a binary.",
                    source_module=self.name))

        for row in _lines(session.sh(_PROC_ROWS, timeout=60)):
            pid, _, cmdline = row.partition("|")
            if not cmdline.strip():
                continue
            src = f"process pid {pid.strip()}"
            scanned = scan_line(cmdline, src)
            for f in scanned:
                f.severity = "high"
                f.source_module = self.name
                f.title = f"Secret on command line: {f.title}"
                findings.append(f)
            if not any(f.credential for f in scanned):
                for m in _CMD_PW.finditer(cmdline):
                    val = m.group(1)
                    if not inline_cmdline_secret(val):
                        continue
                    findings.append(Finding(
                        type="credential", severity="high",
                        title=f"Password on command line (pid {pid.strip()})",
                        detail=f"{cmdline.split()[0][:60]} … {mask(val)}",
                        credential=Credential(kind="password", secret=val, source=src,
                                              metadata={"via": "cmdline"}),
                        source_module=self.name))
                    break
        return findings
