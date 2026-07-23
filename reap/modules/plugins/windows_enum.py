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

from ...models import Credential, EnumFlag, EnumSection, Finding
from ...patterns import inline_cmdline_secret, mask, scan_line
from ..base import Module, register

_PS = "powershell -nop -c "

# Structured (pipe-delimited) queries — reliable to parse, and readable enough to
# also drive the enumerate() display (single-quoted delimiter keeps -c "..." clean).
_SVC_ROWS = _PS + '"Get-CimInstance Win32_Service | ForEach-Object { $_.Name + \'|\' + $_.StartName + \'|\' + $_.PathName }"'
_PROC_ROWS = _PS + '"Get-CimInstance Win32_Process | ForEach-Object { [string]$_.ProcessId + \'|\' + $_.CommandLine }"'
_TASK_TABLE = _PS + '"Get-ScheduledTask | Where-Object {$_.State -ne \'Disabled\'} | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize | Out-String -Width 300"'

_CMD_PW = re.compile(r"(?i)(?:/|--?)(?:password|passwd|pass|pw)[:=\s]+(\S+)")

# Directory fragments that make a service/process binary "out of place" on Windows.
_WIN_INTERESTING = ("\\users\\", "\\temp\\", "\\tmp\\", "\\programdata\\",
                    "\\inetpub\\", "\\appdata\\", "\\public\\", "\\perflogs\\")
# Built-in service logon accounts — anything else is a custom/service/domain account.
_STD_ACCOUNTS = {"localsystem", "localservice", "networkservice", "",
                 "nt authority\\system", "nt authority\\localservice",
                 "nt authority\\networkservice", "nt authority\\local service",
                 "nt authority\\network service"}


def _lines(text: str) -> list[str]:
    return [ln for ln in (text or "").splitlines() if ln.strip()]


def _win_interesting(path: str):
    low = (path or "").lower()
    for frag in _WIN_INTERESTING:
        if frag in low:
            return frag.strip("\\")
    return None


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
        svc_rows = _lines(session.sh(_SVC_ROWS, timeout=60))
        proc_rows = _lines(session.sh(_PROC_ROWS, timeout=60))
        return [
            EnumSection(
                title="Services",
                lines=[r.replace("|", "  ") for r in svc_rows] or ["(none)"],
                hint="unquoted paths, non-standard logon accounts, and binaries "
                     "outside Windows are flagged (unquoted are captured by 'run')",
                flags=self._svc_flags(svc_rows)),
            EnumSection(title="Scheduled tasks (enabled)",
                        lines=_lines(session.sh(_TASK_TABLE, timeout=60))),
            EnumSection(
                title="Processes",
                lines=[r.replace("|", "  ", 1) for r in proc_rows] or ["(none)"],
                hint="secrets on command lines and processes from user/temp dirs "
                     "are flagged (secrets captured by 'run')",
                flags=self._proc_flags(proc_rows)),
        ]

    def _svc_flags(self, rows) -> list:
        flags = []
        for row in rows:
            parts = row.split("|", 2)
            if len(parts) < 3:
                continue
            name, account, path = (p.strip() for p in parts)
            label = f"{name}: {path}"
            if _unquoted_service_path(path):
                flags.append(EnumFlag(text=label, level="alert",
                                      reason="unquoted service path with a space — "
                                             "plantable if an intermediate dir is writable"))
            elif _win_interesting(path):
                flags.append(EnumFlag(text=label, level="notice",
                                      reason=f"binary under {_win_interesting(path)} "
                                             "(outside Windows)"))
            elif account.lower() not in _STD_ACCOUNTS:
                flags.append(EnumFlag(text=f"{name} (runs as {account})", level="notice",
                                      reason="non-standard service logon account"))
            if len(flags) >= 40:
                break
        return flags

    def _proc_flags(self, rows) -> list:
        flags = []
        for row in rows:
            pid, _, cmdline = row.partition("|")
            if not cmdline.strip():
                continue
            label = f"{pid.strip()} {cmdline.strip()}"[:140]
            has_secret = any(f.credential for f in scan_line(cmdline, "cmdline")) or any(
                inline_cmdline_secret(m.group(1)) for m in _CMD_PW.finditer(cmdline))
            if has_secret:
                flags.append(EnumFlag(text=label, level="alert",
                                      reason="secret on the command line"))
            elif _win_interesting(cmdline):
                flags.append(EnumFlag(text=label, level="notice",
                                      reason=f"runs from {_win_interesting(cmdline)}"))
            if len(flags) >= 40:
                break
        return flags

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
