"""Windows / AD account harvester so correlation has real usernames to test over
WinRM/SMB (it otherwise knows only the Linux 'System user:' convention plus three
defaults). Emits the SAME 'System user: <name>' title the engine already reads,
so no correlation change is needed.
"""
from __future__ import annotations

import re

from ...models import Finding
from ..base import Module, register

_SKIP = {"the", "command", "completed", "successfully", "user", "accounts", "for",
         "-------------------------------------------------------------------------------"}


@register
class WindowsUsers(Module):
    name = "windows_users"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows"

    def collect(self, session):
        findings = []
        seen: set[str] = set()
        findings += self._accounts(session.exec("net user", timeout=30).stdout, seen)
        # domain_joined isn't visible in collect(); these no-op cleanly off-domain.
        for cmd in ('net user /domain',
                    'net group "Domain Admins" /domain',
                    'net localgroup Administrators'):
            findings += self._accounts(session.exec(cmd, timeout=30).stdout, seen)
        return findings

    def _accounts(self, out: str, seen: set) -> list:
        findings = []
        for line in out.splitlines():
            s = line.strip()
            if not s or "\\" in s or "command completed" in s.lower():
                continue
            # `net user` lists accounts in space-separated columns.
            for name in re.split(r"\s{2,}", s):
                name = name.strip().lstrip("*")
                if (not name or " " in name or name.lower() in _SKIP
                        or name.startswith("-") or name in seen):
                    continue
                seen.add(name)
                findings.append(Finding(
                    type="info", severity="low", title=f"System user: {name}",
                    detail="windows account (correlation username seed)",
                    source_module=self.name))
        return findings
