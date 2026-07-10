"""System-user enumerator: list real (shell-having) local accounts so the
correlation engine can test discovered creds against the actual usernames on the
box - not just root/admin. (Lesson from a lab box: reap recovered the reused
password but didn't auto-flag the SSH pivot because the real login user wasn't a candidate.)"""
from __future__ import annotations

from ...models import Finding
from ..base import Module, register

_SHELLS = ("bash", "sh", "zsh", "ash", "fish", "dash")


@register
class SystemUsers(Module):
    name = "system_users"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        out = session.exec("getent passwd 2>/dev/null || cat /etc/passwd", timeout=20).out
        findings = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, _, _, home, shell = parts[:7]
            if shell.rsplit("/", 1)[-1] in _SHELLS:
                findings.append(Finding(type="info", title=f"System user: {user}",
                                        severity="low",
                                        detail=f"uid={uid} home={home} shell={shell}",
                                        source_module=self.name))
        return findings

