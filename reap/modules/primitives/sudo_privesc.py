"""sudo -l / SUID / capabilities / writable-cron — the cheapest, loudest Linux
privesc signals, ranked as misconfig findings. Collect-only: reap names the
technique (GTFOBins-style hint) and stops; it does not exploit.

Rationale: on one lab box the root path was a root-run cron script that the secret
scanner caught only incidentally — a dedicated check flags that class as a
ranked finding instead of a lucky grep.
"""
from __future__ import annotations

from ...models import Finding
from ..base import Module, register

# Standard SUID binaries that are boring; anything else is worth a look.
_SUID_ALLOW = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "newgrp",
    "gpasswd", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "ntfs-3g", "at", "crontab", "ssh-keysign", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "unix_chkpwd", "chrome-sandbox",
    "vmware-user-suid-wrapper", "sudoedit", "expiry", "usernetctl",
}


@register
class SudoPrivesc(Module):
    name = "sudo_privesc"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        findings = []
        findings += self._sudo(session)
        findings += self._suid(session)
        findings += self._caps(session)
        findings += self._cron(session)
        return findings

    def _sudo(self, session):
        out = []
        res = session.exec("sudo -n -l 2>/dev/null", timeout=20).stdout  # -n never prompts
        for line in res.splitlines():
            s = line.strip()
            if "NOPASSWD:" in s:
                out.append(Finding(
                    type="misconfig", severity="high", title="sudo NOPASSWD entry",
                    detail=f"{s} — run as the target directly; check GTFOBins for a "
                           f"shell/file-write/read primitive.", source_module=self.name))
            elif s.startswith("(") and ")" in s and ("ALL" in s or "/" in s):
                out.append(Finding(
                    type="misconfig", severity="medium",
                    title="sudo rule (password required)", detail=s,
                    source_module=self.name))
        return out

    def _suid(self, session):
        out = []
        res = session.exec("find / -perm -4000 -type f 2>/dev/null | head -n 200",
                           timeout=60).stdout
        for line in res.splitlines():
            path = line.strip()
            if not path:
                continue
            base = path.rsplit("/", 1)[-1]
            if base in _SUID_ALLOW:
                continue
            out.append(Finding(
                type="misconfig", severity="medium", title=f"Non-standard SUID: {base}",
                detail=f"{path} — check GTFOBins for a SUID escalation.",
                source_module=self.name))
        return out

    def _caps(self, session):
        out = []
        res = session.exec("getcap -r / 2>/dev/null | head -n 100", timeout=45).stdout
        for line in res.splitlines():
            s = line.strip()
            if not s:
                continue
            sev = "high" if any(c in s for c in
                                ("cap_setuid", "cap_dac_override", "cap_dac_read_search",
                                 "cap_sys_admin", "cap_sys_ptrace")) else "medium"
            out.append(Finding(type="misconfig", severity=sev,
                               title="Linux capability set", detail=s,
                               source_module=self.name))
        return out

    def _cron(self, session):
        out = []
        writ = session.exec(
            "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly "
            "/etc/cron.monthly /etc/crontab -writable 2>/dev/null | head -n 40",
            timeout=30).stdout
        for line in writ.splitlines():
            p = line.strip()
            if p:
                out.append(Finding(
                    type="misconfig", severity="high", title=f"Writable cron path: {p}",
                    detail="a root-run cron may execute this — direct privesc.",
                    source_module=self.name))
        return out
