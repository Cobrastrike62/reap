"""Service inventory (linpeas services view) — systemd units + SysV fallback.

Distinct from ``listening_services`` (which turns *network listeners* into Service
rows for correlation): this surveys the init system itself.

``enumerate`` lists running and enabled-at-boot services. ``collect`` persists the
classic systemd privesc handles:

* a **writable unit file** — you own the service definition, so you own its
  ``ExecStart`` (runs as whatever ``User=`` the unit declares, usually root);
* a writable binary named in an **ExecStart=** — same outcome without touching the
  unit;
* a secret embedded in an ``ExecStart=`` line.
"""
from __future__ import annotations

import re

from ...models import EnumSection, Finding
from ...patterns import scan_line
from .._probe import sections, writable_targets
from ..base import Module, register

_UNIT_DIRS = ("/etc/systemd/system /run/systemd/system "
              "/usr/lib/systemd/system /lib/systemd/system")

_SVC_PROBE = (r"""
echo '@@RUNNING@@'; systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -n 200
echo '@@ENABLED@@'; systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | head -n 200
echo '@@SYSV@@'; service --status-all 2>/dev/null; ls /etc/init.d 2>/dev/null
echo '@@WRITABLE_UNIT@@'; find """ + _UNIT_DIRS + r""" -maxdepth 2 -writable -type f 2>/dev/null | head -n 60
echo '@@EXECSTART@@'; grep -rhoE '^[[:space:]]*ExecStart=.*' """ + _UNIT_DIRS + r""" 2>/dev/null | head -n 400
echo '@@END@@'
""").strip()

# ExecStart= may prefix the binary with -, @, +, !, !! (systemd modifiers).
_EXECSTART = re.compile(r"ExecStart\s*=\s*[-@+!]*\s*(\S+)")


@register
class InitServices(Module):
    name = "init_services"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def _survey(self, session):
        return sections(session.exec(_SVC_PROBE, timeout=45).stdout)

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        sec = self._survey(session)
        out = [
            EnumSection(title="Running services",
                        lines=sec.get("RUNNING", "").splitlines(),
                        hint="writable unit files / ExecStart binaries are captured "
                             "by 'run' (systemd privesc)"),
            EnumSection(title="Enabled-at-boot services",
                        lines=sec.get("ENABLED", "").splitlines()),
        ]
        if sec.get("SYSV"):
            out.append(EnumSection(title="SysV / init.d",
                                   lines=sec["SYSV"].splitlines()))
        return out

    # -- collect (persist actionable subset) -----------------------------------
    def collect(self, session):
        sec = self._survey(session)
        findings: list[Finding] = []

        for path in sec.get("WRITABLE_UNIT", "").splitlines():
            path = path.strip()
            if path:
                findings.append(Finding(
                    type="misconfig", severity="high",
                    title=f"Writable systemd unit: {path}",
                    detail="you can edit this unit's ExecStart — runs as the unit's "
                           "User= (root unless set otherwise).",
                    source_module=self.name))

        execstarts = sec.get("EXECSTART", "")
        bins: list[str] = []
        for line in execstarts.splitlines():
            m = _EXECSTART.search(line)
            if m and m.group(1).startswith("/"):
                bins.append(m.group(1))
            for f in scan_line(line, "systemd ExecStart"):
                f.source_module = self.name
                findings.append(f)

        for path in writable_targets(session, bins):
            findings.append(Finding(
                type="misconfig", severity="high",
                title=f"Writable service binary (ExecStart): {path}",
                detail="named in a systemd ExecStart= — replacing it runs your code "
                       "as the service account.",
                source_module=self.name))
        return findings
