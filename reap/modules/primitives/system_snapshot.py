"""System + network snapshot (linpeas 'system information' / 'network' views).

Almost entirely ``enumerate`` (screen-only situational awareness): kernel, distro,
uptime, logged-in and recent users, sudo version, PATH, interfaces, routes, active
connections, ARP neighbors, DNS and hosts. Neighbors/hosts that are worth
*correlating* are already persisted by ``pivot_targets`` and ``listening_services``;
this view is for the operator's eyes.

``collect`` persists exactly one thing: the kernel/distro string, as a low finding —
useful in the report and as the anchor for a kernel-exploit lookup.
"""
from __future__ import annotations

from ...models import EnumSection, Finding
from .._probe import sections
from ..base import Module, register

_SYS_PROBE = r"""
echo '@@KERNEL@@'; uname -a 2>/dev/null
echo '@@OSREL@@'; grep -E 'PRETTY_NAME|^VERSION=' /etc/os-release 2>/dev/null
echo '@@UPTIME@@'; uptime 2>/dev/null
echo '@@SUDO@@'; sudo --version 2>/dev/null | head -n 1
echo '@@WHO@@'; who 2>/dev/null
echo '@@LAST@@'; last -n 12 2>/dev/null | head -n 12
echo '@@PATH@@'; printf '%s\n' "$PATH"
echo '@@IFACES@@'; ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null
echo '@@ROUTES@@'; ip route 2>/dev/null || route -n 2>/dev/null
echo '@@CONNS@@'; { ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null; } | head -n 80
echo '@@ARP@@'; ip neigh 2>/dev/null || arp -a 2>/dev/null
echo '@@DNS@@'; grep -v '^#' /etc/resolv.conf 2>/dev/null
echo '@@HOSTS@@'; grep -vE '^#|^$' /etc/hosts 2>/dev/null
echo '@@END@@'
""".strip()


def _block(sec: dict, *names: str) -> list[str]:
    """Concatenate several probe blocks into one line list, labeling each."""
    lines: list[str] = []
    for name in names:
        body = sec.get(name, "").strip()
        if body:
            lines += body.splitlines()
    return lines


@register
class SystemSnapshot(Module):
    name = "system_snapshot"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def _survey(self, session):
        return sections(session.exec(_SYS_PROBE, timeout=35).stdout)

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        sec = self._survey(session)
        return [
            EnumSection(title="System",
                        lines=_block(sec, "KERNEL", "OSREL", "UPTIME", "SUDO"),
                        hint="check the kernel + sudo version against known "
                             "local-privesc CVEs"),
            EnumSection(title="Users (logged-in / recent)",
                        lines=_block(sec, "WHO", "LAST")),
            EnumSection(title="PATH", lines=_block(sec, "PATH")),
            EnumSection(title="Network — interfaces & routes",
                        lines=_block(sec, "IFACES", "ROUTES")),
            EnumSection(title="Network — connections",
                        lines=_block(sec, "CONNS")),
            EnumSection(title="Network — neighbors / DNS / hosts",
                        lines=_block(sec, "ARP", "DNS", "HOSTS")),
        ]

    # -- collect (persist the kernel anchor only) ------------------------------
    def collect(self, session):
        sec = self._survey(session)
        kernel = sec.get("KERNEL", "").strip()
        if not kernel:
            return []
        pretty = ""
        for ln in sec.get("OSREL", "").splitlines():
            if ln.startswith("PRETTY_NAME"):
                pretty = ln.split("=", 1)[1].strip().strip('"')
        return [Finding(
            type="info", severity="low",
            title=f"Kernel: {kernel.split()[2] if len(kernel.split()) > 2 else kernel}",
            detail=f"{kernel}" + (f"  |  {pretty}" if pretty else ""),
            source_module=self.name)]
