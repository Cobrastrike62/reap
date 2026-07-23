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

from ...models import EnumFlag, EnumSection, Finding
from ...netinfo import format_listeners, guess_service, probe_listeners
from .._probe import sections
from .._triage import sudo_vuln
from ..base import Module, register

# App-level protos worth calling out among listeners.
_INTERESTING_SVC = {"ssh", "mysql", "postgres", "mongodb", "mssql", "redis",
                    "http", "https", "winrm", "smb", "ftp"}

_SYS_PROBE = r"""
echo '@@KERNEL@@'; uname -a 2>/dev/null
echo '@@OSREL@@'; grep -E 'PRETTY_NAME|^VERSION=' /etc/os-release 2>/dev/null
echo '@@UPTIME@@'; uptime 2>/dev/null
echo '@@SUDO@@'; sudo --version 2>/dev/null | head -n 1
echo '@@PASSWD@@'; getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null
echo '@@WHO@@'; who 2>/dev/null
echo '@@LAST@@'; last -n 12 2>/dev/null | head -n 12
echo '@@PATH@@'; printf '%s\n' "$PATH"
echo '@@IFACES@@'; ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null
echo '@@ROUTES@@'; ip route 2>/dev/null || route -n 2>/dev/null
echo '@@ESTAB@@'; { ss -tunp state established 2>/dev/null || netstat -tunp 2>/dev/null; } | head -n 60
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
        listeners = probe_listeners(session)
        return [
            EnumSection(title="System",
                        lines=_block(sec, "KERNEL", "OSREL", "UPTIME", "SUDO"),
                        hint="kernel + sudo version vs known local-root CVEs",
                        flags=self._system_flags(sec)),
            EnumSection(title="Users & accounts",
                        lines=_block(sec, "WHO", "LAST"),
                        flags=self._user_flags(sec)),
            EnumSection(title="PATH", lines=_block(sec, "PATH")),
            EnumSection(title="Network — interfaces & routes",
                        lines=_block(sec, "IFACES", "ROUTES")),
            EnumSection(title="Network — listening sockets",
                        lines=format_listeners(listeners),
                        hint="unioned from ss + netstat + /proc/net (found even with "
                             "no ss/netstat); loopback-only ones are auto-forwarded by 'run'",
                        flags=self._listen_flags(listeners)),
            EnumSection(title="Network — established connections",
                        lines=_block(sec, "ESTAB")),
            EnumSection(title="Network — neighbors / DNS / hosts",
                        lines=_block(sec, "ARP", "DNS", "HOSTS")),
        ]

    def _system_flags(self, sec) -> list:
        flags = []
        note = sudo_vuln(sec.get("SUDO", ""))
        if note:
            label = (sec.get("SUDO", "").splitlines() or ["sudo"])[0]
            flags.append(EnumFlag(text=label, level="alert", reason=note))
        kern = sec.get("KERNEL", "").split()
        if len(kern) >= 3:
            ver = kern[2]
            mm = ".".join(ver.split(".")[:2])
            flags.append(EnumFlag(
                text=f"kernel {ver}", level="notice",
                reason=f"check 'searchsploit linux kernel {mm}' for a local-root exploit"))
        return flags

    def _user_flags(self, sec) -> list:
        flags = []
        for line in sec.get("PASSWD", "").splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                flags.append(EnumFlag(
                    text=line, level="alert",
                    reason=f"UID 0 account '{parts[0]}' other than root — "
                           "backdoor or dangerous misconfig"))
        return flags

    def _listen_flags(self, listeners) -> list:
        flags = []
        for lis in listeners:
            svc = guess_service(lis["port"])
            proc = f" {lis['process']}" if lis.get("process") else ""
            if lis["kind"] == "loopback" and svc in _INTERESTING_SVC:
                flags.append(EnumFlag(
                    text=f"{lis['proto']}/{lis['port']} {svc} (loopback){proc}",
                    level="notice",
                    reason=f"loopback-only {svc} — 'forward 127.0.0.1 {lis['port']}' "
                           "to reach it"))
            elif lis["kind"] == "any" and svc in {"mysql", "postgres", "mongodb",
                                                  "mssql", "redis", "http"}:
                flags.append(EnumFlag(
                    text=f"{lis['proto']}/{lis['port']} {svc}{proc}",
                    level="notice", reason=f"{svc} exposed on all interfaces"))
        return flags

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
