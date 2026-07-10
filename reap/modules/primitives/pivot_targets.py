"""Pivot-target discovery: turn a box's knowledge of its neighbors into Service
rows so correlation can test recovered creds against the NEXT host — where the
framework's cross-hop value lives. listening_services only ever records local
ports; this adds remote targets from ~/.ssh/config, known_hosts, /etc/hosts, arp.
"""
from __future__ import annotations

import shlex

from ...models import Finding, Service
from ..base import Module, register


def _homes(session) -> list[str]:
    out = session.exec("getent passwd 2>/dev/null || cat /etc/passwd", timeout=20).stdout
    homes = {"/root"}
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 6 and parts[5].startswith(("/home/", "/root")):
            homes.add(parts[5].rstrip("/"))
    return sorted(homes)


@register
class PivotTargets(Module):
    name = "pivot_targets"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        findings = []
        seen: set[str] = set()
        for home in _homes(session):
            findings += self._ssh_config(session, home, seen)
            findings += self._known_hosts(session, home, seen)
        findings += self._neighbors(session)
        return findings

    def _emit(self, host, note, seen):
        if not host or host in ("*",) or host in seen:
            return []
        seen.add(host)
        return [Finding(type="info", severity="low",
                        title=f"SSH pivot target: {host}", detail=note,
                        service=Service(proto="ssh", port=22, host=host,
                                        product="pivot target"),
                        source_module=self.name)]

    def _ssh_config(self, session, home, seen):
        out = []
        content = session.exec(f"cat {shlex.quote(home)}/.ssh/config 2>/dev/null",
                               timeout=10).stdout
        host = user = ident = None

        def flush():
            nonlocal host, user, ident
            if host:
                note = f"from {home}/.ssh/config"
                if user:
                    note += f" as {user}"
                if ident:
                    note += f" (key {ident})"
                out.extend(self._emit(host, note, seen))
            host = user = ident = None

        for line in content.splitlines():
            s = line.strip()
            low = s.lower()
            if low.startswith("host "):
                flush()
                host = s.split(None, 1)[1].strip()
            elif low.startswith("hostname "):
                host = s.split(None, 1)[1].strip()
            elif low.startswith("user "):
                user = s.split(None, 1)[1].strip()
            elif low.startswith("identityfile "):
                ident = s.split(None, 1)[1].strip()
        flush()
        return out

    def _known_hosts(self, session, home, seen):
        out = []
        content = session.exec(f"cat {shlex.quote(home)}/.ssh/known_hosts 2>/dev/null",
                               timeout=10).stdout
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("|1|") or s.startswith("#"):  # skip hashed/comments
                continue
            h = s.split()[0].split(",")[0]
            if h.startswith("["):                # [host]:port form
                h = h[1:].split("]")[0]
            out += self._emit(h, f"from {home}/.ssh/known_hosts", seen)
        return out

    def _neighbors(self, session):
        out = []
        arp = session.exec("ip neigh show 2>/dev/null || arp -an 2>/dev/null",
                           timeout=15).stdout
        if arp.strip():
            out.append(Finding(type="info", severity="low",
                               title="Neighbor cache (arp / ip neigh)",
                               detail=arp.strip()[:400], source_module=self.name))
        hosts = session.exec("grep -vE '^#|^$' /etc/hosts 2>/dev/null | head -n 40",
                            timeout=10).stdout
        if hosts.strip():
            out.append(Finding(type="info", severity="low", title="/etc/hosts entries",
                               detail=hosts.strip()[:400], source_module=self.name))
        return out
