"""'.NET runtime plugin: web.config / appsettings.json connection strings
and credentials, ASP.NET machineKey (capability), and encrypted-section awareness.
Works on Windows (IIS) and .NET Core on Linux."""
from __future__ import annotations

import re
import shlex

from ...models import Credential, Finding
from ...patterns import mask, scan_line
from ..base import Module, register

_MACHINEKEY = re.compile(
    r'(?i)<machineKey[^>]*?validationKey\s*=\s*"(?P<vk>[^"]+)"[^>]*?'
    r'decryptionKey\s*=\s*"(?P<dk>[^"]+)"'
)
_FIND_LINUX = ("find /home /var/www /srv /opt /app -type f "
               r"\( -name web.config -o -name 'appsettings*.json' \) "
               "-not -path '*/node_modules/*' 2>/dev/null | head -n 40")
_FIND_WIN = (r'dir /b /s C:\inetpub\web.config C:\inetpub\appsettings.json '
             r'"C:\Program Files\*web.config" 2>nul')


@register
class DotnetPlugin(Module):
    name = "dotnet_plugin"

    def triggers(self, ctx) -> bool:
        return ctx.has_runtime("dotnet") or (ctx.os == "windows")

    def collect(self, session):
        findings: list[Finding] = []
        paths = session.exec(_FIND_LINUX, timeout=45).out.splitlines()
        if not any(p.strip() for p in paths):
            paths = session.exec(_FIND_WIN, timeout=45).out.splitlines()

        for path in paths:
            path = path.strip()
            if not path:
                continue
            content = self._read(session, path)
            if not content.strip():
                continue
            for f in scan_line(content, path):
                f.source_module = self.name
                findings.append(f)
            findings += self._machinekey_cap(content, path)
            if "configProtectionProvider" in content:
                findings.append(Finding(
                    type="info", title="Encrypted .NET config section", severity="medium",
                    detail=f"{path} has a protected section — decrypt on host with "
                           f"'aspnet_regiis -pdf'", source_module=self.name))
        return findings

    @staticmethod
    def _read(session, path: str) -> str:
        out = session.exec(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10).stdout
        if out.strip():
            return out
        return session.exec(f'type "{path}" 2>nul', timeout=10).stdout

    def _machinekey_cap(self, content: str, source: str) -> list[Finding]:
        out = []
        for m in _MACHINEKEY.finditer(content):
            cred = Credential(kind="capability", secret=m.group("vk"), source=source,
                              metadata={"capability": "aspnet_machinekey",
                                        "validationKey": m.group("vk"),
                                        "decryptionKey": m.group("dk"),
                                        "action": "Forge ASP.NET ViewState / auth tokens "
                                                  "with this machineKey."})
            out.append(Finding(type="capability", title="ASP.NET machineKey recovered",
                               severity="high",
                               detail=f"machineKey in {source}: vk={mask(m.group('vk'))}",
                               credential=cred, source_module=self.name))
        return out
