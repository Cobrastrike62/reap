"""Node runtime plugin — the JWT-capability showcase.

Beyond what the generic scanner catches, this knows Node's hiding spots: .env,
PM2 ecosystem.config.js, node-config JSON, and JWT signing secrets in source. It
emits the JWT secret as a CAPABILITY (a key that mints an admin token), not just
a string — so the engine surfaces 'forge an admin token', not 'try to log in'.
"""
from __future__ import annotations

import re
import shlex

from ...models import Credential, Finding
from ...patterns import looks_placeholder, mask, scan_line
from ..base import Module, register

_GREP_LINE = re.compile(r"^(.*?):(\d+):(.*)$")
_JWT_ASSIGN = re.compile(
    r"(?i)\b(?:jwt[_\-]?secret|jwtsecret|access[_\-]?token[_\-]?secret|"
    r"refresh[_\-]?token[_\-]?secret|token[_\-]?secret|secret[_\-]?or[_\-]?key)\b"
    r"\s*[:=]\s*[\"']?(?P<val>[^\s\"',}]{6,256})"
)
_APP_FILES = (".env", "ecosystem.config.js", "config/default.json",
              "config/production.json", "config/local.json")


@register
class NodePlugin(Module):
    name = "node_plugin"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown") and ctx.has_runtime("node")

    def collect(self, session):
        findings: list[Finding] = []
        roots = session.exec(
            "find /home /var/www /srv /opt /app -name package.json "
            "-not -path '*/node_modules/*' 2>/dev/null | head -n 20", timeout=45).out
        dirs = sorted({p.rsplit("/", 1)[0] for p in roots.splitlines() if p.strip()})[:10]

        for d in dirs:
            for rel in _APP_FILES:
                path = f"{d}/{rel}"
                content = session.exec(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10).stdout
                if not content.strip():
                    continue
                for f in scan_line(content, path):
                    f.source_module = self.name
                    findings.append(f)
                findings += self._jwt_caps(content, path)

        findings += self._jwt_from_source(session, dirs)
        return findings

    def _jwt_caps(self, content: str, source: str) -> list[Finding]:
        out = []
        for m in _JWT_ASSIGN.finditer(content):
            secret = m.group("val")
            if looks_placeholder(secret):
                continue
            cred = Credential(kind="capability", secret=secret, source=source,
                              metadata={"capability": "jwt_sign", "alg": "HS256",
                                        "action": "Forge an admin JWT signed with this "
                                                  "secret (HS256)."})
            out.append(Finding(type="capability", title="JWT signing secret",
                               severity="high",
                               detail=f"jwt secret in {source}: {mask(secret)} → forge admin token",
                               credential=cred, source_module=self.name))
        return out

    def _jwt_from_source(self, session, dirs: list[str]) -> list[Finding]:
        if not dirs:
            return []
        quoted = " ".join(shlex.quote(d) for d in dirs)
        cmd = ("grep -rEniI --include='*.js' --include='*.ts' --include='*.json' "
               "--exclude-dir=node_modules "
               "-e 'jwt[_-]?secret|secretOrKey|access[_-]?token[_-]?secret' "
               f"{quoted} 2>/dev/null | head -n 60")
        out = []
        for line in session.exec(cmd, timeout=60).stdout.splitlines():
            m = _GREP_LINE.match(line)
            if m:
                out += self._jwt_caps(m.group(3), f"{m.group(1)}:{m.group(2)}")
        return out
