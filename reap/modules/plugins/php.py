"""PHP runtime plugin: the missing peer to node/python/dotnet.

Laravel APP_KEY and Symfony APP_SECRET are emitted as capabilities (a key that
forges/decrypts signed cookies), not just generic tokens — a Laravel app's .env
commonly leaks exactly this. Plus generic .env/config secrets.
"""
from __future__ import annotations

import re
import shlex

from ...models import Credential, Finding
from ...patterns import looks_placeholder, mask, scan_line
from ..base import Module, register

_APP_KEY = re.compile(r"(?im)^\s*APP_KEY\s*=\s*(?P<val>(?:base64:)?[A-Za-z0-9+/=]{20,})")
_APP_SECRET = re.compile(r"(?im)\bAPP_SECRET\s*[:=]\s*[\"']?(?P<val>[^\s\"',]{12,})")
_APP_FILES = (".env", ".env.local", ".env.dist", "config/app.php",
              "config/services.yaml", ".env.example")


@register
class PhpPlugin(Module):
    name = "php_plugin"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown") and ctx.has_runtime("php")

    def collect(self, session):
        findings: list[Finding] = []
        roots = session.exec(
            r"find /home /var/www /srv /opt /app \( -name composer.json -o -name artisan \) "
            "-not -path '*/vendor/*' 2>/dev/null | head -n 20", timeout=45).out
        dirs = sorted({p.rsplit("/", 1)[0] for p in roots.splitlines() if p.strip()})[:10]
        for d in dirs:
            for rel in _APP_FILES:
                path = f"{d}/{rel}"
                content = session.exec(f"cat {shlex.quote(path)} 2>/dev/null",
                                       timeout=10).stdout
                if not content.strip():
                    continue
                for f in scan_line(content, path):
                    f.source_module = self.name
                    findings.append(f)
                findings += self._caps(content, path)
        return findings

    def _caps(self, content, source):
        out = []
        for m in _APP_KEY.finditer(content):
            val = m.group("val")
            if looks_placeholder(val):
                continue
            out.append(Finding(
                type="capability", severity="high", title="Laravel APP_KEY",
                detail=f"APP_KEY in {source}: {mask(val)} → forge/decrypt cookies",
                source_module=self.name,
                credential=Credential(
                    kind="capability", secret=val, source=source,
                    metadata={"capability": "laravel_appkey",
                              "action": "Forge/decrypt Laravel signed & encrypted "
                                        "cookies (laravel-crypto-killer); with a gadget "
                                        "chain this can reach RCE."})))
        for m in _APP_SECRET.finditer(content):
            val = m.group("val")
            if looks_placeholder(val):
                continue
            out.append(Finding(
                type="capability", severity="high", title="Symfony APP_SECRET",
                detail=f"APP_SECRET in {source}: {mask(val)}", source_module=self.name,
                credential=Credential(
                    kind="capability", secret=val, source=source,
                    metadata={"capability": "symfony_appsecret",
                              "action": "Forge Symfony CSRF / remember-me / signed URIs."})))
        return out
