"""Python runtime plugin: Django/Flask SECRET_KEY (emitted as a capability —
it forges signed cookies), plus .py config modules and DB settings."""
from __future__ import annotations

import re

from ...models import Credential, Finding
from ...patterns import looks_placeholder, mask, scan_line
from ..base import Module, register

_GREP_LINE = re.compile(r"^(.*?):(\d+):(.*)$")
_SECRET_KEY = re.compile(r"(?i)\bSECRET_KEY\b\s*[:=]\s*[\"']?(?P<val>[^\s\"',]{6,256})")
_CAP_HINT = {
    "django_secret": "Forge Django session cookies / signed values with this SECRET_KEY.",
    "flask_secret": "Forge/resign Flask session cookies (e.g. flask-unsign) with this key.",
}


@register
class PythonPlugin(Module):
    name = "python_plugin"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown") and ctx.has_runtime("python")

    def collect(self, session):
        findings: list[Finding] = []
        cmd = ("grep -rEniI --include='*.py' --exclude-dir=node_modules "
               "--exclude-dir=site-packages --exclude-dir=__pycache__ "
               "-e 'SECRET_KEY|SQLALCHEMY_DATABASE_URI|SECURITY_PASSWORD_SALT' "
               "/home /var/www /srv /opt /app 2>/dev/null | head -n 80")
        for line in session.exec(cmd, timeout=60).stdout.splitlines():
            m = _GREP_LINE.match(line)
            if not m:
                continue
            source = f"{m.group(1)}:{m.group(2)}"
            content = m.group(3)
            for f in scan_line(content, source):
                f.source_module = self.name
                findings.append(f)
            findings += self._secret_key_cap(content, source)
        return findings

    def _secret_key_cap(self, content: str, source: str) -> list[Finding]:
        out = []
        for m in _SECRET_KEY.finditer(content):
            val = m.group("val")
            if looks_placeholder(val):
                continue
            low = source.lower()
            framework = "django_secret" if ("django" in low or "settings" in low) else "flask_secret"
            cred = Credential(kind="capability", secret=val, source=source,
                              metadata={"capability": framework, "action": _CAP_HINT[framework]})
            out.append(Finding(type="capability", title=f"{framework} recovered",
                               severity="high",
                               detail=f"SECRET_KEY in {source}: {mask(val)}",
                               credential=cred, source_module=self.name))
        return out
