"""Secret-pattern scanner — build step 4, the first full round-trip.

Walks app/config dirs with a single broad grep (shared via _scan_cache so the
tree is traversed once across scanners), classifies each candidate line locally
via patterns.scan_line (so connection strings become both a credential and a
service), then pulls any private-key files whole.
"""
from __future__ import annotations

import shlex

from ...models import Credential, Finding
from ...patterns import DEFAULT_DIRS, scan_line
from ..base import Module, register
from ._scan_cache import grep_pass


@register
class SecretPatternScanner(Module):
    name = "secret_scanner"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown")

    def collect(self, session):
        findings: list[Finding] = []
        for path, lineno, content in grep_pass(session, DEFAULT_DIRS):
            findings.extend(scan_line(content, f"{path}:{lineno}"))
        findings.extend(self._private_keys(session))
        for f in findings:
            f.source_module = self.name
        return findings

    def _private_keys(self, session) -> list[Finding]:
        out: list[Finding] = []
        cmd = (
            "grep -rlE 'BEGIN [A-Z ]*PRIVATE KEY' --exclude-dir=node_modules "
            "/home /root /etc /opt /var/www /srv 2>/dev/null | head -n 25"
        )
        for path in session.exec(cmd, timeout=60).stdout.splitlines():
            path = path.strip()
            if not path:
                continue
            key = session.exec(f"cat {shlex.quote(path)} 2>/dev/null", timeout=20).stdout
            if "PRIVATE KEY" not in key:
                continue
            cred = Credential(kind="ssh_key", secret=key, source=path, metadata={"path": path})
            out.append(Finding(type="credential", title=f"Private key at {path}",
                               severity="high", detail="SSH/PEM private key recovered",
                               credential=cred))
        return out
