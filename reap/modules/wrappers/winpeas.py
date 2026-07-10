"""WinPEAS wrapper: upload, run, capture; parse for signals + secrets.
Heavy → REAP_HEAVY gated."""
from __future__ import annotations

from ...models import Finding
from ...patterns import scan_line
from ..base import Module, register
from ._util import heavy_enabled, resolve_tool, save_text, signals, skip

_CANDIDATES = [
    "/usr/share/peass/winpeas/winPEASx64.exe",
    "/usr/share/peass/winpeas/winPEASany.exe",
    "winPEASx64.exe",
]


@register
class WinpeasWrapper(Module):
    name = "winpeas"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows" and heavy_enabled()

    def collect(self, session):
        local = resolve_tool(_CANDIDATES, "REAP_WINPEAS")
        if not local:
            return skip("WinPEAS", "binary not found (set REAP_WINPEAS)", self.name)
        remote = r"C:\Windows\Temp\wp.exe"
        try:
            session.upload(local, remote)
        except Exception as exc:
            return skip("WinPEAS", f"upload failed: {exc}", self.name)
        out = session.exec(f'"{remote}" cmd quiet', timeout=420).stdout
        session.exec(f'del /f /q "{remote}"')
        path = save_text(session.host, "winpeas.txt", out)
        findings = [Finding(type="info", title="WinPEAS output captured", severity="low",
                            detail=str(path), source_module=self.name)]
        findings += signals(out, self.name)
        for f in scan_line(out, "winpeas output"):
            f.source_module = self.name
            findings.append(f)
        return findings
