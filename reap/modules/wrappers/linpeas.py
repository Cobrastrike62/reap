"""LinPEAS wrapper: upload, run, capture; parse output into findings and
re-scan it for secrets. Does not reimplement LinPEAS. Heavy → REAP_HEAVY gated."""
from __future__ import annotations

from ...models import Finding
from ...patterns import scan_line
from ..base import Module, register
from ._util import heavy_enabled, resolve_tool, save_text, signals, skip

_CANDIDATES = [
    "/usr/share/peass/linpeas/linpeas.sh",
    "/usr/share/peass/linPEAS/linpeas.sh",
    "/opt/linpeas.sh",
    "linpeas.sh",
]


@register
class LinpeasWrapper(Module):
    name = "linpeas"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux" and heavy_enabled()

    def collect(self, session):
        local = resolve_tool(_CANDIDATES, "REAP_LINPEAS")
        if not local:
            return skip("LinPEAS", "binary not found (set REAP_LINPEAS or install peass)", self.name)
        remote = "/tmp/.lp.sh"
        try:
            session.upload(local, remote)
        except Exception as exc:
            return skip("LinPEAS", f"upload failed: {exc}", self.name)
        out = session.exec(f"sh {remote} -q 2>/dev/null", timeout=420).stdout
        session.exec(f"rm -f {remote}")
        path = save_text(session.host, "linpeas.txt", out)
        findings = [Finding(type="info", title="LinPEAS output captured", severity="low",
                            detail=str(path), source_module=self.name)]
        findings += signals(out, self.name)
        for f in scan_line(out, "linpeas output"):
            f.source_module = self.name
            findings.append(f)
        return findings
