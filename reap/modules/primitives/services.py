"""Listening-services collector: turn local listeners into Service rows so the
correlation engine has DB/WinRM/SSH targets to test discovered creds against.
(Fingerprint uses ports to detect runtimes; this persists them as services.)

Infers the proto from the listening *process* (ss -p) as well as the port, so a
DB on a non-standard port (e.g. MariaDB on 3307) is still recognized and
correlated instead of being filed as 'unknown'."""
from __future__ import annotations

import re

from ...models import Finding, Service
from ...patterns import proto_for_port
from ..base import Module, register

# Listening process name -> proto (covers non-standard ports the port map misses).
_PROC_PROTO = {
    "sshd": "ssh", "mysqld": "mysql", "mariadbd": "mysql", "postgres": "postgres",
    "postmaster": "postgres", "mongod": "mongodb", "redis-server": "redis",
    "sqlservr": "mssql", "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp",
    "smbd": "smb",
}
_PROC_RE = re.compile(r'\("([^"]+)"')  # ss users:(("mariadbd",pid=..,fd=..))


@register
class ListeningServices(Module):
    name = "listening_services"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        out = session.exec(
            "ss -tlnpH 2>/dev/null || ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null",
            timeout=20).stdout
        findings: list[Finding] = []
        seen: set[int] = set()
        for line in out.splitlines():
            addr = next(
                (t for t in line.split()
                 if ":" in t and t.rsplit(":", 1)[-1].isdigit()),
                None,
            )
            if not addr:
                continue
            port = int(addr.rsplit(":", 1)[-1])
            if port in seen:
                continue
            seen.add(port)
            pm = _PROC_RE.search(line)
            proc = pm.group(1) if pm else None
            proto = _PROC_PROTO.get(proc) or proto_for_port(port)
            product = f"listener ({proc})" if proc else "local listener"
            svc = Service(proto=proto, port=port, product=product, notes=addr)
            findings.append(Finding(type="info", title=f"Listening {proto}/{port}",
                                    severity="low", detail=addr, service=svc,
                                    source_module=self.name))
        return findings
