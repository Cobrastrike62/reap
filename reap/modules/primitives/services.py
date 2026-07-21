"""Listening-services collector: turn local listeners into Service rows so the
correlation engine has DB/WinRM/SSH targets to test discovered creds against, and
so loopback-bound services get auto-forwarded.

Listeners come from :func:`reap.netinfo.probe_listeners`, which unions ss, netstat,
and ``/proc/net/*`` — so a service is found even on a box with no ``ss``/``netstat``
installed (previously reap saw nothing there and missed live ports entirely).

The app-level proto is inferred from the listening *process* first (so a DB on a
non-standard port is still recognized) and the port number second.
"""
from __future__ import annotations

from ...models import Finding, Service
from ...netinfo import probe_listeners
from ...patterns import proto_for_port
from ..base import Module, register

# Listening process name -> app proto (covers non-standard ports the port map misses).
_PROC_PROTO = {
    "sshd": "ssh", "mysqld": "mysql", "mariadbd": "mysql", "postgres": "postgres",
    "postmaster": "postgres", "mongod": "mongodb", "redis-server": "redis",
    "sqlservr": "mssql", "vsftpd": "ftp", "proftpd": "ftp", "pure-ftpd": "ftp",
    "smbd": "smb",
}


@register
class ListeningServices(Module):
    name = "listening_services"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        findings: list[Finding] = []
        for lis in probe_listeners(session):
            port, proc = lis["port"], lis["process"]
            app = _PROC_PROTO.get(proc or "") or proto_for_port(port)
            product = f"listener ({proc})" if proc else f"{lis['proto']} listener"
            detail = f"{lis['proto']} {lis['addr']}"
            if lis["kind"] != "any":
                detail += f" [{lis['kind']}]"
            svc = Service(proto=app, port=port, product=product, notes=lis["addr"])
            findings.append(Finding(
                type="info", title=f"Listening {app}/{port}", severity="low",
                detail=detail, service=svc, source_module=self.name))
        return findings
