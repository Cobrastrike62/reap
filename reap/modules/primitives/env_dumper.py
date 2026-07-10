"""Process-environment dumper: /proc/<pid>/environ for app processes.
Twelve-factor apps put secrets in env, so this often spills more than any file."""
from __future__ import annotations

from ...patterns import scan_line
from ..base import Module, register

_PROBE = (
    "for p in $(ps -eo pid=,comm= 2>/dev/null | "
    "grep -Ei 'node|python|java|php|ruby|dotnet|gunicorn|uwsgi|pm2|puma|rails' | "
    "awk '{print $1}'); do echo \"@@PID@@$p\"; "
    "tr '\\0' '\\n' < /proc/$p/environ 2>/dev/null; done"
)


@register
class ProcessEnvDumper(Module):
    name = "env_dumper"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def collect(self, session):
        findings = []
        pid = "?"
        for line in session.exec(_PROBE, timeout=45).stdout.splitlines():
            if line.startswith("@@PID@@"):
                pid = line[len("@@PID@@"):].strip()
                continue
            if "=" not in line:
                continue
            for f in scan_line(line, f"/proc/{pid}/environ"):
                f.severity = "high"  # env-resident secrets are high-value
                f.source_module = self.name
                findings.append(f)
        return findings
