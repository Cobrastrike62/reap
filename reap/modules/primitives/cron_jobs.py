"""Cron / scheduled-job inventory (linpeas cron view).

``enumerate`` dumps every cron source we can read — system crontab, ``/etc/cron.d``,
the periodic run-parts dirs, the calling user's crontab, the spool, and systemd
timers. ``collect`` persists the two actionable classes:

* a command line referencing a path the current user can **write** — if that job
  runs as root, editing the target is direct privesc;
* a secret embedded in a cron command line.

Complements ``sudo_privesc``, which flags writable cron *files* (the ``cron.d``
drop-ins themselves); this flags writable *targets referenced by* the jobs.
"""
from __future__ import annotations

import re

from ...models import EnumFlag, EnumSection, Finding
from ...patterns import scan_line
from .._probe import sections, writable_targets
from .._triage import interesting_path
from ..base import Module, register

_CRON_PROBE = r"""
echo '@@SYSTEM@@'; cat /etc/crontab 2>/dev/null
echo '@@CRON_D@@'; for f in /etc/cron.d/*; do [ -f "$f" ] && echo "## $f" && cat "$f" 2>/dev/null; done
echo '@@PERIODIC@@'; for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do echo "## $d"; ls -la "$d" 2>/dev/null; done
echo '@@USER@@'; crontab -l 2>/dev/null
echo '@@SPOOL@@'; for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && echo "## $f" && cat "$f" 2>/dev/null; done
echo '@@TIMERS@@'; systemctl list-timers --all --no-pager 2>/dev/null | head -n 40
echo '@@END@@'
""".strip()

# Absolute paths referenced in a cron line — the candidate writable targets.
_ABS_PATH = re.compile(r"(?<![\w=])(/[^\s;|&><\"']+)")
# Sections whose bodies are actual crontab lines (not directory listings/timers).
_JOB_SECTIONS = ("SYSTEM", "CRON_D", "USER", "SPOOL")


@register
class CronJobs(Module):
    name = "cron_jobs"

    def triggers(self, ctx) -> bool:
        return ctx.os == "linux"

    def _survey(self, session):
        return sections(session.exec(_CRON_PROBE, timeout=35).stdout)

    @staticmethod
    def _job_lines(sec: dict) -> list[str]:
        lines = []
        for name in _JOB_SECTIONS:
            for ln in sec.get(name, "").splitlines():
                s = ln.strip()
                if not s or s.startswith("#") or "=" == s[:1]:
                    continue
                if s.startswith("##"):          # our "## <file>" separators
                    continue
                if re.match(r"^[A-Z_]+=", s):   # crontab env assignment
                    continue
                lines.append(s)
        return lines

    # -- enumerate (screen) ----------------------------------------------------
    def enumerate(self, session):
        sec = self._survey(session)
        flags = self._flags(sec)
        out = []
        if flags:
            out.append(EnumSection(
                title="Cron jobs — worth a look", flags=flags,
                hint="jobs invoking scripts outside the base system (and secrets on "
                     "the line); writable targets are captured by 'run'"))
        for name, title in (
            ("SYSTEM", "System crontab (/etc/crontab)"),
            ("CRON_D", "/etc/cron.d"),
            ("PERIODIC", "Periodic dirs (hourly/daily/weekly/monthly)"),
            ("USER", "User crontab (crontab -l)"),
            ("SPOOL", "Cron spool"),
            ("TIMERS", "systemd timers"),
        ):
            body = sec.get(name, "")
            out.append(EnumSection(title=title,
                                   lines=body.splitlines() if body else []))
        return out

    def _flags(self, sec) -> list:
        flags = []
        for line in self._job_lines(sec):
            if any(f.credential for f in scan_line(line, "cron")):
                flags.append(EnumFlag(text=line[:140], level="alert",
                                      reason="secret in cron entry"))
                continue
            path = interesting_path(line)
            if path:
                root = re.search(r"\broot\b", line) is not None
                flags.append(EnumFlag(
                    text=line[:140], level="alert" if root else "notice",
                    reason=f"cron runs {path}" + (" as root" if root else "")
                           + " (outside base system)"))
            if len(flags) >= 30:
                break
        return flags

    # -- collect (persist actionable subset) -----------------------------------
    def collect(self, session):
        sec = self._survey(session)
        job_lines = self._job_lines(sec)
        findings: list[Finding] = []

        candidates: list[str] = []
        for line in job_lines:
            for f in scan_line(line, "cron job"):
                f.source_module = self.name
                if f.severity == "low":
                    f.severity = "medium"
                findings.append(f)
            candidates += _ABS_PATH.findall(line)

        for path in writable_targets(session, candidates):
            findings.append(Finding(
                type="misconfig", severity="high",
                title=f"Writable cron target: {path}",
                detail="referenced by a scheduled job; if the job runs as root, "
                       "editing this file is direct privesc.",
                source_module=self.name))
        return findings
