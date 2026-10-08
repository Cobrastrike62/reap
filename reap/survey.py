"""Survey coverage, run-local caching, and stable snapshot comparison."""
from __future__ import annotations

import re
import json
from dataclasses import asdict

from .modules._probe import sections
from .transport.base import Result, Session

_ERROR = re.compile(
    r'^(?:\S*/)?(?:sh|bash|dash|ash|zsh|find|ls|cat|stat|id|grep|ps|ss|netstat|'
    r'sudo|lsattr|systemctl|crontab|head|od|uname|env|service):.*(?:'
    r'not found|permission denied|operation not permitted|access is denied|'
    r'unknown (?:option|predicate)|unrecognized(?: option|:)|cannot (?:open|access)|'
    r'password is required|no such file or directory)'
    r'|^(?:failed to connect to bus|system has not been booted with systemd)', re.I)


class SurveySession(Session):
    """Expose failures that old probes redirected away. Cache only within this run."""
    def __init__(self, session, linux=True):
        self.session = session
        self.linux = linux
        self.cache = {}
        self.checks = []
        self.module = 'survey'

    def __getattr__(self, name):
        return getattr(self.session, name)

    def upload(self, local_path, remote_path):
        return self.session.upload(local_path, remote_path)

    def open_forward(self, remote_host, remote_port, local_port=0):
        return self.session.open_forward(remote_host, remote_port, local_port)

    def is_alive(self):
        return self.session.is_alive()

    def exec(self, cmd, timeout=30):
        key = (cmd, timeout)
        if key in self.cache:
            result = self.cache[key]
        else:
            diagnostic = cmd.replace('2>/dev/null', '2>&1') if self.linux else cmd
            try:
                result = self.session.exec(diagnostic, timeout=timeout)
            except Exception as exc:
                result = Result('', str(exc), 1, 0.0)
            self.cache[key] = result
        blocks = sections(result.stdout)
        wanted = list(dict.fromkeys(re.findall(r"echo\s+['\"]?@@([A-Z_0-9]+)@@", cmd)))
        chunks = re.split(r"echo\s+['\"]?@@([A-Z_0-9]+)@@['\"]?", cmd)
        source = dict(zip(chunks[1::2], chunks[2::2]))
        if not wanted:
            blocks = {'command': result.stdout}
            wanted = ['command']
        for name in wanted:
            if name in ('END', 'CHECKS'):
                continue
            body = blocks.get(name, '')
            errors = [line for line in body.splitlines() if _ERROR.search(line)]
            status, detail = 'completed', ''
            if result.exit_code == 124:
                status, detail = 'timed out', result.stderr
            elif name not in blocks:
                status, detail = 'partial', 'section missing from response'
            elif errors or result.stderr:
                detail = '\n'.join(errors) or result.stderr
                status = 'tool unavailable' if 'not found' in detail.lower() else 'permission denied / partial'
            elif wanted != ['command'] and '@@END@@' not in result.stdout:
                status, detail = 'partial', 'probe end marker missing'
            elif wanted == ['command'] and result.exit_code not in (0,):
                # A negative test means no match; a collector command failure is different.
                if not (cmd.lstrip().startswith(('[', 'test '))):
                    status, detail = 'partial', 'exit %s' % result.exit_code
            caps = [int(n) for n in re.findall(r'head\s+-n\s+(\d+)', source.get(name, cmd))]
            if caps:
                detail = (detail + '; ' if detail else '') + 'bounded probe; configured caps: ' + ', '.join(map(str, caps))
                lines = [line for line in body.splitlines() if line.strip() and not _ERROR.search(line)]
                if len(lines) in caps and status == 'completed':
                    status = 'partial'
                    detail += '; result cap reached'
            self.checks.append({'module': self.module, 'name': name, 'status': status,
                                'detail': detail, 'rows': len(body.splitlines()),
                                'duration': result.duration})
        # Keep diagnostics in coverage, rather than feeding them to legacy parsers
        # as if they were discovered filenames, processes or accounts.
        cleaned = '\n'.join(line for line in result.stdout.splitlines() if not _ERROR.search(line))
        return Result(cleaned, result.stderr, result.exit_code, result.duration)


def snapshot_sections(sections_):
    return [asdict(section) for section in sections_]


def snapshot_diff(previous, current):
    """Compare section facts and flags without treating timestamps as changes."""
    def facts(snapshot):
        out = set()
        for section in snapshot.get('sections', []):
            title = section['title']
            out.update((title, 'line', line) for line in section.get('lines', []))
            out.update((title, 'flag', json.dumps(flag, sort_keys=True, ensure_ascii=False))
                       for flag in section.get('flags', []))
        out.update(('Coverage', 'check', json.dumps({k: check.get(k, '') for k in ('module', 'name', 'status', 'detail')}, sort_keys=True))
                   for check in snapshot.get('checks', []))
        return out
    old, new = facts(previous), facts(current)
    return {'added': sorted(new - old), 'removed': sorted(old - new)}
