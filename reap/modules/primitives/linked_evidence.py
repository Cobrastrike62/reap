"""Join scheduled/service execution to permissions checked as the session user."""
from __future__ import annotations

import posixpath
import re
import shlex

from ...models import EnumFlag, EnumSection, Finding
from .._probe import sections
from ..base import Module, register
from .cron_jobs import _CRON_PROBE
from .init_services import _SVC_PROBE

_PATHS = re.compile(r"(?<![\w])(/[^\s;|&><\"']+)")


def execution_references(cron, service):
    refs = []
    for section in ('SYSTEM', 'CRON_D', 'SPOOL', 'USER'):
        source = '/etc/crontab' if section == 'SYSTEM' else section
        for line in cron.get(section, '').splitlines():
            if line.startswith('## '):
                source = line[3:].strip()
                continue
            text = line.strip()
            if not text or text.startswith('#') or re.match(r'^\w+=', text):
                continue
            parts = text.split(None, 6 if not text.startswith('@') else 2)
            # User crontabs don't contain a run-as field.
            user_cron = section in ('USER', 'SPOOL')
            cron_account = posixpath.basename(source) if section == 'SPOOL' else 'session user'
            if text.startswith('@'):
                minimum, account = (2, cron_account) if user_cron else (3, parts[1] if len(parts) > 1 else '?')
            else:
                minimum, account = (6, cron_account) if user_cron else (7, parts[5] if len(parts) > 5 else '?')
            if len(parts) < minimum:
                continue
            for path in _PATHS.findall(text):
                refs.append((path, source, account, text))
    units = {}
    for line in service.get('EXECSTART', '').splitlines():
        source, _, assignment = line.partition(':')
        if not source.endswith('.service') or '=' not in assignment:
            continue
        key, value = assignment.strip().split('=', 1)
        units.setdefault(source, {})[key] = value.strip()
    for source, unit in units.items():
        for path in _PATHS.findall(unit.get('ExecStart', '')):
            refs.append((path, source, unit.get('User') or 'root', unit.get('ExecStart', '')))
    return list(dict.fromkeys(refs))


def file_evidence(session, path):
    parent = posixpath.dirname(path) or '/'
    q, d = shlex.quote(path), shlex.quote(parent)
    command = (f'stat -Lc "%U|%G|%a|%F" -- {q} 2>/dev/null; '
               f'[ -w {q} ] && echo FILE_WRITABLE; '
               f'[ -w {d} ] && [ -x {d} ] && [ ! -k {d} ] && echo PARENT_REPLACEABLE; '
               f'lsattr -d {q} 2>/dev/null; true')
    result = session.exec(command, timeout=15)
    lines = result.stdout.splitlines()
    stat = next((line for line in lines if line.count('|') == 3), '')
    if not stat or result.exit_code == 124:
        return None
    owner, group, mode, kind = stat.split('|', 3)
    if kind not in ('regular file', 'regular empty file'):
        return None
    attrs = [line.split()[0] for line in lines if line.split() and re.match(r'^[a-zA-Z-]{8,}$', line.split()[0])]
    protected = any('i' in attr or 'a' in attr for attr in attrs)
    writable = 'FILE_WRITABLE' in lines and not protected
    replaceable = 'PARENT_REPLACEABLE' in lines and not protected
    return {'owner': owner, 'group': group, 'mode': mode, 'writable': writable,
            'replaceable': replaceable, 'parent': parent, 'protected': protected}


@register
class LinkedEvidence(Module):
    name = 'linked_evidence'

    def triggers(self, ctx):
        return ctx.os == 'linux'

    def enumerate(self, session):
        cron = sections(session.exec(_CRON_PROBE, timeout=35).stdout)
        services = sections(session.exec(_SVC_PROBE, timeout=45).stdout)
        flags, lines, checks = [], [], []
        facts, users = {}, {}
        references = execution_references(cron, services)
        if len(references) > 60:
            checks.append({'name': 'execution reference scope', 'status': 'partial',
                           'detail': 'First 60 of %s parsed references checked.' % len(references)})
        for path, source, account, command in references[:60]:
            if path.startswith(('/proc/', '/sys/', '/dev/', '/run/')):
                continue
            if path not in facts:
                facts[path] = file_evidence(session, path)
            fact = facts[path]
            if not fact or not (fact['writable'] or fact['replaceable']):
                continue
            confidence = 'observed'
            if source.endswith('.service'):
                unit = posixpath.basename(source)
                if unit not in users:
                    result = session.exec(f'systemctl show {shlex.quote(unit)} --property=User --value 2>/dev/null', timeout=10)
                    # A successful empty User property means the system manager's
                    # default root account. Diagnostic output is never an account.
                    output = result.stdout.strip()
                    users[unit] = (output or 'root') if result.ok and '\n' not in output and ':' not in output else None
                if users[unit] is not None:
                    account = users[unit]
                else:
                    confidence = 'inferred'
            influence = 'can modify the file' if fact['writable'] else 'can replace it through its writable, searchable, non-sticky parent'
            evidence = [f'Execution source: {source}', f'Run-as account: {account}',
                        f'Command: {command}', f"Ownership/mode: {fact['owner']}:{fact['group']} {fact['mode']}",
                        f'Session access check: {influence}']
            reason = f'{source} references this file as {account}; your session {influence}'
            # A reference in a cron file is observed configuration; activation is
            # deliberately left as a next check rather than claiming an exploit.
            flags.append(EnumFlag(path, reason, 'alert' if account == 'root' else 'notice',
                                  confidence, evidence,
                                  'Verify activation, mount options, ACLs and runtime use before concluding exploitability.'))
            lines.extend(evidence + [''])
        return [EnumSection('Connected execution and permission evidence', lines,
                            'Checks at most 60 parsed absolute-path references. Links describe configuration; verify activation and runtime use.', flags, checks)]

    def collect(self, session):
        return [Finding('misconfig', 'Writable execution dependency: ' + flag.text + ' (' + flag.evidence[0] + ')',
                        'high' if flag.level == 'alert' else 'medium',
                        '\n'.join(flag.evidence + [flag.reason, 'Confidence: ' + flag.confidence,
                                                  'Next check: ' + flag.next_check]), self.name)
                for section in self.enumerate(session) for flag in section.flags]
