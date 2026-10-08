from __future__ import annotations

import os

import pytest

from reap.modules._triage import critical_file
from reap.modules.primitives.linked_evidence import LinkedEvidence, execution_references, file_evidence
from reap.transport.base import Result
from tests.test_survey import LocalSession


def test_execution_references_account_and_source():
    cron = {'CRON_D': '## /etc/cron.d/backup\n* * * * * root /opt/backup.sh\n',
            'USER': '@hourly /opt/user.sh', 'SPOOL': '## /var/spool/cron/crontabs/alice\n* * * * * /opt/alice.sh'}
    service = {'EXECSTART': '/etc/systemd/system/app.service:User=deploy\n/etc/systemd/system/app.service:ExecStart=/opt/app/start'}
    refs = execution_references(cron, service)
    assert ('/opt/backup.sh', '/etc/cron.d/backup', 'root', '* * * * * root /opt/backup.sh') in refs
    assert any(path == '/opt/user.sh' and account == 'session user' for path, _, account, _ in refs)
    assert any(path == '/opt/app/start' and account == 'deploy' for path, _, account, _ in refs)
    assert any(path == '/opt/alice.sh' and account == 'alice' for path, _, account, _ in refs)
    assert critical_file('/opt/app/passwd') is None


@pytest.mark.skipif(os.name != 'posix', reason='POSIX effective permissions')
def test_effective_permissions_and_sticky_parent(tmp_path):
    script = tmp_path / 'script.sh'
    script.write_text('echo lab')
    fact = file_evidence(LocalSession(), str(script))
    assert fact['owner'] and fact['group'] and fact['mode']
    assert fact['writable'] and fact['replaceable']
    tmp_path.chmod(0o1777)
    assert not file_evidence(LocalSession(), str(script))['replaceable']
    tmp_path.chmod(0o700)


def test_connected_lead_includes_permission_and_execution_evidence():
    class Fixture:
        def exec(self, command, timeout=30):
            if '@@SYSTEM@@' in command:
                return Result('@@SYSTEM@@\n* * * * * root /opt/backup.sh\n@@END@@', '', 0, 0)
            if '@@RUNNING@@' in command:
                return Result('@@END@@', '', 0, 0)
            return Result('root|developers|660|regular file\nFILE_WRITABLE', '', 0, 0)
    flag = LinkedEvidence().enumerate(Fixture())[0].flags[0]
    assert flag.level == 'alert' and flag.confidence == 'observed'
    assert any('root:developers 660' in item for item in flag.evidence)
    assert any('/etc/crontab' in item for item in flag.evidence)
    assert flag.next_check
