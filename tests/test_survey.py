from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import time

import pytest
from rich.console import Console

from reap.models import Context, Credential, EnumFlag, EnumSection, Finding
from reap.netinfo import ListenerList, _parse_proc, _parse_tool, probe_listeners
from reap.reporter import Reporter
from reap.store import LootStore
from reap.survey import SurveySession, snapshot_diff, snapshot_sections
from reap.transport.base import Result, Session


class LocalSession(Session):
    host = '127.0.0.1'
    session_id = 'local-fixture'

    def exec(self, command, timeout=30):
        start = time.monotonic()
        from reap.data.reap_agent import execute
        result = execute(command, timeout)
        return Result(**result)


class Canned(Session):
    host = 'fixture'
    session_id = 'fixture'

    def __init__(self, result):
        self.result = result
        self.calls = 0

    def exec(self, command, timeout=30):
        self.calls += 1
        return self.result


def test_distinct_binds_transport_family_and_process():
    output = ('@@SSTCP@@\nLISTEN 0 1 127.0.0.1:3000 0.0.0.0:* users:(("one",pid=41,fd=1))\n'
              'LISTEN 0 1 10.0.0.5:3000 0.0.0.0:* users:(("two",pid=42,fd=1))\n'
              '@@SSTCP6@@\nLISTEN 0 1 [::1]:3000 [::]:* users:(("six",pid=43,fd=1))\n'
              '@@SSUDP@@\nUNCONN 0 0 127.0.0.1:3000 0.0.0.0:*\n@@END@@')
    rows = probe_listeners(Canned(Result(output, '', 0, 0)))
    assert len(rows) == 4
    assert {(r['ip'], r['process'], r['pid']) for r in rows if r['proto'] == 'tcp'} == {
        ('127.0.0.1', 'one', '41'), ('10.0.0.5', 'two', '42'), ('::1', 'six', '43')}
    assert next(r for r in rows if r['ip'] == '::1')['addr'] == '[::1]:3000'


@pytest.mark.parametrize('encoded,expected', [
    ('00000000000000000000000001000000', '::1'),
    ('B80D0120000000000000000078563412', '2001:db8::1234:5678')])
def test_proc_ipv6_native_words(encoded, expected):
    rows = _parse_proc('#/proc/net/tcp6\n 0: %s:0BB8 0:0000 0A 0 0 0 0 0 1' % encoded)
    assert rows[0]['ip'] == expected
    assert rows[0]['family'] == 'ipv6'


def test_big_endian_proc():
    rows = _parse_proc('#/proc/net/tcp6\n 0: 00000000000000000000000000000001:0BB8 0:0000 0A 0 0', 'big')
    assert rows[0]['ip'] == '::1'


def test_empty_timeout_is_incomplete():
    rows = probe_listeners(Canned(Result('', 'timed out', 124, 25)))
    assert not rows and not rows.complete
    assert rows.checks[0]['status'] == 'timed out'


def test_coverage_requires_all_families_and_transports():
    rows = ListenerList(checks=[{'name': 'PROC_tcp', 'status': 'completed'}])
    assert not rows.complete
    rows.checks.extend({'name': 'PROC_' + name, 'status': 'completed'} for name in ('tcp6', 'udp', 'udp6'))
    assert rows.complete


def test_survey_diagnostics_caps_missing_markers_cache():
    session = Canned(Result('@@FILES@@\nfind: /root: Permission denied\n/opt/app\n/opt/app2\n@@END@@', '', 0, 1))
    survey = SurveySession(session)
    command = "echo '@@FILES@@'; find /root 2>/dev/null | head -n 2; echo '@@END@@'"
    result = survey.exec(command)
    survey.exec(command)
    assert session.calls == 1
    assert 'Permission denied' not in result.stdout
    assert survey.checks[0]['status'] != 'completed'
    assert 'Permission denied' in survey.checks[0]['detail']
    capped = SurveySession(Canned(Result('@@X@@\none\ntwo\n@@END@@', '', 0, 0)))
    capped.exec("echo '@@X@@'; ls | head -n 2; echo '@@END@@'")
    assert 'cap reached' in capped.checks[0]['detail']
    truncated = SurveySession(Canned(Result('@@X@@\npartial', '', 0, 0)))
    truncated.exec("echo '@@X@@'; ls; echo '@@END@@'")
    assert truncated.checks[0]['status'] == 'partial'


def test_survey_preserves_optional_adapter_methods():
    class Adapter(Canned):
        def upload(self, local, remote):
            return (local, remote)
        def open_forward(self, host, port, local=0):
            return (host, port, local)
        def is_alive(self):
            return True
    survey = SurveySession(Adapter(Result('', '', 0, 0)))
    assert survey.upload('one', 'two') == ('one', 'two')
    assert survey.open_forward('::1', 3000, 3001) == ('::1', 3000, 3001)
    assert survey.is_alive()


def test_diagnostic_detection_does_not_discard_evidence_text():
    data = 'PASSWORD=not found\n/opt/not found.log\n/etc/config:PASSWORD=Permission denied'
    survey = SurveySession(Canned(Result(data, '', 0, 0)))
    assert survey.exec('env').stdout == data
    assert survey.checks[0]['status'] == 'completed'


def test_snapshot_roundtrip_full_evidence_and_diff(tmp_path):
    store = LootStore(str(tmp_path / 'loot.db'))
    host = store.get_or_create_host('target')
    evidence = 'full evidence ' * 100
    previous = {'sections': snapshot_sections([EnumSection('Files', [evidence], flags=[EnumFlag('item', 'reason')])])}
    ident = store.save_snapshot(host, 'one', previous, 'files')
    store.close()
    store = LootStore(str(tmp_path / 'loot.db'))
    assert store.get_snapshot(ident)['payload'] == previous
    assert store.latest_snapshot(host, 'files')['id'] == ident
    assert store.latest_snapshot(host, 'processes') is None
    current = {'sections': snapshot_sections([EnumSection('Files', ['new'])])}
    changes = snapshot_diff(previous, current)
    assert changes['added'] == [('Files', 'line', 'new')]
    assert ('Files', 'line', evidence) in changes['removed']
    assert not snapshot_diff(previous, dict(previous, session='different'))['added']


def test_services_do_not_collapse_distinct_bind_or_transport(tmp_path):
    store = LootStore(str(tmp_path / 'loot.db'))
    host = store.get_or_create_host('target')
    for address, family, transport in [('::1', 'ipv6', 'tcp'), ('127.0.0.1', 'ipv4', 'tcp'), ('127.0.0.1', 'ipv4', 'udp')]:
        store.add_service(host, 'unknown', 3000, transport=transport, bind_address=address, address_family=family)
    assert len(store.get_services()) == 3


def test_console_save_diff_show_and_no_false_stock(tmp_path, monkeypatch):
    from reap.console import ReapConsole
    from reap.modules.base import Module
    import reap.console as module

    class Fixture(Module):
        name = 'fixture'
        def enumerate(self, session):
            session.exec("echo '@@FILES@@'; ls; echo '@@END@@'")
            return [EnumSection('Fixture', ['evidence ' * 200], flags=[EnumFlag('lead', 'inspect', evidence=['full ' * 200])])]

    monkeypatch.setattr(module, 'select', lambda ctx: [Fixture()])
    console = ReapConsole(str(tmp_path / 'loot.db'))
    output = io.StringIO()
    console.console = Console(file=output, width=160, color_system=None)
    console.sessions['fixture'] = Canned(Result('@@FILES@@\npartial', '', 0, 0))
    console.contexts['fixture'] = Context(os='linux')
    console.active = 'fixture'
    console.do_enum('--save --brief')
    console.do_enum('--diff --brief')
    console.do_show('E1')
    console.do_show('snapshot 1')
    text = output.getvalue()
    assert 'end marker missing' in text and 'Saved snapshot 1' in text
    assert '0 added, 0 removed' in text and 'full ' * 20 in text
    assert 'stock' not in text
    assert len(console.store.get_snapshots()) == 1


def test_credential_exports_separate_hashes_tokens_and_preserve_report(tmp_path):
    store = LootStore(str(tmp_path / 'loot.db'))
    host = store.get_or_create_host('target')
    for credential in [Credential('password', 'actual-password', 'bob'),
                       Credential('token', 'token-material', 'api'),
                       Credential('hash', '*' + 'A' * 40, 'mysql', metadata={'hash_type': 'mysql_native'}),
                       Credential('hash', 'md5' + 'b' * 32, 'postgres', metadata={'hash_type': 'postgres_md5'}),
                       Credential('hash', 'c' * 32, 'unknown', metadata={'hash_type': 'md5_or_ntlm'})]:
        store.add_credential(credential, host)
    detail = 'evidence with tail ' * 100
    store.ingest(Finding('info', 'Full evidence', detail=detail), host)
    reporter = Reporter(store)
    files = reporter.export_creds_txt(str(tmp_path / 'credentials'))
    assert (tmp_path / 'credentials-pass.txt').read_text() == 'actual-password\n'
    assert 'token-material' not in (tmp_path / 'credentials-userpass.txt').read_text()
    paths = reporter.export_hashes(str(tmp_path / 'hashes'))
    assert (tmp_path / 'hashes-m300.txt').read_text() == 'A' * 40 + '\n'
    assert (tmp_path / 'hashes-m12.txt').read_text() == 'b' * 32 + ':postgres\n'
    manifest = json.loads((tmp_path / 'hashes-manifest.json').read_text())
    assert len(manifest['records']) == 2 and len(manifest['skipped']) == 1
    assert detail in reporter.to_markdown()


@pytest.mark.skipif(os.name != 'posix', reason='Linux socket inventory')
def test_real_socket_discovery_without_tools():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]

        class ProcOnly(LocalSession):
            def exec(self, command, timeout=30):
                command = command.replace('ss -', 'missing_reap_ss -').replace('netstat -', 'missing_reap_netstat -')
                return super().exec(command, timeout)

        rows = probe_listeners(ProcOnly())
        assert any(row['ip'] == '127.0.0.1' and row['port'] == port for row in rows)
        assert rows.complete
        assert any(check['status'] == 'tool unavailable' for check in rows.checks)
