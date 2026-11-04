from __future__ import annotations

import copy

import pytest

from reap.netinfo import _endpoint
from reap.probe import probe_endpoints
from reap.serviceinfo import identify_services
from reap.survey import SurveySession
from reap.transport import agent
from reap.transport.base import NotSupported, Result, Session


ENDPOINT = {'proto': 'tcp', 'ip': '127.0.0.1', 'port': 3000, 'addr': '127.0.0.1:3000'}
ROW = dict(ENDPOINT, status='completed', protocol='http', http_status='HTTP/1.0 200 OK', title='Native lab')


class Channel:
    def __init__(self):
        self.closed = False
        self.sent = []
        self.reply = dict(id=1, op='probe_result', rows=[copy.deepcopy(ROW)], duration=0.01)

    def getsockname(self):
        return ('127.0.0.1', 7443)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


@pytest.fixture
def make_session(tmp_path, monkeypatch):
    (tmp_path / 'token.txt').write_text('a' * 64)
    (tmp_path / 'fingerprint.txt').write_text('b' * 64)
    channel = Channel()
    monkeypatch.setattr(agent, 'pinned_client', lambda *args: channel)
    monkeypatch.setattr(agent, 'send', lambda channel, message: channel.sent.append(message))
    monkeypatch.setattr(agent, 'receive', lambda channel: channel.reply)

    def make(capabilities=('probe_tcp_v1',), platform='Linux'):
        hello = {'version': 1, 'op': 'ready', 'platform': platform}
        if capabilities is not None:
            hello['capabilities'] = list(capabilities)
        monkeypatch.setattr(agent, 'authenticate_client', lambda *args: hello)
        return agent.AgentSession(bundle=tmp_path), channel
    return make


def test_native_probe_negotiated_and_survey_delegates_without_exec(make_session):
    session, channel = make_session()
    section = identify_services(SurveySession(session), [_endpoint('tcp', '127.0.0.1', 3000)])
    assert 'Native lab' in section.lines[0]
    assert section.checks[0]['status'] == 'completed'
    assert channel.sent == [dict(id=1, op='probe_tcp', endpoints=[ENDPOINT])]
    assert channel.timeout == 65
    assert not channel.closed


@pytest.mark.parametrize('capabilities,platform', [(None, 'Linux'), ([], 'Linux'), (['probe_tcp_v1'], 'Windows')])
def test_older_agent_and_windows_never_receive_unsupported_probe(make_session, capabilities, platform):
    session, channel = make_session(capabilities, platform)
    with pytest.raises(NotSupported):
        session.probe_tcp([ENDPOINT])
    assert channel.sent == [] and not channel.closed


@pytest.mark.parametrize('changes', [
    {'ip': 'service.example'}, {'port': True}, {'port': 3.0}, {'port': 0}, {'port': 65536},
    {'proto': 'udp'}, {'family': 'ipv6'}, {'addr': '127.0.0.1:9999'}, {'ip': '::1%bad!'}])
def test_invalid_request_stays_local(make_session, changes):
    session, channel = make_session()
    with pytest.raises(ValueError):
        session.probe_tcp([dict(ENDPOINT, **changes)])
    assert channel.sent == [] and not channel.closed


def test_probe_hard_limit_and_wildcard_family():
    with pytest.raises(ValueError, match='24'):
        probe_endpoints([ENDPOINT] * 25)
    assert probe_endpoints([_endpoint('tcp', '*', 3000, family='ipv6')]) == [
        {'proto': 'tcp', 'ip': '::', 'port': 3000, 'addr': '[::]:3000'}]
    assert probe_endpoints([_endpoint('tcp', 'fe80::1%eth0', 3000)])[0]['ip'] == 'fe80::1%eth0'


@pytest.mark.parametrize('response', [
    {'rows': []}, {'id': True}, {'op': 'pong'}, {'duration': True}, {'duration': -1}, {'duration': float('nan')},
    {'rows': [dict(ROW, port=True)]}, {'rows': [dict(ROW, status='absent')]},
    {'rows': [dict(ROW, title=42)]}, {'rows': [dict(ROW, title='x' * 513)]},
    {'rows': [dict(ROW, read_partial='yes')]},
    {'rows': [dict(ROW, title='\ud800')]},
    {'rows': [dict(ROW, http_status='not HTTP')]},
    {'rows': [dict(ROW, protocol='https')]},
    {'rows': [dict(ROW, protocol='banner', banner='')]},
    {'rows': [dict(ROW, tls={'version': 'TLS1.3', 'identity_verified': True, 'certificate_sha256': 'a' * 64})]}])
def test_malformed_native_response_closes_channel_without_python_retry(make_session, response):
    session, channel = make_session()
    channel.reply.update(response)
    section = identify_services(SurveySession(session), [ENDPOINT])
    assert not section.lines
    assert section.checks[0]['status'] == 'partial'
    assert 'native probe failed' in section.checks[0]['detail']
    assert len(channel.sent) == 1 and channel.sent[0]['op'] == 'probe_tcp'
    assert channel.closed and session._closed


def test_valid_tls_observation_and_partial_coverage(make_session):
    session, channel = make_session()
    channel.reply['rows'] = [dict(ROW, protocol='https', read_partial=True,
        tls={'version': 'TLS1.3', 'identity_verified': False, 'certificate_sha256': 'a' * 64})]
    section = identify_services(session, [ENDPOINT])
    assert '"identity_verified": false' in section.lines[0]
    assert section.checks[0]['status'] == 'partial'


def test_native_default_and_hard_cap_preserve_discovered_scope():
    class Native(Session):
        def probe_tcp(self, endpoints):
            self.endpoints = endpoints
            return [dict(row, status='partial', detail='refused') for row in endpoints]

        def exec(self, *args, **kwargs):
            raise AssertionError('native probe must not execute Python')
    session = Native()
    listeners = [_endpoint('tcp', '127.0.0.1', port) for port in range(3000, 3030)]
    listeners.insert(0, _endpoint('udp', '127.0.0.1', 53))
    section = identify_services(session, listeners)
    assert len(session.endpoints) == 12 and '12 of 30' in section.checks[-1]['detail']
    identify_services(session, listeners, limit=1000)
    assert len(session.endpoints) == 24


def test_unavailable_base_method_preserves_python_fallback():
    class Legacy(Session):
        def exec(self, cmd, timeout=30):
            assert 'command -v python3' in cmd
            return Result('', 'Python unavailable', 127, 0)
    section = identify_services(SurveySession(Legacy()), [ENDPOINT])
    assert section.checks[0]['status'] == 'tool unavailable'


def test_wrapped_legacy_duck_typed_session_preserves_python_fallback():
    class Legacy:
        def exec(self, cmd, timeout=30):
            return Result('', 'Python unavailable', 127, 0)
    section = identify_services(SurveySession(Legacy()), [ENDPOINT])
    assert section.checks[0]['status'] == 'tool unavailable'


@pytest.mark.parametrize('reply', [
    dict(id=True, op='pong'),
    dict(id=1, op='result', stdout='', stderr='', exit_code=True, duration=0),
    dict(id=1, op='result', stdout=[], stderr='', exit_code=0, duration=0),
    dict(id=1, op='result', stdout='\ud800', stderr='', exit_code=0, duration=0),
    dict(id=1, op='result', stdout='x' * (512 * 1024 + 1), stderr='', exit_code=0, duration=0),
    dict(id=1, op='result', stdout='', stderr='', exit_code=0, duration=float('inf'))])
def test_invalid_exec_or_ping_response_closes_channel(make_session, reply):
    session, channel = make_session()
    channel.reply = reply
    with pytest.raises(ConnectionError):
        session._request('ping' if reply['op'] == 'pong' else 'exec', command='id')
    assert channel.closed
