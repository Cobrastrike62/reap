"""Runtime interoperability fixtures. Commands on the target never invoke Python."""
from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import time

import pytest

from reap.agent import prepare_bundle
from reap.data.reap_agent import pinned_client, receive, send
from reap.transport.agent import AgentSession
from tests.test_agent import unused_port, wait_listening


@pytest.fixture(scope='module')
def native_binary():
    filename = 'reap-agent-windows-amd64.exe' if os.name == 'nt' else 'reap-agent-linux-amd64'
    path = Path(os.environ.get('REAP_NATIVE_BINARY', Path(__file__).resolve().parents[1] / 'native-agent/dist' / filename))
    if not path.is_file():
        pytest.skip('native executable unavailable; run native-agent/build.py explicitly')
    return path.resolve()


@pytest.fixture(params=['bind', 'connect'])
def native_session(native_binary, tmp_path, request):
    bundle = prepare_bundle(tmp_path / 'kit')
    port = unused_port()
    command = [str(native_binary), '--port', str(port), '--token-file', str(bundle / 'token.txt')]
    session = process = None
    pool = concurrent.futures.ThreadPoolExecutor(1)
    try:
        if request.param == 'bind':
            process = subprocess.Popen(command + ['--bind', '127.0.0.1', '--cert', str(bundle / 'cert.pem'),
                                      '--key', str(bundle / 'key.pem')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            wait_listening(port, process)
            session = AgentSession('127.0.0.1', port, bundle)
        else:
            future = pool.submit(AgentSession, '127.0.0.1', port, bundle, 'listen', 10)
            wait_listening(port)
            process = subprocess.Popen(command + ['--connect', '127.0.0.1', '--fingerprint-file',
                                       str(bundle / 'fingerprint.txt')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            session = future.result(timeout=10)
        yield session
        session.close()
        assert process.wait(timeout=5) == 0, process.communicate()
    finally:
        if session:
            session.close()
        if process:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        pool.shutdown(wait=True)


def test_native_shell_exit_and_timeout(native_session):
    session = native_session
    assert session.shell == ('cmd' if os.name == 'nt' else 'sh')
    command = '(echo agent output)& (echo agent error 1>&2)& exit /b 7' if os.name == 'nt' else "printf 'agent output\n'; printf 'agent error\n' >&2; exit 7"
    result = session.exec(command)
    assert result.stdout.strip() == 'agent output'
    assert result.stderr.strip() == 'agent error'
    assert result.exit_code == 7 and result.duration >= 0
    assert session.is_alive()
    sleeper = 'ping -n 10 127.0.0.1 >nul' if os.name == 'nt' else 'sleep 10'
    start = time.monotonic()
    result = session.exec(sleeper, timeout=0.15)
    assert result.exit_code == 124 and 'timed out' in result.stderr
    assert time.monotonic() - start < 4
    assert session.exec('echo usable').stdout.strip() == 'usable'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX command fixture')
def test_native_output_bytes_caps_and_background_cleanup(native_session, tmp_path):
    result = native_session.exec("printf '\\377'; printf 'unicode: ☃\n' >&2")
    assert result.stdout == '\ufffd' and '☃' in result.stderr
    result = native_session.exec("(yes x | head -c 700000) & (yes y | head -c 700000 >&2) & wait")
    assert result.exit_code == 125 and 'output cap' in result.stderr
    assert len(result.stdout.encode()) <= 524288
    assert len(result.stderr.encode()) < 525000
    marker = tmp_path / 'background-survived'
    result = native_session.exec("(sleep 1; touch '%s') & wait" % marker, timeout=0.1)
    assert result.exit_code == 124
    time.sleep(1.1)
    assert not marker.exists()
    # A child retaining pipes after its shell exits must still honor the deadline.
    start = time.monotonic()
    result = native_session.exec('sleep 10 &', timeout=0.1)
    assert time.monotonic() - start < 4
    assert native_session.is_alive()


@pytest.mark.skipif(os.name == 'nt', reason='Linux native probe')
def test_native_probe_through_survey(native_session):
    import threading
    from http.server import ThreadingHTTPServer
    from reap.netinfo import _endpoint
    from reap.serviceinfo import identify_services
    from reap.survey import SurveySession
    from tests.test_serviceinfo import Handler
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        wrapped = SurveySession(native_session)
        assert 'probe_tcp_v1' in native_session.capabilities
        result = identify_services(wrapped, [_endpoint('tcp', '127.0.0.1', server.server_port)])
        assert 'Lab & test service' in result.lines[0]
        assert 'do-not-follow.invalid' in result.lines[0]
        assert result.checks[0]['status'] == 'completed'
        assert not wrapped.cache  # No target Python command was sent.
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_native_listener_rejects_invalid_clients(native_binary, tmp_path):
    bundle = prepare_bundle(tmp_path / 'kit')
    port = unused_port()
    process = subprocess.Popen([str(native_binary), '--bind', '127.0.0.1', '--port', str(port),
        '--token-file', str(bundle / 'token.txt'), '--cert', str(bundle / 'cert.pem'),
        '--key', str(bundle / 'key.pem')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_listening(port, process)
        with pytest.raises(ssl.SSLError):
            pinned_client('127.0.0.1', port, '0' * 64)
        for payload in [struct.pack('!I', 8388609), struct.pack('!I', 0), struct.pack('!I', 2) + b'[]']:
            channel = pinned_client('127.0.0.1', port, (bundle / 'fingerprint.txt').read_text())
            channel.sendall(payload)
            with pytest.raises((ConnectionError, OSError)):
                receive(channel)
            channel.close()
        wrong = pinned_client('127.0.0.1', port, (bundle / 'fingerprint.txt').read_text())
        send(wrong, dict(op='auth', version=1, token='x' * 43))
        with pytest.raises((ConnectionError, OSError)):
            receive(wrong)
        wrong.close()
        session = AgentSession('127.0.0.1', port, bundle)
        assert session.is_alive()
        session.close()
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
