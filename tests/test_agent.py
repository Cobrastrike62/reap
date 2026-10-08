from __future__ import annotations

import concurrent.futures
import os
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import time

import pytest

from reap.agent import prepare_bundle
from reap.data.reap_agent import (MAX_FRAME, OUTPUT_LIMIT, execute, pinned_client,
                                  receive, send)
from reap.transport.agent import AgentSession


def unused_port():
    with socket.socket() as channel:
        channel.bind(('127.0.0.1', 0))
        return channel.getsockname()[1]


def wait_listening(port, process=None):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process and process.poll() is not None:
            raise AssertionError(process.communicate()[1])
        try:
            with socket.create_connection(('127.0.0.1', port), 0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise AssertionError('fixture listener did not start')


def python_command(code):
    if os.name == 'nt':
        return subprocess.list2cmdline([sys.executable, '-c', code])
    return shlex.join([sys.executable, '-c', code])


@pytest.fixture
def bundle(tmp_path):
    return prepare_bundle(tmp_path / 'agent-bundle')


def check_session(session):
    result = session.exec(python_command('import sys; print("agent output"); print("agent error", file=sys.stderr); sys.exit(7)'))
    assert result.stdout.strip() == 'agent output'
    assert result.stderr.strip() == 'agent error'
    assert result.exit_code == 7 and result.duration > 0
    assert session.is_alive()
    result = session.exec(python_command('import time; time.sleep(10)'), timeout=0.2)
    assert result.exit_code == 124 and 'timed out' in result.stderr
    assert session.exec(python_command('print("still usable")')).ok


def test_standalone_bind_agent_token_pin_and_session_contract(bundle, tmp_path):
    port = unused_port()
    command = [sys.executable, '-u', str(bundle / 'reap_agent.py'), '--bind', '127.0.0.1',
               '--port', str(port), '--token-file', str(bundle / 'token.txt'),
               '--cert', str(bundle / 'cert.pem'), '--key', str(bundle / 'key.pem')]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    session = None
    try:
        wait_listening(port, process)
        with pytest.raises(ssl.SSLError, match='fingerprint mismatch'):
            pinned_client('127.0.0.1', port, '0' * 64)
        bad = tmp_path / 'bad'
        bad.mkdir()
        (bad / 'token.txt').write_text('different' * 8)
        (bad / 'fingerprint.txt').write_text((bundle / 'fingerprint.txt').read_text())
        with pytest.raises((ConnectionError, PermissionError)):
            AgentSession('127.0.0.1', port, bad)
        session = AgentSession('127.0.0.1', port, bundle)
        check_session(session)
        session.close()
        assert not session.is_alive()
        assert process.wait(timeout=5) == 0
    finally:
        if session:
            session.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def test_standalone_connect_back_agent(bundle):
    port = unused_port()
    process = session = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(AgentSession, '127.0.0.1', port, bundle, 'listen', 10)
        try:
            wait_listening(port)
            process = subprocess.Popen([sys.executable, '-u', str(bundle / 'reap_agent.py'),
                '--connect', '127.0.0.1', '--port', str(port), '--token-file', str(bundle / 'token.txt'),
                '--fingerprint-file', str(bundle / 'fingerprint.txt')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            session = future.result(timeout=10)
            check_session(session)
            session.close()
            assert process.wait(timeout=5) == 0
        finally:
            if session:
                session.close()
            if process:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


def test_frames_enforce_bounds_and_eof():
    one, two = socket.socketpair()
    try:
        one.sendall(struct.pack('!I', MAX_FRAME + 1))
        with pytest.raises(ValueError, match='length'):
            receive(two)
        one.sendall(struct.pack('!I', 5) + b'{}')
        one.close()
        with pytest.raises(ConnectionError):
            receive(two)
    finally:
        one.close()
        two.close()


def test_output_cap_is_explicit_and_bounded():
    result = execute(python_command('import sys; sys.stdout.write("x" * 2000000)'), 10)
    assert len(result['stdout']) <= OUTPUT_LIMIT
    assert result['exit_code'] == 125
    assert 'output cap reached' in result['stderr']


def test_bundle_never_overwrites_identity(bundle):
    token = (bundle / 'token.txt').read_bytes()
    with pytest.raises(FileExistsError):
        prepare_bundle(bundle)
    assert (bundle / 'token.txt').read_bytes() == token


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process group cleanup')
def test_timeout_stops_background_children(tmp_path):
    marker = tmp_path / 'should-not-exist'
    command = '(sleep 1; touch %s) & wait' % shlex.quote(str(marker))
    assert execute(command, 0.1)['exit_code'] == 124
    time.sleep(1.1)
    assert not marker.exists()
