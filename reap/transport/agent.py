"""Authenticated TLS agent adapter implementing the normal Session contract."""
from __future__ import annotations

import threading
import uuid
import math
from pathlib import Path

from ..data.reap_agent import (OUTPUT_LIMIT, accept_authenticated, authenticate_client, pinned_client,
                               receive, send, server_context, token_from)
from ..probe import PROBE_CAPABILITY, finite_number, probe_endpoints, probe_rows, valid_text
from .base import NotSupported, Result, Session


class AgentSession(Session):
    def __init__(self, host='127.0.0.1', port=4444, bundle=None, mode='connect', timeout=60):
        root = Path(bundle)
        token = token_from(root / 'token.txt')
        if mode == 'listen':
            channel, address, hello = accept_authenticated(
                host, port, server_context(root / 'cert.pem', root / 'key.pem'), token, timeout)
            self.host = address[0]
        elif mode == 'connect':
            channel = pinned_client(host, port, (root / 'fingerprint.txt').read_text(), timeout)
            try:
                hello = authenticate_client(channel, token)
            except BaseException:
                channel.close()
                raise
            self.host = host
        else:
            raise ValueError('agent mode must be connect or listen')
        self.channel = channel
        try:
            capabilities = hello.get('capabilities', [])
            if (not isinstance(capabilities, list) or len(capabilities) > 32
                    or any(not isinstance(item, str) or len(item) > 128 for item in capabilities)):
                raise ConnectionError('invalid agent capabilities')
            self.capabilities = frozenset(capabilities)
        except BaseException:
            channel.close()
            raise
        self.local_addr = channel.getsockname()[0]
        self.shell = 'cmd' if hello.get('platform') == 'Windows' else 'sh'
        self.session_id = 'agent-' + uuid.uuid4().hex[:8]
        self._lock = threading.Lock()
        self._closed = False
        self._sequence = 0

    def _request(self, op, wait=30, **fields):
        with self._lock:
            if self._closed:
                raise ConnectionError('agent session is closed')
            self._sequence += 1
            self.channel.settimeout(wait + 10)
            try:
                send(self.channel, dict(fields, id=self._sequence, op=op))
                reply = receive(self.channel)
                expected = {'exec': 'result', 'ping': 'pong', 'probe_tcp': 'probe_result'}.get(op)
                if (type(reply.get('id')) is not int or reply['id'] != self._sequence
                        or expected is None or reply.get('op') != expected):
                    raise ConnectionError('invalid agent response')
                if op == 'exec':
                    if (not valid_text(reply.get('stdout'), OUTPUT_LIMIT)
                            or not valid_text(reply.get('stderr'), OUTPUT_LIMIT + 512)
                            or type(reply.get('exit_code')) is not int
                            or not finite_number(reply.get('duration'))):
                        raise ConnectionError('invalid agent execution result')
                elif op == 'probe_tcp':
                    if not finite_number(reply.get('duration')):
                        raise ConnectionError('invalid agent probe duration')
                    probe_rows(reply.get('rows'), fields['endpoints'])
                return reply
            except BaseException:
                # A timed-out exchange cannot safely be reused for another command.
                self.channel.close()
                self._closed = True
                raise

    def exec(self, cmd, timeout=30):
        if not isinstance(cmd, str) or len(cmd) > 256 * 1024:
            raise ValueError('invalid command')
        timeout = float(timeout)
        if not math.isfinite(timeout):
            raise ValueError('command timeout must be finite')
        timeout = max(0.1, min(timeout, 300))
        reply = self._request('exec', timeout, command=cmd, timeout=timeout)
        return Result(reply['stdout'], reply['stderr'], int(reply['exit_code']), float(reply['duration']))

    def probe_tcp(self, endpoints):
        if PROBE_CAPABILITY not in self.capabilities or self.shell == 'cmd':
            raise NotSupported('peer does not support Linux native TCP probing')
        endpoints = probe_endpoints(endpoints)
        return self._request('probe_tcp', 55, endpoints=endpoints)['rows']

    def is_alive(self):
        try:
            return self._request('ping', 5).get('op') == 'pong'
        except Exception:
            return False

    def close(self):
        with self._lock:
            if not self._closed:
                try:
                    send(self.channel, {'op': 'close'})
                except OSError:
                    pass
                self.channel.close()
                self._closed = True
