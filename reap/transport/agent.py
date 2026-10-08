"""Authenticated TLS agent adapter implementing the normal Session contract."""
from __future__ import annotations

import threading
import uuid
from pathlib import Path

from ..data.reap_agent import (accept_authenticated, authenticate_client, pinned_client,
                               receive, send, server_context, token_from)
from .base import Result, Session


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
                expected = 'result' if op == 'exec' else 'pong'
                if reply.get('id') != self._sequence or reply.get('op') != expected:
                    raise ConnectionError('invalid agent response')
                return reply
            except BaseException:
                # A timed-out exchange cannot safely be reused for another command.
                self.channel.close()
                self._closed = True
                raise

    def exec(self, cmd, timeout=30):
        timeout = max(0.1, min(float(timeout), 300))
        reply = self._request('exec', timeout, command=cmd, timeout=timeout)
        return Result(reply['stdout'], reply['stderr'], int(reply['exit_code']), float(reply['duration']))

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
