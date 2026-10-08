from __future__ import annotations

import os
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from reap.agent import prepare_bundle
from reap.netinfo import _endpoint
from reap.serviceinfo import identify_services
from tests.test_survey import Canned, LocalSession
from reap.transport.base import Result


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://do-not-follow.invalid/private')
        self.end_headers()
        self.wfile.write(b'<html><title>Lab &amp; test service</title></html>')
    def log_message(self, *args):
        pass


@pytest.mark.skipif(os.name != 'posix', reason='Linux target identification')
@pytest.mark.parametrize('tls', [False, True])
def test_unknown_port_http_title_redirect_and_tls(tmp_path, tls):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    if tls:
        bundle = prepare_bundle(tmp_path / 'tls')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(bundle / 'cert.pem'), str(bundle / 'key.pem'))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        section = identify_services(LocalSession(), [_endpoint('tcp', '127.0.0.1', port)])
        assert 'Lab & test service' in section.lines[0]
        assert '302' in section.lines[0] and 'do-not-follow.invalid' in section.lines[0]
        assert section.flags[0].confidence == 'observed'
        assert section.checks[0]['status'] == 'completed'
        if tls:
            assert 'certificate_sha256' in section.lines[0]
            assert '"identity_verified": false' in section.lines[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_missing_python_and_candidate_cap():
    session = Canned(Result('', 'Python unavailable', 127, 0))
    rows = [_endpoint('tcp', '127.0.0.1', port) for port in range(3000, 3015)]
    section = identify_services(session, rows)
    assert section.checks[0]['status'] == 'tool unavailable'
    assert '12 of 15' in section.checks[-1]['detail']
