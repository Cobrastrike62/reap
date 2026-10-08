#!/usr/bin/env python3
"""Foreground Reap lab agent. Standalone: Python 3.9+ standard library only."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

MAX_FRAME = 8 * 1024 * 1024
OUTPUT_LIMIT = 512 * 1024


def receive(sock):
    def exact(n):
        data = bytearray()
        while len(data) < n:
            part = sock.recv(n - len(data))
            if not part:
                raise ConnectionError('agent channel closed')
            data.extend(part)
        return bytes(data)
    size = struct.unpack('!I', exact(4))[0]
    if size == 0 or size > MAX_FRAME:
        raise ValueError('invalid agent frame length')
    message = json.loads(exact(size).decode('utf-8'))
    if not isinstance(message, dict):
        raise ValueError('agent frame must be an object')
    return message


def send(sock, message):
    data = json.dumps(message, ensure_ascii=True).encode('utf-8')
    if len(data) > MAX_FRAME:
        raise ValueError('agent frame too large')
    sock.sendall(struct.pack('!I', len(data)) + data)


def token_from(path):
    token = Path(path).read_text(encoding='utf-8').strip()
    if len(token) < 32:
        raise ValueError('token file must contain at least 32 characters')
    return token


def pinned_client(host, port, fingerprint, timeout=30):
    pin = fingerprint.replace(':', '').strip().lower()
    if len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
        raise ValueError('a SHA-256 certificate fingerprint is required')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # identity is checked against the explicit pin below
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        channel = context.wrap_socket(raw, server_hostname=host)
        digest = hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(digest, pin):
            channel.close()
            raise ssl.SSLError('agent certificate fingerprint mismatch')
        return channel
    except BaseException:
        raw.close()
        raise


def server_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def info():
    return {'version': 1, 'platform': platform.system(), 'hostname': socket.gethostname()}


def authenticate_client(channel, token):
    send(channel, dict(info(), op='auth', token=token))
    reply = receive(channel)
    if reply.get('op') != 'ready' or reply.get('version') != 1:
        raise PermissionError('agent authentication failed')
    return reply


def authenticate_server(channel, token):
    hello = receive(channel)
    supplied = hello.get('token', '')
    if (hello.get('op') != 'auth' or hello.get('version') != 1
            or not isinstance(supplied, str) or len(supplied) != len(token)
            or not hmac.compare_digest(supplied.encode('utf-8'), token.encode('utf-8'))):
        raise PermissionError('agent authentication failed')
    send(channel, dict(info(), op='ready'))
    hello.pop('token', None)
    return hello


def kill_process(process):
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except (ProcessLookupError, OSError):
        pass


def execute(command, timeout):
    if not isinstance(command, str) or len(command) > 256 * 1024:
        raise ValueError('invalid command')
    timeout = max(0.1, min(float(timeout), 300))
    start = time.monotonic()
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=os.name == 'posix')
    buffers = [bytearray(), bytearray()]
    capped = threading.Event()

    def drain(stream, buffer):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                remaining = OUTPUT_LIMIT - len(buffer)
                buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    capped.set()
        except (OSError, ValueError):
            pass
        finally:
            stream.close()

    readers = [threading.Thread(target=drain, args=(stream, buffer), daemon=True)
               for stream, buffer in zip((process.stdout, process.stderr), buffers)]
    for reader in readers:
        reader.start()
    status = None
    # Wait for both output streams too: a background child can retain pipe handles.
    try:
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if capped.is_set():
                status = 125
                break
            if time.monotonic() - start >= timeout:
                status = 124
                break
            time.sleep(0.02)
        if capped.is_set() and status is None:
            status = 125
        if status is not None:
            kill_process(process)
        process.wait(timeout=5)
    except BaseException:
        kill_process(process)
        process.wait(timeout=5)
        raise
    finally:
        for reader in readers:
            reader.join(timeout=1)
    stdout, stderr = (bytes(b).decode('utf-8', 'replace') for b in buffers)
    if status == 124:
        stderr += '\nReap agent: command timed out; output may be partial.'
    elif status == 125:
        stderr += '\nReap agent: output cap reached (512 KiB per stream); command stopped.'
    return dict(stdout=stdout, stderr=stderr, exit_code=status if status is not None else process.returncode,
                duration=time.monotonic() - start)


def serve(channel):
    channel.settimeout(None)
    while True:
        request = receive(channel)
        ident, op = request.get('id'), request.get('op')
        if op == 'close':
            return
        if op == 'ping':
            send(channel, {'id': ident, 'op': 'pong'})
        elif op == 'exec':
            result = execute(request.get('command'), request.get('timeout', 30))
            send(channel, dict(result, id=ident, op='result'))
        else:
            raise ValueError('unsupported agent operation')


def accept_authenticated(host, port, context, token, timeout=60):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(4)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            raw, address = listener.accept()
            channel = None
            try:
                raw.settimeout(min(10, max(0.1, deadline - time.monotonic())))
                channel = context.wrap_socket(raw, server_side=True)
                hello = authenticate_server(channel, token)
                return channel, address, hello
            except (OSError, ValueError, PermissionError, ConnectionError):
                if channel:
                    channel.close()
                raw.close()
        raise TimeoutError('no authenticated agent connection received')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--connect', metavar='HOST', help='connect back to Reap')
    group.add_argument('--bind', metavar='ADDRESS', help='listen for Reap (foreground)')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--fingerprint-file', help='required in connect mode')
    parser.add_argument('--cert', help='required in bind mode')
    parser.add_argument('--key', help='required in bind mode')
    args = parser.parse_args(argv)
    token = token_from(args.token_file)
    if args.connect:
        if not args.fingerprint_file:
            parser.error('--connect requires --fingerprint-file')
        pin = Path(args.fingerprint_file).read_text(encoding='utf-8')
        channel = pinned_client(args.connect, args.port, pin)
        authenticate_client(channel, token)
    else:
        if not args.cert or not args.key:
            parser.error('--bind requires --cert and --key')
        print('Reap agent listening on %s:%s for 60 seconds' % (args.bind, args.port), flush=True)
        channel, _, _ = accept_authenticated(args.bind, args.port, server_context(args.cert, args.key), token)
    print('Reap agent connected; Ctrl-C stops it. No persistence is installed.', flush=True)
    try:
        with channel:
            serve(channel)
    except (ConnectionError, KeyboardInterrupt):
        pass


if __name__ == '__main__':
    main()
