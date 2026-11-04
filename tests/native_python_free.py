#!/usr/bin/env python3
"""Operator-side smoke test against an isolated Alpine rootfs. Run as root on Linux.

The supplied rootfs must be a disposable Alpine minirootfs extraction. No Python,
Go, compiler, glibc or OpenSSL CLI is installed in the target. iproute2, unshare
and chroot run on the operator. Target networking is isolated with a veth pair.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import io
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import time

from rich.console import Console
from reap.agent import create_agent
from reap.console import ReapConsole
from reap.fingerprint import fingerprint
from reap.netinfo import probe_listeners
from reap.serviceinfo import identify_services
from reap.survey import SurveySession
from reap.transport.agent import AgentSession


def call(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--http-fixture', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root for temporary network/mount/PID namespaces')
    source = args.rootfs.resolve()
    if not (source / 'etc/alpine-release').is_file():
        parser.error('--rootfs must be a disposable Alpine minirootfs')
    tag = secrets.token_hex(4)
    namespace, host_veth, target_veth = 'reap-' + tag, 'rh' + tag, 'rt' + tag
    octet = secrets.randbelow(254) + 1
    host_ip, target_ip = '198.19.%s.1' % octet, '198.19.%s.2' % octet
    process = session = None
    pool = concurrent.futures.ThreadPoolExecutor(1)
    with tempfile.TemporaryDirectory(prefix='reap-python-free-') as scratch:
        scratch = Path(scratch)
        root = scratch / 'target'
        shutil.copytree(source, root, symlinks=True)
        for name, minor in (('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)):
            path = root / 'dev' / name
            if not path.exists():
                os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        from reap import agent
        agent._NATIVE_ROOT = args.binary.resolve().parent
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        profile = create_agent(host_ip, output=scratch / 'reap-agent', port=port,
                               state_dir=scratch / 'operator-private-settings')
        shutil.copyfile(profile.executable, root / 'reap-agent')
        assert not (root / 'kit').exists()
        shutil.copyfile(args.http_fixture, root / 'http-fixture')
        (root / 'reap-agent').chmod(0o700)
        (root / 'http-fixture').chmod(0o700)
        # Force the procfs fallback instead of relying on BusyBox netstat.
        for directory in ('bin', 'sbin', 'usr/bin', 'usr/sbin'):
            for name in ('ss', 'netstat'):
                path = root / directory / name
                if path.is_file() or path.is_symlink():
                    path.unlink()
        try:
            call('ip', 'netns', 'add', namespace)
            call('ip', 'link', 'add', host_veth, 'type', 'veth', 'peer', 'name', target_veth)
            call('ip', 'link', 'set', target_veth, 'netns', namespace)
            call('ip', 'addr', 'add', host_ip + '/30', 'dev', host_veth)
            call('ip', 'link', 'set', host_veth, 'up')
            call('ip', 'netns', 'exec', namespace, 'ip', 'addr', 'add', target_ip + '/30', 'dev', target_veth)
            call('ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', target_veth, 'up')
            call('ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up')
            listener = pool.submit(AgentSession, '0.0.0.0', port, profile.authkit, 'listen', 10)
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('operator listener did not start')
                    time.sleep(0.02)
            process = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'unshare', '--mount', '--pid',
                '--fork', '--kill-child', 'chroot', str(root), '/bin/sh', '-c',
                'mount -t proc proc /proc || exit 1\n/http-fixture &\n'
                'exec /reap-agent'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            session = listener.result(timeout=12)
            missing = session.exec('for x in python python3 go gcc openssl ss netstat; do command -v "$x" && exit 9; done; test ! -e /lib/ld-linux-x86-64.so.2')
            assert missing.exit_code == 0, missing
            ctx = fingerprint(session)
            assert ctx.os == 'linux' and not ctx.has_runtime('python'), ctx
            assert session.exec("printf 'quoted path\n' | grep 'quoted path'; id").ok
            listeners = probe_listeners(SurveySession(session))
            endpoint = next(row for row in listeners if row['port'] == 3000 and row['ip'] == '127.0.0.1')
            assert any(check['name'].startswith('PROC_') and check['status'] == 'completed' for check in listeners.checks)
            section = identify_services(SurveySession(session), [endpoint])
            assert 'Python-free lab application' in section.lines[0], section
            console = ReapConsole(str(scratch / 'smoke.reap.db'))
            output = io.StringIO()
            console.console = Console(file=output, width=180, color_system=None)
            console.sessions[session.session_id] = session
            console.contexts[session.session_id] = ctx
            console.active = session.session_id
            console.do_ports('--probe')
            console.do_enum('--save --probe --brief')
            assert 'Python-free lab application' in output.getvalue(), output.getvalue()
            assert len(console.store.get_snapshots()) > 0
            session.close()
            assert process.wait(timeout=5) == 0
            print('PASS: One copied agent with no flags or companion credentials; Alpine has no Python/Go/compiler/OpenSSL/glibc; fingerprint, shell, procfs ports, probe and enum --save verified.')
        finally:
            if session:
                session.close()
            if process:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
            subprocess.run(['ip', 'netns', 'delete', namespace], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['ip', 'link', 'delete', host_veth], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pool.shutdown(wait=True)


if __name__ == '__main__':
    main()
