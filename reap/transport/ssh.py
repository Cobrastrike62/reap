"""SSHSession — paramiko adapter. The cleanest channel: real exit codes for free."""
from __future__ import annotations

import io
import os
import socket
import time
from typing import Optional

from .base import Result, Session

try:
    import paramiko
except ImportError:  # pragma: no cover - surfaced at construction
    paramiko = None


class SSHSession(Session):
    """One SSH channel to one target.

    Accepts a password or a private key (PEM string or path). Agent/known-keys
    lookup is disabled so auth is deterministic — important for a tool that also
    *tests* credentials during correlation.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        port: int = 22,
        session_id: Optional[str] = None,
        connect_timeout: int = 15,
    ):
        if paramiko is None:
            raise RuntimeError("paramiko not installed — pip install paramiko")
        self.host = host
        self.port = int(port)
        self.username = username
        self.session_id = session_id or f"ssh:{username}@{host}:{self.port}"
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = self._load_key(key, key_passphrase) if key else None
        self._client.connect(
            hostname=host,
            port=self.port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=connect_timeout,
            allow_agent=False,
            look_for_keys=False,
        )

    @staticmethod
    def _load_key(key: str, passphrase: Optional[str]):
        """Load a private key from PEM content or a filesystem path, trying each
        key type until one parses."""
        if "PRIVATE KEY" in key:
            data = key
        else:
            with open(os.path.expanduser(key)) as fh:
                data = fh.read()
        last_err: Optional[Exception] = None
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                return cls.from_private_key(io.StringIO(data), password=passphrase)
            except Exception as exc:  # wrong type / needs passphrase — try next
                last_err = exc
        raise ValueError(f"could not parse private key: {last_err}")

    def exec(self, cmd: str, timeout: int = 30) -> Result:
        start = time.monotonic()
        try:
            _stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        except socket.timeout:
            return Result("", f"timeout after {timeout}s", 124, time.monotonic() - start)
        return Result(out, err, code, time.monotonic() - start)

    def upload(self, local_path: str, remote_path: str) -> bool:
        sftp = self._client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
            return True
        finally:
            sftp.close()

    def open_forward(self, remote_host: str, remote_port: int, local_port: int = 0):
        """Local forward (ssh -L) over this session's transport via direct-tcpip."""
        from .forward import LocalForward
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("SSH transport is not active")
        return LocalForward(transport, remote_host, int(remote_port), int(local_port))

    def is_alive(self) -> bool:
        transport = self._client.get_transport()
        return bool(transport and transport.is_active())

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
