"""WinRMSession — pypsrp adapter for structured exec on Windows."""
from __future__ import annotations

import time
from typing import Optional

from .base import Result, Session

try:
    from pypsrp.client import Client
except ImportError:  # pragma: no cover - surfaced at construction
    Client = None


class WinRMSession(Session):
    """WS-Management channel. ``exec`` runs through cmd.exe to preserve a real
    exit code (the Session contract); use :meth:`ps` for PowerShell where the
    error stream, not an exit code, signals failure."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 5985,
        ssl: bool = False,
        auth: str = "negotiate",
        session_id: Optional[str] = None,
        operation_timeout: int = 30,
    ):
        if Client is None:
            raise RuntimeError("pypsrp not installed — pip install pypsrp")
        self.host = host
        self.port = int(port)
        self.username = username
        self.session_id = session_id or f"winrm:{username}@{host}:{self.port}"
        self._client = Client(
            host,
            username=username,
            password=password,
            port=self.port,
            ssl=ssl,
            auth=auth,
            cert_validation=False,
            operation_timeout=operation_timeout,
        )

    def exec(self, cmd: str, timeout: int = 30) -> Result:
        start = time.monotonic()
        stdout, stderr, rc = self._client.execute_cmd(cmd)
        return Result(stdout, stderr, rc, time.monotonic() - start)

    def ps(self, script: str, timeout: int = 30) -> Result:
        """Run a PowerShell script. PS reports failure via its error stream, so
        exit_code is synthesized: 0 when no errors, 1 otherwise."""
        start = time.monotonic()
        output, streams, had_errors = self._client.execute_ps(script)
        err = "\n".join(str(e) for e in streams.error) if had_errors else ""
        return Result(output, err, 1 if had_errors else 0, time.monotonic() - start)

    def upload(self, local_path: str, remote_path: str) -> bool:
        self._client.copy(local_path, remote_path)
        return True

    def is_alive(self) -> bool:
        try:
            _out, _err, rc = self._client.execute_cmd("echo alive")
            return rc == 0
        except Exception:
            return False
