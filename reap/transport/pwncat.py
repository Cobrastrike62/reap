"""PwncatHandoffSession — glue for a pwncat-vl–stabilized shell.

CONSTRAINT: declare, don't reimplement. Raw reverse shells (nc, react2shell)
are a bad exec channel — no boundaries, no exit codes. Stabilization is a solved
problem **owned by pwncat-vl** (auto-PTY, raw mode, TERM sync, and a busybox
``forkpty`` helper for minimal_userland targets). We do not write a
raw-shell stabilizer and we do not vendor busybox/forkpty binaries.

The v1 flow this wraps:
  1. pwncat-vl catches and stabilizes the shell.
  2. Operator upgrades to a proper channel — drops/uses an SSH key.
  3. That SSH channel is registered here.

So the simplest correct adapter is a thin convenience over the resulting
``SSHSession``; it embeds no pwncat internals. When the Meterpreter adapter
exists, ``shell_to_meterpreter`` becomes an alternative upgrade target.

Manual fallback (docs): on boxes where even pwncat-vl taps out (restricted or
exotic shells), the operator does the PTY dance by hand and registers SSH/WinRM
directly — this adapter is a convenience, not a dependency.
"""
from __future__ import annotations

from typing import Optional

from .base import Result, Session
from .ssh import SSHSession


class PwncatHandoffSession(Session):
    def __init__(
        self,
        host: str,
        username: str,
        key: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 22,
        session_id: Optional[str] = None,
        **ssh_kwargs,
    ):
        self.host = host
        self.username = username
        self.session_id = session_id or f"handoff:{username}@{host}:{port}"
        # The upgraded channel. v1 == SSH after a pwncat-dropped key.
        self._inner = SSHSession(
            host,
            username,
            password=password,
            key=key,
            port=port,
            session_id=self.session_id,
            **ssh_kwargs,
        )

    def exec(self, cmd: str, timeout: int = 30) -> Result:
        return self._inner.exec(cmd, timeout=timeout)

    def upload(self, local_path: str, remote_path: str) -> bool:
        return self._inner.upload(local_path, remote_path)

    def open_forward(self, remote_host: str, remote_port: int, local_port: int = 0):
        return self._inner.open_forward(remote_host, remote_port, local_port)

    def is_alive(self) -> bool:
        return self._inner.is_alive()

    def close(self) -> None:
        self._inner.close()
