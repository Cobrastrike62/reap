"""The ``Session`` contract — the single seam between modules and targets.

CONSTRAINT: modules never see the transport. Everything talks to the target
through ``Session.exec()``. A module must behave identically over SSH, WinRM,
or a handed-off pwncat shell. Build this right; everything depends on it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass


class NotSupported(Exception):
    """Raised by an adapter for an operation its channel cannot perform
    (e.g. ``upload`` over a bare shell)."""


@dataclass
class Result:
    """The clean, per-command result. ``exit_code`` MUST be real; output MUST
    NOT interleave across calls."""

    stdout: str
    stderr: str
    exit_code: int
    duration: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def out(self) -> str:
        """stdout stripped of a single trailing newline — convenient for parsing."""
        return self.stdout.rstrip("\n")


class Session:
    """One target, one channel. Adapters implement :meth:`exec`."""

    session_id: str   # stable handle for the loot store
    host: str         # target IP/hostname

    def exec(self, cmd: str, timeout: int = 30) -> Result:
        """Run a command; return output cleanly associated with that command.

        MUST return a real exit code. MUST NOT interleave output across calls.
        """
        raise NotImplementedError

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Optional per adapter; raise :class:`NotSupported` if the channel can't."""
        raise NotSupported(f"{type(self).__name__} does not support upload")

    def open_forward(self, remote_host: str, remote_port: int, local_port: int = 0):
        """Open a local port-forward through this session's channel (like ``ssh -L``),
        returning a started ``LocalForward``. Only SSH-backed sessions can; others raise
        :class:`NotSupported`. Used to reach a target's loopback-only services."""
        raise NotSupported(
            f"{type(self).__name__} cannot forward (needs an SSH transport)")

    def is_alive(self) -> bool:
        raise NotImplementedError

    # -- convenience shared by adapters; not part of the minimal contract -------
    def sh(self, cmd: str, timeout: int = 30) -> str:
        """Run and return stdout (stripped). Errors are swallowed to empty string
        so probe/collection code can stay terse. Use :meth:`exec` when you need
        the exit code."""
        try:
            return self.exec(cmd, timeout=timeout).out
        except Exception:
            return ""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{type(self).__name__} {getattr(self, 'session_id', '?')} {getattr(self, 'host', '?')}>"


def _timed(fn):
    """Decorator helper for adapters: measure wall-clock and stamp ``duration``."""
    def wrapper(*args, **kwargs):
        start = time.monotonic()
        result: Result = fn(*args, **kwargs)
        result.duration = time.monotonic() - start
        return result
    return wrapper
