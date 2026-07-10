"""Transport layer - adapters implementing the one Session contract.

Modules never import from here; they receive a Session and call exec().
The console uses ADAPTERS to build a session from a register command.
"""
from __future__ import annotations

from .base import NotSupported, Result, Session
from .meterpreter import MeterpreterSession
from .pwncat import PwncatHandoffSession
from .ssh import SSHSession
from .webshell import WebShellSession

# pypsrp is an optional dependency; keep the package importable without it.
try:
    from .winrm import WinRMSession
except Exception:  # pragma: no cover
    WinRMSession = None  # type: ignore[assignment]

ADAPTERS = {
    "ssh": SSHSession,
    "winrm": WinRMSession,
    "handoff": PwncatHandoffSession,
    "pwncat": PwncatHandoffSession,
    "meterpreter": MeterpreterSession,
    "webshell": WebShellSession,
}

__all__ = [
    "Session",
    "Result",
    "NotSupported",
    "SSHSession",
    "WinRMSession",
    "PwncatHandoffSession",
    "MeterpreterSession",
    "WebShellSession",
    "ADAPTERS",
]

