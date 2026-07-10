"""MeterpreterSession — OUT OF SCOPE (v1). Build hook only.

Left as a stub so the slot in the transport layer is obvious. The intended
implementation is pymetasploit3 talking to msfrpcd: the operator runs
``shell_to_meterpreter`` (from pwncat or msf), then registers the resulting
session here. The Session interface above is deliberately transport-agnostic so
this drops in without touching modules, store, engine, or console.
"""
from __future__ import annotations

from .base import Result, Session


class MeterpreterSession(Session):
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "MeterpreterSession is an out-of-scope v1 hook. "
            "Implement via pymetasploit3 + msfrpcd when the adapter is needed."
        )

    def exec(self, cmd: str, timeout: int = 30) -> Result:  # pragma: no cover
        raise NotImplementedError

    def is_alive(self) -> bool:  # pragma: no cover
        return False
