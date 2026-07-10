"""Module base + registry.

A module is trigger → collect → emit. CONSTRAINT: the plugin interface is the
backbone — a new runtime must be addable as a ~30-line plugin (a file + the
known-filename list) without touching the engine, store, or console. The
``@register`` decorator plus auto-import in ``registry.py`` makes that true.
"""
from __future__ import annotations

from ..models import Context, Finding
from ..transport.base import Session


class Module:
    name: str = "module"

    def triggers(self, ctx: Context) -> bool:
        """Should this module fire for this context? Default: always."""
        return True

    def collect(self, session: Session) -> list[Finding]:
        """Run collection, return typed findings. Never prints as output."""
        return []


_REGISTRY: list[type[Module]] = []


def register(cls: type[Module]) -> type[Module]:
    """Class decorator: add a module to the global registry."""
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def registered() -> list[type[Module]]:
    return list(_REGISTRY)
