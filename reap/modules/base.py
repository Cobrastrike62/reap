"""Module base + registry.

A module is trigger → collect → emit. CONSTRAINT: the plugin interface is the
backbone — a new runtime must be addable as a ~30-line plugin (a file + the
known-filename list) without touching the engine, store, or console. The
``@register`` decorator plus auto-import in ``registry.py`` makes that true.
"""
from __future__ import annotations

from ..models import Context, EnumSection, Finding
from ..transport.base import Session


class Module:
    name: str = "module"

    def triggers(self, ctx: Context) -> bool:
        """Should this module fire for this context? Default: always."""
        return True

    def collect(self, session: Session) -> list[Finding]:
        """Run collection, return typed findings. Never prints as output."""
        return []

    def enumerate(self, session: Session) -> list[EnumSection]:
        """Optional situational-awareness dump for the ``enum`` console view
        (full process / service / cron / network listings, linpeas-style).

        Screen-only and unbounded by design; the actionable subset is persisted
        as ``Finding`` objects by :meth:`collect` instead. Modules that have
        nothing to survey inherit this no-op and are skipped by ``enum``.
        """
        return []


_REGISTRY: list[type[Module]] = []


def register(cls: type[Module]) -> type[Module]:
    """Class decorator: add a module to the global registry."""
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def registered() -> list[type[Module]]:
    return list(_REGISTRY)
