"""Module discovery. Auto-imports every submodule under primitives/, wrappers/,
and plugins/ so that dropping a new ``@register``-decorated file is enough to
add a module — no engine/console edits (the CONSTRAINT)."""
from __future__ import annotations

import importlib
import pkgutil

from ..models import Context
from .base import Module, registered

_LOADED = False


def _load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    from . import plugins, primitives, wrappers
    for pkg in (primitives, wrappers, plugins):
        for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
            importlib.import_module(info.name)
    _LOADED = True


def all_modules() -> list[Module]:
    _load_all()
    return [cls() for cls in registered()]


def select(ctx: Context) -> list[Module]:
    """Modules whose trigger fires for this context. A raising trigger is
    treated as 'no' rather than aborting selection."""
    out = []
    for module in all_modules():
        try:
            if module.triggers(ctx):
                out.append(module)
        except Exception:
            continue
    return out
