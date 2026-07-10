"""Module/plugin system: fingerprint-gated collection."""
from __future__ import annotations

from .base import Module, register, registered
from .registry import all_modules, select

__all__ = ["Module", "register", "registered", "all_modules", "select"]
