"""Shared helpers for enumeration wrappers: tool resolution, loot persistence,
and high-signal output parsing. Not a Module (no @register) — just utilities."""
from __future__ import annotations

import os
import re
from pathlib import Path
from shutil import which

from ...models import Finding


def heavy_enabled() -> bool:
    """Heavy wrappers (PEASS, SharpHound) only auto-fire when opted in, to keep
    the default `run` light and avoid MCP transport timeouts."""
    return os.environ.get("REAP_HEAVY", "").lower() in ("1", "true", "yes", "on")


def resolve_tool(candidates: list[str], env_var: str | None = None) -> str | None:
    """Find a tool binary on the *local* (operator/Kali) host. Honors an env
    override first, then explicit paths, then PATH. Returns None if absent."""
    if env_var:
        override = os.environ.get(env_var)
        if override and Path(override).exists():
            return override
    for cand in candidates:
        if "/" in cand or "\\" in cand:
            if Path(cand).exists():
                return cand
        else:
            found = which(cand)
            if found:
                return found
    return None


def loot_dir(host: str) -> Path:
    base = Path(os.environ.get("REAP_LOOT", "loot")) / (host or "unknown")
    base.mkdir(parents=True, exist_ok=True)
    return base


def save_text(host: str, name: str, text: str) -> Path:
    path = loot_dir(host) / name
    path.write_text(text, encoding="utf-8", errors="replace")
    return path


def save_bytes(host: str, name: str, data: bytes) -> Path:
    path = loot_dir(host) / name
    path.write_bytes(data)
    return path


def skip(tool: str, reason: str, module: str) -> list[Finding]:
    return [Finding(type="info", title=f"{tool} skipped", severity="low",
                    detail=reason, source_module=module)]


_SIGNALS = [
    ("sudo NOPASSWD entry", re.compile(r"NOPASSWD"), "high"),
    ("Linux capability +ep", re.compile(r"cap_[a-z_]+\+ep"), "medium"),
    ("Reference to a CVE", re.compile(r"CVE-\d{4}-\d{3,}"), "medium"),
    ("Possible privilege-escalation hint", re.compile(r"(?i)you can (?:read|write|exec|sudo)"), "medium"),
]


def signals(text: str, module: str, cap: int = 60) -> list[Finding]:
    """Pull high-signal misconfig lines out of verbose enumeration output. Full
    output is always saved to the loot dir; this just surfaces the loud bits."""
    out: list[Finding] = []
    for line in text.splitlines():
        for title, rx, sev in _SIGNALS:
            if rx.search(line):
                out.append(Finding(type="misconfig", title=title, severity=sev,
                                   detail=line.strip()[:200], source_module=module))
                break
        if len(out) >= cap:
            break
    return out
