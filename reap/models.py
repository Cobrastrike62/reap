"""Shared, transport-agnostic data types.

These are the structures that flow *up* the stack: fingerprint produces a
``Context``; modules emit ``Finding`` objects (which may carry a ``Credential``
and/or ``Service``); the loot store routes them into normalized tables.

Kept free of any transport/store imports so every layer can depend on it
without cycles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Context:
    """Cheap, heuristic facts about a session that gate module selection."""

    os: str = "unknown"            # "linux" | "windows" | "unknown"
    privilege: str = "unknown"     # "root" | "system" | "user" | "service" | "unknown"
    runtime: list[str] = field(default_factory=list)  # e.g. ["node"], ["python","mysql"]
    is_container: bool = False
    minimal_userland: bool = False  # busybox/alpine — routes stabilization
    domain_joined: bool = False
    shell: str = ""
    fingerprint_complete: bool = True  # False when the probe was truncated

    def has_runtime(self, name: str) -> bool:
        return name.lower() in {r.lower() for r in self.runtime}


@dataclass
class Credential:
    """A piece of secret material. ``kind`` mirrors ``credentials.kind`` in the store.

    ``capability`` is first-class: not a password to spray but a key that
    unlocks an action (e.g. a JWT signing secret). The unlock action lives in
    ``metadata`` and is surfaced — never auto-exploited — by the engine.
    """

    kind: str                       # 'password'|'hash'|'ssh_key'|'token'|'capability'
    secret: str
    username: Optional[str] = None
    source: Optional[str] = None    # file path, env, or module name
    metadata: dict = field(default_factory=dict)


@dataclass
class Service:
    """A network service worth correlating credentials against.

    ``host`` is the address the service actually lives on. It is usually the
    foothold, but for a service parsed out of a connection string
    (``mysql://user:pw@db01:3306``) it is the *remote* DB host — carrying it
    here lets correlation test the cred against ``db01``, not the foothold IP.
    """

    proto: str                      # ssh, mysql, mongodb, postgres, http, winrm, ...
    port: Optional[int] = None
    product: Optional[str] = None
    notes: Optional[str] = None
    host: Optional[str] = None      # remote host (e.g. from a conn string); None = foothold


@dataclass
class Finding:
    """The unit modules emit. Always becomes a row in ``findings``; if it carries
    a ``credential``/``service`` those are also routed to their tables."""

    type: str                       # 'credential'|'capability'|'misconfig'|'info'
    title: str
    severity: str = "low"           # 'high'|'medium'|'low' — drives ranking
    detail: str = ""
    source_module: str = ""
    credential: Optional[Credential] = None
    service: Optional[Service] = None


@dataclass
class EnumFlag:
    """Something inside an enum section that stands out, with a reason.

    This is the triage layer over the raw dump: the ``enum`` view renders flags
    prominently (in colour) above the full listing and aggregates them into a
    summary, so the operator sees *what to look at* rather than only *everything*.
    """

    text: str                       # the item (a process / cron / service / port line)
    reason: str                     # why it's worth a look
    level: str = "notice"           # "alert" (red, likely important) | "notice" (yellow)


@dataclass
class EnumSection:
    """A block of situational-awareness output for the console ``enum`` view
    (linpeas-style: processes, services, crons, network, kernel).

    Screen-only and high-volume by nature — it is *not* persisted. A module still
    routes the actionable subset (secrets in a command line, a writable service /
    cron target) into the loot store as ranked ``Finding`` objects via ``collect``;
    ``enumerate`` is only the human-readable dump.

    ``flags`` is the triage layer: items in this section that stand out, surfaced
    above the raw ``lines`` and rolled up into the end-of-``enum`` summary.
    """

    title: str
    lines: list[str] = field(default_factory=list)
    hint: str = ""                  # one line on why it matters / what to check
    flags: list["EnumFlag"] = field(default_factory=list)
