"""Config-file harvester: the secrets that live specifically in config
files, regardless of which framework wrote them.

Shares the single cached grep pass with secret_scanner (_scan_cache) so the tree
is walked once, then filters to config-shaped paths — a focused view of the same
data. Overlap with secret_scanner is de-duplicated by the store on ingest.
"""
from __future__ import annotations

from ...patterns import DEFAULT_DIRS, scan_line
from ..base import Module, register
from ._scan_cache import grep_pass

_CONFIG_EXT = (".env", ".json", ".yml", ".yaml", ".xml", ".ini", ".conf",
               ".config", ".properties", ".toml")


@register
class ConfigHarvester(Module):
    name = "config_harvester"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown")

    def collect(self, session):
        findings = []
        for path, lineno, content in grep_pass(session, DEFAULT_DIRS):
            low = path.lower()
            if not (low.endswith(_CONFIG_EXT) or "/.env" in low or low.endswith(".env")):
                continue
            findings.extend(scan_line(content, f"{path}:{lineno}"))
        for f in findings:
            f.source_module = self.name
        return findings
