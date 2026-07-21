"""reap — post-exploitation loot framework for sanctioned CTF/lab targets.

The operator gains the foothold by hand; reap runs *after* a session exists:
it collects loot, correlates discovered credentials against discovered
services, and surfaces a ranked findings list. It does not exploit, gain
access, or make pivot decisions.
"""
import logging as _logging

# Silence paramiko's noisy background-thread logging — e.g. "Error reading SSH
# protocol banner" tracebacks when correlation probes a port that accepts TCP
# but does not speak SSH. reap already catches these; this just keeps the
# console clean during credential-reuse testing.
for _n in ("paramiko", "paramiko.transport"):
    _logging.getLogger(_n).setLevel(_logging.CRITICAL)

__version__ = "1.7.0"
__all__ = ["__version__"]
