"""reap — post-exploitation loot framework for sanctioned CTF/lab targets.

The operator gains the foothold by hand; reap runs *after* a session exists:
it collects loot, correlates discovered credentials against discovered
services, and surfaces a ranked findings list. It does not exploit, gain
access, or make pivot decisions.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
