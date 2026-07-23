"""Shared triage heuristics for the enum surveyors — deciding what stands out.

`enum` used to be a raw dump; these helpers let each surveyor flag the handful of
things an operator actually cares about, with a one-line reason:

* **software that isn't part of the base system** — anything running / referenced
  out of ``/opt``, ``/home``, ``/srv``, ``/usr/local`` ... rather than the distro's
  ``/usr``,``/bin``,``/sbin``,``/lib``. This one heuristic surfaces the target app,
  operator-installed daemons, custom cron/service scripts, and dropped payloads;
* **operator / attacker tools** running as processes (nc, socat, tmux, tcpdump...);
* **known-vulnerable versions** (sudo local-root CVEs).

Matched as a *positive* "interesting" list so ``/usr/local`` is caught without
having to exclude all of ``/usr``.
"""
from __future__ import annotations

import re

# Roots where operator/app/attacker files live (system files live elsewhere).
INTERESTING_ROOTS = ("/home/", "/root/", "/opt/", "/srv/", "/tmp/", "/var/tmp/",
                     "/dev/shm/", "/var/www", "/usr/local/", "/app/", "/data/")

_PATH = re.compile(r"/[^\s,;:'\"()]+")

# Programs whose presence as a live process / cron / service is worth noting.
_TOOL_BINS = {"nc", "ncat", "netcat", "socat", "screen", "tmux", "tcpdump",
              "gdb", "strace", "ltrace", "lxc", "lxd", "runc", "chisel", "ligolo",
              "frpc", "frps"}
_APP_BINS = {"python", "perl", "ruby", "php", "php-fpm", "node", "nodejs", "java",
             "gunicorn", "uwsgi", "puma", "flask", "rails", "streamlit", "deno"}


def interesting_path(text: str):
    """First absolute path in `text` living outside the base system, else None."""
    for m in _PATH.finditer(text or ""):
        if m.group(0).startswith(INTERESTING_ROOTS):
            return m.group(0)
    return None


def interesting_bin(argv0: str):
    """Classify a program name → ('tool'|'app', name), else None. Tolerates a
    version suffix (python3.11) and an absolute path."""
    base = (argv0 or "").strip().split()[0].rsplit("/", 1)[-1] if argv0 else ""
    b = base.lower()
    stripped = re.sub(r"[0-9.]+$", "", b) or b
    if b in _TOOL_BINS or stripped in _TOOL_BINS:
        return ("tool", base)
    if b in _APP_BINS or stripped in _APP_BINS:
        return ("app", base)
    return None


# Unix groups that hand you (a path to) root. (level, why).
DANGEROUS_GROUPS = {
    "docker": ("alert", "docker group → mount the host fs as root via a container"),
    "lxd":    ("alert", "lxd group → root via a privileged container"),
    "lxc":    ("alert", "lxc group → root via a container"),
    "disk":   ("alert", "disk group → raw block access; read or patch /etc/shadow"),
    "shadow": ("alert", "shadow group → read /etc/shadow and crack the hashes"),
    "sudo":   ("notice", "sudo group → you can run sudo (check 'sudo -l')"),
    "wheel":  ("notice", "wheel group → you can run sudo (check 'sudo -l')"),
    "adm":    ("notice", "adm group → read system logs (creds/tokens leak there)"),
    "video":  ("notice", "video group → read the framebuffer / screen contents"),
}

# Root-owned files whose writability is an instant win — name them loudly.
CRITICAL_FILES = {"passwd", "shadow", "gshadow", "sudoers", "master.passwd"}


def critical_file(path: str):
    """Return a loud reason if `path` is a security-critical file, else None."""
    base = (path or "").rstrip("/").rsplit("/", 1)[-1]
    if base in CRITICAL_FILES or "/sudoers.d/" in (path or ""):
        return f"writable {base or path} — edit it for instant root"
    return None


def sudo_vuln(version_line: str):
    """CVE note if the sudo version string looks vulnerable to a big local-root
    bug, else None. Deliberately conservative."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:p(\d+))?", version_line or "")
    if not m:
        return None
    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))
    notes = []
    if ver < (1, 9, 5, 2):
        notes.append("CVE-2021-3156 'Baron Samedit' heap overflow → root")
    if ver[:3] < (1, 8, 28):
        notes.append("CVE-2019-14287 'sudo -u#-1' → root")
    return "; ".join(notes) or None
