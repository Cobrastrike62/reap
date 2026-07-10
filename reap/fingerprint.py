"""Fingerprint — a cheap probe returning a Context that gates module selection.

Heuristic and fast: a few commands, seconds, not a scan. CONSTRAINT: ambiguity
broadens — if two runtimes are plausible, set both and let both module sets fire.
A missed `.env` costs more than a module that returns nothing.
"""
from __future__ import annotations

from .models import Context
from .transport.base import Session

_SERVICE_ACCTS = {
    "www-data", "mysql", "postgres", "redis", "nobody", "daemon",
    "apache", "nginx", "mongodb", "tomcat", "node",
}

# One round-trip on Linux: emit marker-delimited sections, parse below.
_LINUX_PROBE = r"""
echo '@@OS@@'; uname -srm 2>/dev/null
echo '@@USER@@'; id -un 2>/dev/null; id -u 2>/dev/null
echo '@@SHELL@@'; getent passwd "$(id -un 2>/dev/null)" 2>/dev/null | awk -F: '{print $7}'
echo '@@DOCKER@@'; { test -f /.dockerenv && echo dockerenv; }; cat /proc/1/cgroup 2>/dev/null | tr '\n' ' '
echo '@@OSREL@@'; cat /etc/os-release 2>/dev/null | tr '\n' ' '
echo '@@LS@@'; ls --help 2>&1 | head -n1; readlink -f "$(command -v ls 2>/dev/null)" 2>/dev/null
echo '@@HAVE@@'; for b in python3 python script node php java dotnet ruby perl; do command -v "$b" >/dev/null 2>&1 && echo "$b"; done
echo '@@PROCS@@'; { ps -eo comm 2>/dev/null || ps -A 2>/dev/null; } | tr '\n' ' '
echo '@@PORTS@@'; { ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null; } | tr -s ' ' | cut -d' ' -f4 | tr '\n' ' '
echo '@@END@@'
"""


def fingerprint(session: Session) -> Context:
    """Probe a freshly-registered session. Re-run on every new session.

    A failed/timed-out probe must never silently narrow the OS to 'unknown'
    (which would disable every Linux collector). Ambiguity broadens.
    """
    ctx = Context()
    head = session.exec("uname -s", timeout=15)
    if head.exit_code == 124:  # transient timeout — retry once, larger window
        head = session.exec("uname -s", timeout=45)
    if head.ok and "linux" in head.out.lower():
        return _linux(session, ctx)

    whoami = session.exec("whoami", timeout=15)
    ver = session.exec("ver", timeout=10)
    if "\\" in whoami.out or "windows" in (ver.out + whoami.out).lower():
        return _windows(session, ctx)

    # Still undetermined. Run the full Linux probe and promote to Linux only on
    # positive evidence (Linux uname marker or a numeric uid) rather than
    # giving up — a slow first `uname -s` shouldn't cost us the Linux modules.
    probe = _linux(session, ctx, confirmed=False)
    if probe.os == "linux":
        return probe
    ctx.os = "unknown"
    return ctx


def _sections(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    cur: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@@") and s.endswith("@@"):
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur, buf = s.strip("@"), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


def _linux(session: Session, ctx: Context, confirmed: bool = True) -> Context:
    raw = session.exec(_LINUX_PROBE, timeout=30).stdout
    if "@@END@@" not in raw:  # truncated (slow/lossy channel) — retry once larger
        raw = session.exec(_LINUX_PROBE, timeout=60).stdout
        if "@@END@@" not in raw:
            ctx.fingerprint_complete = False
    sec = _sections(raw)

    user_fields = sec.get("USER", "").split()
    username = user_fields[0] if user_fields else ""
    uid = user_fields[1] if len(user_fields) > 1 else ""

    # When called speculatively (uname was inconclusive), only claim Linux with
    # positive evidence; otherwise leave os as-is so the caller can fall through.
    if not confirmed and "linux" not in sec.get("OS", "").lower() and not uid.isdigit():
        return ctx
    ctx.os = "linux"
    ctx.shell = sec.get("SHELL", "").strip()

    if uid == "0":
        ctx.privilege = "root"
    elif username in _SERVICE_ACCTS or ctx.shell.endswith(("nologin", "false")):
        ctx.privilege = "service"
    elif username:
        ctx.privilege = "user"

    docker = sec.get("DOCKER", "").lower()
    if any(m in docker for m in ("dockerenv", "docker", "lxc", "kubepods", "containerd")):
        ctx.is_container = True

    osrel = sec.get("OSREL", "").lower()
    ls = sec.get("LS", "").lower()
    have = {h.lower() for h in sec.get("HAVE", "").split()}
    alpine = "alpine" in osrel
    busybox = "busybox" in ls
    has_python = bool({"python3", "python"} & have)
    has_script = "script" in have
    ctx.minimal_userland = (busybox or alpine) and not has_python and not has_script

    ctx.runtime = _detect_runtimes(have, sec.get("PROCS", ""), sec.get("PORTS", ""))
    return ctx


def _detect_runtimes(have: set[str], procs: str, ports: str) -> list[str]:
    rt: set[str] = set()
    p = procs.lower()

    def proc(*names: str) -> bool:
        return any(n in p for n in names)

    if "node" in have or proc("node"):
        rt.add("node")
    if {"python3", "python"} & have or proc("python"):
        rt.add("python")
    if "php" in have or proc("php", "php-fpm", "apache2", "httpd"):
        rt.add("php")
    if "java" in have or proc("java"):
        rt.add("java")
    if "dotnet" in have or proc("dotnet"):
        rt.add("dotnet")
    if "ruby" in have or proc("ruby"):
        rt.add("ruby")
    if proc("mysqld", "mariadb") or ":3306" in ports:
        rt.add("mysql")
    if proc("postgres") or ":5432" in ports:
        rt.add("postgres")
    if proc("mongod") or ":27017" in ports:
        rt.add("mongodb")
    if proc("redis") or ":6379" in ports:
        rt.add("redis")
    return sorted(rt)


def _windows(session: Session, ctx: Context) -> Context:
    ctx.os = "windows"
    ctx.shell = "cmd"
    who = session.exec("whoami").out.lower()
    if "nt authority\\system" in who:
        ctx.privilege = "system"
    elif "nt service" in who or "iis apppool" in who:
        ctx.privilege = "service"
    elif who:
        ctx.privilege = "user"

    # wmic is deprecated/removed on modern Windows — prefer PowerShell/CIM.
    ps = session.exec(
        'powershell -nop -c "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"'
    ).out.strip().lower()
    if ps in ("true", "false"):
        ctx.domain_joined = ps == "true"
    else:
        dom = session.exec(
            "wmic computersystem get domain,partofdomain /format:list").out.lower()
        ctx.domain_joined = "partofdomain=true" in dom.replace(" ", "")

    tasks = session.exec("tasklist /fo csv /nh").out.lower()
    rt: set[str] = set()
    if "node.exe" in tasks:
        rt.add("node")
    if "python" in tasks:
        rt.add("python")
    if "w3wp.exe" in tasks or "dotnet" in tasks:
        rt.add("dotnet")
    if "java.exe" in tasks:
        rt.add("java")
    if "php" in tasks:
        rt.add("php")
    if "sqlservr.exe" in tasks:
        rt.add("mssql")
    if "mysqld" in tasks:
        rt.add("mysql")
    ctx.runtime = sorted(rt)
    return ctx
