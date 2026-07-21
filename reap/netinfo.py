"""Robust local-listener enumeration — union of every source that can see a port.

`ss` and `netstat` are missing on plenty of real targets (minimal containers,
stripped images, distroless-ish boxes). reap used to rely on them alone, so on
such a box it saw *no* listening ports and a live service on `:3000` looked like
it didn't exist. This unions three sources and dedupes:

* ``ss -tlnpH`` / ``ss -ulnpH`` — richest (process names), when present;
* ``netstat -tlnp`` / ``netstat -ulnp`` — the older fallback;
* ``/proc/net/{tcp,tcp6,udp,udp6}`` — **always present on Linux, no binary and no
  root required** (it is the very table ss/netstat parse). This is the backstop:
  if a socket is listening, it is in here.

Each listener is ``{proto, port, kind, process, addr}`` where ``proto`` is the
transport (``tcp``/``udp``), ``kind`` is ``any``/``loopback``/``other`` (so the
console can flag loopback-only services that need a ``forward``), and ``addr`` is
a synthesized ``ip:port`` string kept compatible with the auto-forward check.
"""
from __future__ import annotations

import re

_PROC_FILES = ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")

# Single marker-delimited probe. No trailing newline (raw-shell adapter appends
# `; printf <sentinel>` and a trailing newline would break it).
LISTEN_PROBE = "\n".join([
    "echo '@@SSTCP@@'; ss -tlnpH 2>/dev/null",
    "echo '@@SSUDP@@'; ss -ulnpH 2>/dev/null",
    "echo '@@NET@@'; { netstat -tlnp 2>/dev/null; netstat -ulnp 2>/dev/null; }",
    "echo '@@PROC@@'; for f in " + " ".join(_PROC_FILES)
    + '; do echo "#$f"; cat "$f" 2>/dev/null; done',
    "echo '@@END@@'",
])

_PROC_NAME = re.compile(r'"([^"]+)"')          # ss users:(("node",pid=..))
_KIND_RANK = {"any": 0, "other": 1, "loopback": 2}   # most-reachable wins a merge


def _sections(text: str) -> dict:
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@@") and s.endswith("@@") and len(s) > 4:
            if cur is not None:
                out[cur] = "\n".join(buf)
            cur, buf = s.strip("@"), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf)
    return out


def _addr_kind(host: str) -> str:
    h = (host or "").strip("[]").lower()
    if h in ("0.0.0.0", "*", "::", ""):
        return "any"
    if h == "127.0.0.1" or h.startswith("127.") or h == "::1":
        return "loopback"
    return "other"


def _synth_addr(kind: str, port: int, ip: str = "") -> str:
    if ip and _addr_kind(ip) == "other":
        return f"{ip}:{port}"
    return {"any": "0.0.0.0", "loopback": "127.0.0.1"}.get(kind, "0.0.0.0") + f":{port}"


# -- ss / netstat -------------------------------------------------------------
def _parse_tool(block: str, proto: str) -> list:
    """Parse an ss/netstat block. ``proto`` is the known transport for ss blocks;
    for netstat it is read from the first column (self-describing)."""
    out = []
    for line in block.splitlines():
        toks = line.split()
        if not toks:
            continue
        p = proto
        if proto == "auto":                      # netstat: first col is tcp/tcp6/udp/udp6
            if not toks[0].startswith(("tcp", "udp")):
                continue
            p = "udp" if toks[0].startswith("udp") else "tcp"
        addr = next((t for t in toks
                     if ":" in t and t.rsplit(":", 1)[-1].isdigit()), None)
        if not addr:
            continue
        host, port = addr.rsplit(":", 1)
        m = _PROC_NAME.search(line)
        proc = m.group(1) if m else None
        if not proc:                             # netstat "1234/node"
            pm = re.search(r"\d+/(\S+)", line)
            proc = pm.group(1) if pm else None
        out.append({"proto": p, "port": int(port), "kind": _addr_kind(host),
                    "process": proc, "ip": host})
    return out


# -- /proc/net ----------------------------------------------------------------
_TCP_LISTEN = "0A"      # /proc/net/tcp st == LISTEN
_UDP_BOUND = ("07", "0A")


def _proc_ipv4(hexip: str) -> str:
    try:
        b = bytes.fromhex(hexip)
    except ValueError:
        return ""
    return ".".join(str(x) for x in reversed(b)) if len(b) == 4 else ""


def _proc_kind(hexip: str) -> str:
    h = hexip.upper()
    if len(h) == 8:                              # IPv4
        return {"00000000": "any", "0100007F": "loopback"}.get(h, "other")
    if set(h) == {"0"}:                          # IPv6 all-zero -> ::
        return "any"
    if h.endswith("01000000") and set(h[:-8]) == {"0"}:   # ::1
        return "loopback"
    return "other"


def _parse_proc(block: str) -> list:
    out, proto = [], None
    for line in block.splitlines():
        s = line.strip()
        if s.startswith("#/proc/net/"):
            proto = "udp" if "udp" in s else "tcp"
            continue
        toks = s.split()
        if len(toks) < 4 or toks[0] == "sl" or ":" not in toks[1]:
            continue
        st = toks[3].upper()
        if proto == "tcp" and st != _TCP_LISTEN:
            continue
        if proto == "udp" and st not in _UDP_BOUND:
            continue
        hexip, _, hexport = toks[1].partition(":")
        try:
            port = int(hexport, 16)
        except ValueError:
            continue
        if not port:
            continue
        out.append({"proto": proto, "port": port, "kind": _proc_kind(hexip),
                    "process": None, "ip": _proc_ipv4(hexip)})
    return out


def probe_listeners(session, timeout: int = 25) -> list:
    """Union all sources; return listeners sorted by (proto, port). Best-effort —
    a source that isn't installed simply contributes nothing."""
    raw = session.exec(LISTEN_PROBE, timeout=timeout).stdout
    sec = _sections(raw)
    rows = (_parse_tool(sec.get("SSTCP", ""), "tcp")
            + _parse_tool(sec.get("SSUDP", ""), "udp")
            + _parse_tool(sec.get("NET", ""), "auto")
            + _parse_proc(sec.get("PROC", "")))

    merged: dict = {}
    for r in rows:
        key = (r["proto"], r["port"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = r
            continue
        # Keep the most-reachable bind and the best process/ip we have seen.
        if _KIND_RANK[r["kind"]] < _KIND_RANK[cur["kind"]]:
            cur["kind"] = r["kind"]
        cur["process"] = cur["process"] or r["process"]
        if not cur.get("ip") and r.get("ip"):
            cur["ip"] = r["ip"]

    out = []
    for (proto, port), r in merged.items():
        out.append({
            "proto": proto, "port": port, "kind": r["kind"],
            "process": r["process"],
            "addr": _synth_addr(r["kind"], port, r.get("ip", "")),
        })
    out.sort(key=lambda d: (d["proto"], d["port"]))
    return out


def guess_service(port: int) -> str:
    """App-level guess for a port (http for 3000/8080, mysql for 3306, ...)."""
    from .patterns import proto_for_port
    return proto_for_port(port)


def format_listeners(listeners: list) -> list:
    """Plain aligned lines for the console/enum view."""
    if not listeners:
        return ["(no listening sockets found)"]
    lines = [f"{'PROTO':<5} {'PORT':>6}  {'BIND':<22} {'SERVICE':<8} PROCESS"]
    for lis in listeners:
        svc = guess_service(lis["port"])
        flag = "" if lis["kind"] == "any" else f"  [{lis['kind']}]"
        lines.append(f"{lis['proto']:<5} {lis['port']:>6}  {lis['addr']:<22} "
                     f"{svc:<8} {lis['process'] or '-'}{flag}")
    return lines
