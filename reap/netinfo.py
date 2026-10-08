"""Local socket discovery with per-source coverage and distinct bind addresses."""
from __future__ import annotations

import ipaddress
import re

from .modules._probe import sections

_PROC_FILES = ('tcp', 'tcp6', 'udp', 'udp6')
_TOOL_COMMANDS = {'SSTCP': 'ss -4 -tlnpH', 'SSTCP6': 'ss -6 -tlnpH',
                  'SSUDP': 'ss -4 -ulnpH', 'SSUDP6': 'ss -6 -ulnpH',
                  'NETTCP': 'netstat -tlnp', 'NETUDP': 'netstat -ulnp'}
_probe_lines = ['reap_checks=""']
for _name, _command in _TOOL_COMMANDS.items():
    _probe_lines += ["echo '@@%s@@'" % _name,
                    '%s 2>&1; reap_rc=$?' % _command,
                    'reap_checks="${reap_checks}%s|$reap_rc\n"' % _name]
_probe_lines += ["echo '@@PROC@@'"]
for _file in _PROC_FILES:
    _probe_lines += ['echo "#/proc/net/%s"; cat /proc/net/%s 2>&1; reap_rc=$?' % (_file, _file),
                    'reap_checks="${reap_checks}PROC_%s|$reap_rc\n"' % _file]
_probe_lines += ["echo '@@BYTEORDER@@'; printf '\\001\\000' | od -An -tu2 2>/dev/null"]
_probe_lines += ["echo '@@CHECKS@@'; printf '%s' \"$reap_checks\"", "echo '@@END@@'"]
LISTEN_PROBE = '\n'.join(_probe_lines)
_PROC_NAME = re.compile(r'"([^"]+)"')


class ListenerList(list):
    """List-compatible discovery result. Empty plus failed coverage is not absence."""
    def __init__(self, rows=(), checks=()):
        super().__init__(rows)
        self.checks = list(checks)

    @property
    def complete(self):
        done = {c['name'] for c in self.checks if c['status'] == 'completed'}
        covered = all(tool in done or proc in done for tool, proc in (
            ('SSTCP', 'PROC_tcp'), ('SSTCP6', 'PROC_tcp6'),
            ('SSUDP', 'PROC_udp'), ('SSUDP6', 'PROC_udp6')))
        return covered and not any(c['status'] == 'timed out' for c in self.checks)


def _addr_kind(host):
    h = (host or '').strip('[]').split('%', 1)[0]
    if h in ('0.0.0.0', '*', '::', ''):
        return 'any'
    try:
        return 'loopback' if ipaddress.ip_address(h).is_loopback else 'other'
    except ValueError:
        return 'other'


def _endpoint(proto, host, port, process=None, pid=None, family=None):
    host = host.strip('[]')
    family = 'ipv6' if ':' in host else (family or 'ipv4')
    if host == '*':
        host = '::' if family == 'ipv6' else '0.0.0.0'
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    addr = '[%s]:%s' % (host, port) if family == 'ipv6' else '%s:%s' % (host, port)
    return {'proto': proto, 'port': int(port), 'kind': _addr_kind(host),
            'process': process, 'pid': pid, 'ip': host, 'family': family, 'addr': addr}


def _parse_tool(block, proto, address_family=None):
    rows = []
    for line in block.splitlines():
        toks = line.split()
        if not toks:
            continue
        p, family = proto, address_family
        if proto == 'auto':
            if toks[0] not in ('tcp', 'tcp6', 'udp', 'udp6'):
                continue
            p = 'udp' if toks[0].startswith('udp') else 'tcp'
            family = 'ipv6' if toks[0].endswith('6') else 'ipv4'
        addr = next((t for t in toks if ':' in t and t.rsplit(':', 1)[-1].isdigit()), None)
        if not addr:
            continue
        host, port = addr.rsplit(':', 1)
        pm, pidm = _PROC_NAME.search(line), re.search(r'pid=(\d+)', line)
        proc, pid = pm.group(1) if pm else None, pidm.group(1) if pidm else None
        old = re.search(r'(\d+)/(\S+)', line)
        if old and not proc:
            pid, proc = old.groups()
        rows.append(_endpoint(p, host, port, proc, pid, family))
    return rows


def _proc_ip(hexip, byteorder='little'):
    raw = bytes.fromhex(hexip)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1] if byteorder == 'little' else raw))
    if len(raw) == 16:
        # procfs encodes each IPv6 32-bit word in the target's native byte order.
        if byteorder == 'little':
            raw = b''.join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        return str(ipaddress.IPv6Address(raw))
    raise ValueError('unexpected procfs address length')


def _parse_proc(block, byteorder='little'):
    rows, proto, family = [], None, None
    for line in block.splitlines():
        s = line.strip()
        if s.startswith('#/proc/net/'):
            name = s.rsplit('/', 1)[-1]
            proto = 'udp' if name.startswith('udp') else 'tcp'
            family = 'ipv6' if name.endswith('6') else 'ipv4'
            continue
        toks = s.split()
        if proto is None or len(toks) < 4 or not toks[0].endswith(':'):
            continue
        if toks[3].upper() not in (('0A',) if proto == 'tcp' else ('07', '0A')):
            continue
        try:
            hexip, hexport = toks[1].split(':', 1)
            port = int(hexport, 16)
            if port:
                rows.append(_endpoint(proto, _proc_ip(hexip, byteorder), port, family=family))
        except (ValueError, IndexError):
            continue
    return rows


def probe_listeners(session, timeout=25):
    result = session.exec(LISTEN_PROBE, timeout=timeout)
    sec = sections(result.stdout)
    checks = []
    for line in sec.get('CHECKS', '').splitlines():
        name, _, rc = line.partition('|')
        if not rc.isdigit():
            continue
        status = 'completed' if rc == '0' else ('tool unavailable' if rc == '127' else 'permission denied / unavailable')
        checks.append({'name': name, 'status': status, 'detail': 'exit ' + rc})
    if result.exit_code != 0 or '@@END@@' not in result.stdout:
        checks.append({'name': 'listener probe', 'status': 'timed out' if result.exit_code == 124 else 'partial',
                       'detail': result.stderr or 'end marker missing'})
    if not checks:
        checks.append({'name': 'listener probe', 'status': 'partial', 'detail': 'source coverage not supplied'})
    if sec.get('PROC', '').strip() and sec.get('BYTEORDER', '').strip() not in ('1', '256'):
        checks.append({'name': 'procfs byte order', 'status': 'partial',
                       'detail': 'Target byte-order check unavailable; little-endian decoding assumed.'})
    rows = (_parse_tool(sec.get('SSTCP', ''), 'tcp', 'ipv4') + _parse_tool(sec.get('SSTCP6', ''), 'tcp', 'ipv6')
            + _parse_tool(sec.get('SSUDP', ''), 'udp', 'ipv4') + _parse_tool(sec.get('SSUDP6', ''), 'udp', 'ipv6')
            + _parse_tool(sec.get('NETTCP', '') + '\n' + sec.get('NETUDP', '') + '\n' + sec.get('NET', ''), 'auto')
            + _parse_proc(sec.get('PROC', ''), 'big' if sec.get('BYTEORDER', '').strip() == '256' else 'little'))
    merged = {}
    for row in rows:
        key = (row['proto'], row['family'], row['ip'], row['port'])
        if key in merged:
            merged[key]['process'] = merged[key]['process'] or row['process']
            merged[key]['pid'] = merged[key]['pid'] or row['pid']
        else:
            merged[key] = row
    return ListenerList(sorted(merged.values(), key=lambda d: (d['proto'], d['port'], d['family'], d['ip'])), checks)


def guess_service(port):
    from .patterns import proto_for_port
    return proto_for_port(port)


def format_listeners(listeners):
    if not listeners:
        return ['(no sockets observed; consult source coverage before assuming absence)']
    lines = ['PROTO FAMILY PORT   BIND                         SERVICE  PROCESS (PID)']
    for lis in listeners:
        lines.append('%-5s %-6s %-6s %-28s %-8s %s (%s)%s' % (
            lis['proto'], lis.get('family', '?'), lis['port'], lis['addr'], guess_service(lis['port']),
            lis['process'] or '-', lis.get('pid') or '-', ' [loopback]' if lis['kind'] == 'loopback' else ''))
    return lines
