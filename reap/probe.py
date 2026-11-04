"""Transport-independent validation for the optional bounded TCP probe operation."""
from __future__ import annotations

import ipaddress
import math
import re

PROBE_CAPABILITY = 'probe_tcp_v1'
PROBE_LIMIT = 24
_STRINGS = {'protocol': 16, 'http_status': 256, 'server': 256, 'title': 512,
            'redirect': 1024, 'banner': 512, 'detail': 4096}


def probe_endpoints(endpoints):
    """Accept discovered IP endpoints only; never resolve names or expand a range."""
    if not isinstance(endpoints, (list, tuple)) or len(endpoints) > PROBE_LIMIT:
        raise ValueError('probe requires a list of at most 24 TCP endpoints')
    selected = []
    for row in endpoints:
        if (not isinstance(row, dict) or row.get('proto') != 'tcp'
                or not isinstance(row.get('ip'), str)
                or type(row.get('port')) is not int or not 1 <= row['port'] <= 65535):
            raise ValueError('invalid TCP probe endpoint')
        ip = row['ip']
        if ip == '*':
            ip = '::' if row.get('family') == 'ipv6' else '0.0.0.0'
        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError('probe endpoint must use an IPv4 or IPv6 literal') from exc
        if '%' in ip:
            zone = ip.split('%', 1)[1]
            if address.version != 6 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', zone):
                raise ValueError('invalid IPv6 probe scope zone')
        family = 'ipv6' if address.version == 6 else 'ipv4'
        if row.get('family', family) != family:
            raise ValueError('probe endpoint address family mismatch')
        addr = ('[%s]:%s' if address.version == 6 else '%s:%s') % (ip, row['port'])
        if row.get('addr', addr) != addr and row['ip'] != '*':
            raise ValueError('probe endpoint address does not match its IP and port')
        selected.append({'proto': 'tcp', 'ip': ip, 'port': row['port'], 'addr': addr})
    return selected


def finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def valid_text(value, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def probe_rows(rows, endpoints):
    """Validate a complete response so an empty result cannot imply absence."""
    expected = probe_endpoints(endpoints)
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError('probe response must include every selected endpoint')
    for row, endpoint in zip(rows, expected):
        if (not isinstance(row, dict)
                or any(row.get(key) != value or type(row.get(key)) is not type(value)
                       for key, value in endpoint.items())):
            raise ValueError('probe response endpoint mismatch')
        if row.get('status') not in ('completed', 'partial', 'timed out', 'tool unavailable'):
            raise ValueError('invalid probe response status')
        for key, size in _STRINGS.items():
            if key in row and not valid_text(row[key], size):
                raise ValueError('invalid probe evidence field: ' + key)
        if 'read_partial' in row and type(row['read_partial']) is not bool:
            raise ValueError('invalid probe read_partial field')
        if 'protocol' in row and row['protocol'] not in ('http', 'https', 'banner', 'tls'):
            raise ValueError('invalid observed probe protocol')
        if 'tls' in row:
            tls = row['tls']
            if (not isinstance(tls, dict)
                    or set(tls) != {'version', 'identity_verified', 'certificate_sha256'}
                    or not valid_text(tls.get('version'), 64) or not tls['version']
                    or tls.get('identity_verified') is not False
                    or not isinstance(tls.get('certificate_sha256'), str)
                    or not re.fullmatch(r'[0-9a-fA-F]{64}', tls['certificate_sha256'])):
                raise ValueError('invalid TLS observation metadata')
        if row['status'] == 'completed' and not row.get('protocol'):
            raise ValueError('completed probe response lacks observed evidence')
        if row.get('protocol') in ('http', 'https'):
            if not re.fullmatch(r'HTTP/[0-9]+\.[0-9]+ [1-5][0-9]{2}(?:[ \t].*)?', row.get('http_status', '')):
                raise ValueError('HTTP probe response lacks a valid status line')
            if row['protocol'] == 'https' and 'tls' not in row:
                raise ValueError('HTTPS probe response lacks TLS observation metadata')
        elif row.get('protocol') == 'banner' and not row.get('banner', '').strip():
            raise ValueError('banner probe response lacks observed banner text')
        elif row.get('protocol') == 'tls' and 'tls' not in row:
            raise ValueError('TLS probe response lacks TLS observation metadata')
    return rows
