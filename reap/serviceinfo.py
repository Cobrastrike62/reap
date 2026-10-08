"""Opt-in, bounded identification of already discovered TCP listeners."""
from __future__ import annotations

import base64
import json
import shlex

from .models import EnumFlag, EnumSection

# Runs on the target so loopback and private interface binds are reachable without
# scanning a different network or following redirects to another host.
_REMOTE = r'''
import hashlib, html, json, re, socket, ssl, sys, time
rows = json.loads(sys.argv[1])
deadline = time.monotonic() + 55
results = []
for row in rows:
    result = dict(row)
    if time.monotonic() >= deadline:
        result.update(status='partial', detail='overall 55-second budget reached')
        results.append(result)
        continue
    host = row['ip']
    if host in ('0.0.0.0', '*'): host = '127.0.0.1'
    if host == '::': host = '::1'
    port = row['port']
    errors = []
    for secure in ((True, False) if port in (443, 8443, 9443) else (False, True)):
        channel = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                errors.append('overall 55-second budget reached')
                break
            channel = socket.create_connection((host, port), timeout=min(2, remaining))
            channel.settimeout(max(0.01, min(2, deadline - time.monotonic())))
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                channel = context.wrap_socket(channel, server_hostname=host)
                result['tls'] = {'version': channel.version(),
                    'certificate_sha256': hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest(),
                    'identity_verified': False}
            if port in (21, 22, 25, 110, 143) and not secure:
                data = channel.recv(4096)
            else:
                authority = ('[%s]' % host if ':' in host else host) + ':' + str(port)
                request = 'GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Reap-survey\r\nConnection: close\r\n\r\n' % authority
                channel.sendall(request.encode('ascii'))
                data = bytearray()
                while len(data) < 65536:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        result['read_partial'] = True
                        break
                    channel.settimeout(min(2, remaining))
                    try:
                        part = channel.recv(min(4096, 65536 - len(data)))
                    except socket.timeout:
                        result['read_partial'] = True
                        break
                    if not part: break
                    data.extend(part)
                if len(data) == 65536: result['read_partial'] = True
            text = bytes(data).decode('utf-8', 'replace')
            if text.startswith('HTTP/'):
                headers, _, body = text.partition('\r\n\r\n')
                fields = {}
                for line in headers.splitlines()[1:]:
                    key, sep, value = line.partition(':')
                    if sep: fields[key.lower()] = value.strip()
                title = re.search(r'<title\b[^>]*>(.*?)</title>', body, re.I | re.S)
                result.update(status='completed', protocol='https' if secure else 'http',
                    http_status=headers.splitlines()[0][:256], server=fields.get('server', '')[:256],
                    redirect=fields.get('location', '')[:1024],
                    title=html.unescape(re.sub(r'\s+', ' ', title.group(1))).strip()[:512] if title else '')
                break
            if text.strip():
                result.update(status='completed', protocol='banner', banner=text.splitlines()[0][:512])
                break
            errors.append('no response over ' + ('TLS' if secure else 'plain TCP'))
        except (OSError, ValueError) as exc:
            errors.append(('TLS: ' if secure else 'TCP: ') + str(exc))
        finally:
            if channel: channel.close()
    if 'status' not in result: result.update(status='partial', detail='; '.join(errors))
    results.append(result)
print(json.dumps(results))
'''


def identify_services(session, listeners, limit=12):
    candidates = [dict(row) for row in listeners if row['proto'] == 'tcp']
    selected = candidates[:max(1, min(limit, 24))]
    checks = []
    if not selected:
        return EnumSection('Service identification', ['No discovered TCP listeners to probe.'])
    code = base64.b64encode(_REMOTE.encode()).decode()
    command = ('reap_python="$(command -v python3 || command -v python)"; '
               '[ -n "$reap_python" ] || { echo "Python unavailable for service identification" >&2; exit 127; }; '
               '"$reap_python" -c ' + shlex.quote('import base64; exec(base64.b64decode(%r))' % code)
               + ' ' + shlex.quote(json.dumps(selected)))
    result = session.exec(command, timeout=65)
    try:
        rows = json.loads(result.stdout)
        if not isinstance(rows, list):
            raise ValueError('invalid response')
    except (ValueError, TypeError):
        rows = []
        checks.append({'name': 'service identification', 'status': 'tool unavailable' if result.exit_code == 127 else 'partial',
                       'detail': result.stderr or 'response incomplete'})
    lines, flags = [], []
    for row in rows:
        checks.append({'name': row['addr'], 'status': row['status'],
                       'detail': row.get('detail', '') or ('64 KiB/read-time cap reached' if row.get('read_partial') else '')})
        if row.get('read_partial'):
            checks[-1]['status'] = 'partial'
        evidence = row['addr'] + ' ' + json.dumps({k: row[k] for k in (
            'protocol', 'http_status', 'server', 'title', 'redirect', 'tls', 'banner', 'detail') if k in row}, ensure_ascii=False)
        lines.append(evidence)
        if row.get('protocol') in ('http', 'https') and row['port'] not in (80, 443):
            flags.append(EnumFlag(row['addr'] + ' serves ' + row['protocol'].upper(),
                                  'An HTTP response was observed on an alternate port.', 'notice',
                                  'observed', [evidence],
                                  'Inspect the application through this session or forward its actual bind address.'))
    if len(candidates) > len(selected):
        checks.append({'name': 'service identification limit', 'status': 'partial',
                       'detail': '%s of %s TCP endpoints selected' % (len(selected), len(candidates))})
    return EnumSection('Service identification', lines,
                       'Opt-in TCP requests; at most 12 endpoints, 64 KiB each, 55 seconds total. Redirects are recorded, not followed.',
                       flags, checks)
