"""Validated export syntax for supported Hashcat modes, without running a cracker.

Format reference: https://hashcat.net/wiki/doku.php?id=example_hashes
Ambiguous digests and legacy Mongo stored-key records are explicitly rejected.
"""
from __future__ import annotations

import base64
import re


def format_hash(credential):
    secret = (credential.get('secret') or '').strip()
    meta = credential.get('metadata') or {}
    kind = meta.get('hash_type', '')
    mode = str(meta.get('hashcat_mode') or '')
    user = credential.get('username') or ''
    if '\n' in secret or '\r' in secret:
        raise ValueError('multiline hash record')
    if kind == 'mysql_native' or mode == '300':
        value = secret.lstrip('*')
        if not re.fullmatch(r'[0-9a-fA-F]{40}', value):
            raise ValueError('invalid MySQL native hash')
        return '300', value, '40 hexadecimal characters; MySQL leading * removed'
    if kind == 'postgres_md5' or mode == '12':
        value = secret[3:] if secret.startswith('md5') else secret
        if not re.fullmatch(r'[0-9a-fA-F]{32}', value) or not user or any(c in user for c in ':\r\n'):
            raise ValueError('PostgreSQL MD5 requires a digest and a valid username salt')
        return '12', value + ':' + user, 'digest:username (username is the salt)'
    if kind == 'postgres_scram_sha256' or mode == '28600':
        match = re.fullmatch(r'SCRAM-SHA-256\$([1-9][0-9]*):([^$]+)\$([^:]+):(.+)', secret)
        if not match:
            raise ValueError('invalid PostgreSQL SCRAM format')
        try:
            salt, stored, server = [base64.b64decode(x, validate=True) for x in match.groups()[1:]]
            if not salt or len(stored) != 32 or len(server) != 32:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError('invalid PostgreSQL SCRAM key/salt encoding')
        return '28600', secret, 'native SCRAM verifier with salt, stored key and server key'
    if kind.startswith('mongodb_scram') or mode in ('24100', '24200'):
        match = re.fullmatch(r'\$mongodb-scram\$\*([01])\*([^*]+)\*([1-9][0-9]*)\*([^*]+)\*([^*]+)', secret)
        if not match:
            raise ValueError('legacy/invalid Mongo format; recollect serverKey using Reap 1.11+')
        mechanism, encoded_user, _, salt, server = match.groups()
        try:
            if not base64.b64decode(encoded_user, validate=True) or not base64.b64decode(salt, validate=True):
                raise ValueError()
            if len(base64.b64decode(server, validate=True)) != (32 if mechanism == '1' else 20):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError('invalid Mongo server key/salt encoding')
        return ('24200' if mechanism == '1' else '24100'), secret, 'base64 username, iteration count, salt and serverKey'
    if kind in ('mssql_2012', 'mssql_2005') or mode in ('1731', '132'):
        mode = '1731' if kind == 'mssql_2012' or mode == '1731' else '132'
        prefix, length = ('0x0200', 142) if mode == '1731' else ('0x0100', 54)
        if len(secret) != length or not secret.lower().startswith(prefix) or not re.fullmatch(r'0x[0-9a-fA-F]+', secret):
            raise ValueError('invalid MSSQL verifier length/prefix')
        return mode, secret, 'native hexadecimal SQL login verifier'
    if kind == 'ntlm' or mode == '1000':
        value = secret.rsplit(':', 1)[-1]
        if not re.fullmatch(r'[0-9a-fA-F]{32}', value):
            raise ValueError('invalid NTLM digest')
        return '1000', value, 'NT digest only; optional LM digest removed'
    patterns = {
        '3200': ('bcrypt', r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'),
        '1800': ('sha512crypt', r'\$6\$(?:rounds=[0-9]+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}'),
        '7400': ('sha256crypt', r'\$5\$(?:rounds=[0-9]+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}'),
        '500': ('md5crypt', r'\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}'),
    }
    for candidate, (label, pattern) in patterns.items():
        if kind == label or mode == candidate:
            if not re.fullmatch(pattern, secret):
                raise ValueError('invalid ' + label + ' verifier')
            return candidate, secret, 'native salted verifier'
    raise ValueError('unsupported or ambiguous hash type; no mode guessed')
