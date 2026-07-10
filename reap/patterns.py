"""Language-agnostic secret shapes + the parser that turns a matched line into
structured Findings. Shared by the secret scanner, config harvester,
known-filename collector, env dumper, and runtime plugins.

The design idea: detect by *shape*, not by framework. A connection string is
parsed into BOTH a Credential and a Service so the correlation engine can later
test cred-against-service reuse.
"""
from __future__ import annotations

import re

from .models import Credential, Finding, Service

# --- port/proto maps ---------------------------------------------------------
PORT_PROTO = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 1433: "mssql",
    3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http", 5432: "postgres",
    5985: "winrm", 5986: "winrm", 6379: "redis", 8000: "http", 8080: "http",
    8443: "https", 9200: "http", 27017: "mongodb",
}
PROTO_PORT = {
    "ssh": 22, "ftp": 21, "mysql": 3306, "postgres": 5432, "mongodb": 27017,
    "redis": 6379, "mssql": 1433, "winrm": 5985, "http": 80, "https": 443,
    "smb": 445, "ldap": 389,
}

# --- regexes -----------------------------------------------------------------
CONN_STRING = re.compile(
    r'(?P<scheme>jdbc:[a-z0-9]+|mongodb\+srv|mongodb|postgresql|postgres|mysql|'
    r'mariadb|redis|amqp|mssql|sqlserver|ftp|sftp)://'
    r'(?:(?P<user>[^:/@\s]+)(?::(?P<pw>[^@/\s]+))?@)?'
    r'(?P<host>[A-Za-z0-9_.\-]+)'
    r'(?::(?P<port>\d+))?'
    r'(?:/(?P<db>[^\s"\'?#]+))?',
    re.IGNORECASE,
)
HTTP_CREDS = re.compile(
    r'https?://(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+)@(?P<host>[A-Za-z0-9_.\-]+)',
    re.IGNORECASE,
)
AWS_ACCESS_KEY = re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b')
ASSIGNMENT = re.compile(
    r'(?P<key>[A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|APIKEY|API_KEY|'
    r'ACCESS_KEY|PRIVATE_KEY|JWT|AUTH_?TOKEN)[A-Za-z0-9_]*)'
    r'\s*[=:]\s*'
    r'(?P<q>["\']?)(?P<val>[^\s"\']{3,256})(?P=q)',
    re.IGNORECASE,
)
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')

# Single broad ERE handed to `grep -iE` on the target to find candidate lines
# cheaply; precise classification happens locally via scan_line().
GREP_ALTERNATION = (
    r'(mongodb|postgres|postgresql|mysql|mariadb|redis|amqp|mssql|jdbc):|'
    r'://[a-z0-9_.\-]+:[^@[:space:]]+@|'
    r'(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|jwt|auth_?token)[[:space:]]*[=:]|'
    r'AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY'
)

# Directories the broad scanners walk. Kept to app/config roots to bound cost.
DEFAULT_DIRS = [
    "/home", "/var/www", "/srv", "/opt", "/app", "/etc", "/root",
    "/usr/local", "/tmp",
]

_PLACEHOLDERS = {
    "changeme", "change_me", "password", "passwd", "secret", "token", "example",
    "test", "null", "none", "true", "false", "yourpassword", "your_password",
    "xxx", "redacted", "placeholder", "string",
}


def normalize_proto(scheme: str) -> str:
    s = scheme.lower()
    if s.startswith("jdbc:"):
        s = s[5:]
    return {
        "postgresql": "postgres", "mongodb+srv": "mongodb",
        "mariadb": "mysql", "sqlserver": "mssql",
    }.get(s, s)


def proto_for_port(port: int) -> str:
    return PORT_PROTO.get(port, "unknown")


def kind_for_key(key: str) -> str:
    u = key.upper()
    if "PRIVATE" in u and "KEY" in u:
        return "ssh_key"
    if any(t in u for t in ("PASSWORD", "PASSWD", "PWD")):
        return "password"
    return "token"


def looks_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if len(v) < 3:
        return True
    if v[0] in "$%{<":                       # ${VAR}, %VAR%, {{x}}, <pass>
        return True
    low = v.lower()
    if "process.env" in low or "os.environ" in low or "getenv" in low:
        return True
    if low in _PLACEHOLDERS:
        return True
    if set(v) <= set("x*•.-_"):
        return True
    return False


def mask(value: str) -> str:
    v = value.strip().strip("\"'")
    if len(v) <= 6:
        return "***"
    return f"{v[:2]}***{v[-2:]} ({len(v)} chars)"


# Common password-hash shapes, most-specific first. Used to recognize hashes
# pulled from DB dumps / SAM output and to route NTLM hashes to pass-the-hash.
_HASH_SHAPES = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("sha512crypt", re.compile(r"^\$6\$[^$]{1,16}\$[./A-Za-z0-9]{86}$")),
    ("sha256crypt", re.compile(r"^\$5\$[^$]{1,16}\$[./A-Za-z0-9]{43}$")),
    ("md5crypt", re.compile(r"^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("md5_or_ntlm", re.compile(r"^[a-fA-F0-9]{32}$")),  # 32-hex: md5 OR an NTLM hash
]
# LM:NT combined form, e.g. aad3b435b51404eeaad3b435b51404ee:<32-hex>
_NTLM_COMBINED = re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$")


def looks_like_hash(value: str):
    """Return the hash type name if ``value`` matches a known hash shape, else None."""
    v = (value or "").strip().strip("\"'")
    if _NTLM_COMBINED.match(v):
        return "ntlm"
    for name, rx in _HASH_SHAPES:
        if rx.match(v):
            return name
    return None


def nt_hash(value: str):
    """Extract the NT hash from a bare 32-hex or an ``lm:nt`` pair, else None."""
    v = (value or "").strip().strip("\"'")
    if _NTLM_COMBINED.match(v):
        return v.split(":", 1)[1].lower()
    if re.match(r"^[a-fA-F0-9]{32}$", v):
        return v.lower()
    return None


def scan_line(content: str, source: str) -> list[Finding]:
    """Apply every shape to one line of text; return typed Findings."""
    findings: list[Finding] = []

    for m in CONN_STRING.finditer(content):
        proto = normalize_proto(m.group("scheme"))
        port = m.group("port")
        port_i = int(port) if port and port.isdigit() else PROTO_PORT.get(proto)
        user, pw = m.group("user"), m.group("pw")
        conn_host = m.group("host")
        # Carry the remote host on the Service so correlation tests the cred
        # against the DB host from the URL, not the foothold IP.
        svc = Service(proto=proto, port=port_i, product=m.group("scheme").lower(),
                      notes=f"conn string @ {source}", host=conn_host)
        cred = None
        if pw and not looks_placeholder(pw):
            cred = Credential(kind="password", secret=pw, username=user, source=source,
                              metadata={"proto": proto, "conn_host": conn_host})
        # Endpoint discriminator in the title so two distinct endpoints from the
        # same module/host don't collapse in the store's (type,title,...) dedup.
        endpoint = conn_host + (f":{port_i}" if port_i else "")
        findings.append(Finding(
            type="credential" if cred else "info",
            title=f"{proto} connection string @ {endpoint}" + (f" ({user})" if user else ""),
            severity="high" if cred else "low",
            detail=content.strip()[:200], service=svc, credential=cred))

    for m in HTTP_CREDS.finditer(content):
        pw = m.group("pw")
        if looks_placeholder(pw):
            continue
        cred = Credential(kind="password", secret=pw, username=m.group("user"),
                          source=source, metadata={"url_host": m.group("host")})
        findings.append(Finding(type="credential",
                                title=f"HTTP basic creds for {m.group('host')}",
                                severity="high",
                                detail=f"{m.group('user')}:{mask(pw)}@{m.group('host')}",
                                credential=cred))

    for m in AWS_ACCESS_KEY.finditer(content):
        cred = Credential(kind="token", secret=m.group(0), source=source,
                          metadata={"type": "aws_access_key_id"})
        findings.append(Finding(type="credential", title="AWS access key id",
                                severity="medium", detail=m.group(0), credential=cred))

    for m in ASSIGNMENT.finditer(content):
        key, val = m.group("key"), m.group("val")
        if looks_placeholder(val):
            continue
        cred = Credential(kind=kind_for_key(key), secret=val, source=source,
                          metadata={"var": key})
        findings.append(Finding(type="credential", title=key, severity="medium",
                                detail=f"{key}={mask(val)} ({source})", credential=cred))

    return findings
