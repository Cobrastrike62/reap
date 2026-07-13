"""Offline tests — no target required. Run after exporting to Kali to validate
the build end-to-end:  pytest -q
"""
from __future__ import annotations

from reap.fingerprint import _sections
from reap.models import Context, Credential, Finding, Service
from reap.patterns import scan_line
from reap.store import LootStore
from reap.transport.base import Result


class FakeSession:
    """Canned exec() responses keyed by a substring of the command."""
    host = "10.0.0.1"
    session_id = "fake"

    def __init__(self, responses: dict):
        self.responses = responses

    def exec(self, cmd, timeout=30):
        for key, out in self.responses.items():
            if key in cmd:
                return Result(out, "", 0, 0.0)
        return Result("", "", 0, 0.0)

    def is_alive(self):
        return True


# --- patterns ---------------------------------------------------------------
def test_scan_line_connection_string_emits_cred_and_service():
    findings = scan_line("DATABASE_URL=mysql://admin:p4ss@db.local:3306/app", "x")
    creds = [f.credential for f in findings if f.credential]
    svcs = [f.service for f in findings if f.service]
    assert any(c.secret == "p4ss" and c.username == "admin" for c in creds)
    assert any(s.proto == "mysql" and s.port == 3306 for s in svcs)


def test_scan_line_assignment_and_placeholder_filtering():
    hit = scan_line('DB_PASSWORD="Sup3rS3cret!"', "x")
    assert any(f.credential and f.credential.secret == "Sup3rS3cret!" for f in hit)
    # placeholders / env refs are ignored
    assert scan_line("PASSWORD=changeme", "x") == []
    assert scan_line("SECRET=${ENV_SECRET}", "x") == []


# --- store ------------------------------------------------------------------
def test_store_ingest_dedup_rank_and_verify(tmp_path):
    store = LootStore(str(tmp_path / "t.db"))
    hid = store.get_or_create_host("10.0.0.1", os="linux")
    f = Finding(type="credential", title="DB pw", severity="high",
                credential=Credential(kind="password", secret="x", username="admin",
                                       source="/cfg"),
                service=Service(proto="mysql", port=3306))
    store.ingest(f, hid)
    store.ingest(f, hid)  # dedup
    assert len(store.get_credentials()) == 1
    assert len(store.get_services()) == 1
    assert store.get_findings()[0]["severity"] == "high"

    cid = store.get_credentials()[0]["id"]
    sid = store.get_services()[0]["id"]
    store.mark_verified(cid, sid)
    assert sid in store.get_credentials()[0]["verified_against"]


# --- fingerprint parsing ----------------------------------------------------
def test_sections_parser():
    raw = "@@OS@@\nLinux x 6.1 x86_64\n@@USER@@\nroot\n0\n@@END@@"
    sec = _sections(raw)
    assert sec["OS"].startswith("Linux")
    assert sec["USER"].split()[1] == "0"


# --- module pipeline (no real box) ------------------------------------------
def test_secret_scanner_pipeline_offline():
    from reap.modules.primitives.secret_scanner import SecretPatternScanner
    grep_out = ("/var/www/app/.env:3:DB_PASSWORD=Sup3rS3cret\n"
                "/app/config.js:5:mysql://admin:p4ss@db.local:3306/app")
    sess = FakeSession({"grep -rEni": grep_out})
    findings = SecretPatternScanner().collect(sess)
    assert any(f.credential and f.credential.secret == "Sup3rS3cret" for f in findings)
    assert any(f.service and f.service.proto == "mysql" for f in findings)
    assert all(f.source_module == "secret_scanner" for f in findings)


# --- registry / selection ---------------------------------------------------
def test_registry_selects_by_context():
    from reap.modules import all_modules, select
    names = {m.name for m in all_modules()}
    assert {"secret_scanner", "node_plugin", "config_harvester"} <= names

    ctx = Context(os="linux", runtime=["node"])
    selected = {m.name for m in select(ctx)}
    assert "secret_scanner" in selected
    assert "node_plugin" in selected      # node runtime present
    win = {m.name for m in select(Context(os="windows"))}
    assert "secret_scanner" not in win    # linux-only primitive stays off
    assert "windows_loot" in win          # windows-only collector fires


# --- port forwarding contract -----------------------------------------------
def test_non_ssh_session_cannot_forward():
    import pytest
    from reap.transport.base import NotSupported
    from reap.transport.webshell import WebShellSession
    sess = WebShellSession(url="http://target/sh.php")   # no network in __init__
    with pytest.raises(NotSupported):
        sess.open_forward("127.0.0.1", 3306)


# --- conn-string remote host (Tier-1 bug #1) --------------------------------
def test_conn_string_carries_remote_host(tmp_path):
    findings = scan_line("DATABASE_URL=mysql://root:pw@db01:3306/app", "cfg")
    svc = next(f.service for f in findings if f.service)
    assert svc.host == "db01"
    store = LootStore(str(tmp_path / "t.db"))
    hid = store.get_or_create_host("10.0.0.1", os="linux")
    for f in findings:
        store.ingest(f, hid)
    row = next(s for s in store.get_services() if s["proto"] == "mysql")
    assert row["remote_host"] == "db01"                 # correlation targets db01
    assert any(h["address"] == "db01" for h in store.get_hosts())  # neighbor registered


def test_conn_string_localhost_stays_foothold(tmp_path):
    findings = scan_line("DATABASE_URL=mysql://root:pw@localhost:3306/app", "cfg")
    store = LootStore(str(tmp_path / "t.db"))
    hid = store.get_or_create_host("10.0.0.1", os="linux")
    for f in findings:
        store.ingest(f, hid)
    row = next(s for s in store.get_services() if s["proto"] == "mysql")
    assert row["remote_host"] is None                   # loopback -> foothold, not sprayed
    assert not any(h["address"] == "localhost" for h in store.get_hosts())


# --- correlation (no network) -----------------------------------------------
def test_correlation_capability_no_network(tmp_path):
    from reap.correlation import CorrelationEngine
    store = LootStore(str(tmp_path / "t.db"))
    hid = store.get_or_create_host("10.0.0.1")
    store.add_credential(Credential(kind="capability", secret="k", source="/app/.env",
                                    metadata={"capability": "jwt_sign"}), hid)
    results = CorrelationEngine(store).run()
    assert any(r["type"] == "capability" and r["capability"] == "jwt_sign" for r in results)
    assert any(f["type"] == "capability" for f in store.get_findings())


def test_correlation_compatible():
    from reap.correlation import CorrelationEngine, _PASSWORD_PROTOS
    C = CorrelationEngine
    assert C._compatible({"kind": "ssh_key"}, {"proto": "ssh"})
    assert not C._compatible({"kind": "ssh_key"}, {"proto": "mysql"})
    assert C._compatible({"kind": "hash"}, {"proto": "smb"})
    assert C._compatible({"kind": "hash"}, {"proto": "winrm"})
    assert not C._compatible({"kind": "hash"}, {"proto": "ssh"})   # PtH not over ssh
    for p in _PASSWORD_PROTOS:
        assert C._compatible({"kind": "password"}, {"proto": p})


def test_candidate_usernames_priority(tmp_path):
    from reap.correlation import CorrelationEngine
    store = LootStore(str(tmp_path / "t.db"))
    hid = store.get_or_create_host("10.0.0.1")
    store.add_credential(Credential(kind="password", secret="x", username="svcacct"), hid)
    store.add_finding("info", "System user: webadmin", host_id=hid)
    users = CorrelationEngine(store, max_users=3)._candidate_usernames(store.get_credentials())
    assert users[0] == "svcacct"                        # discovered cred user first
    assert "webadmin" in users                          # real account survives the cap
    assert users.index("webadmin") < users.index("root")  # real users before defaults


# --- webshell exit-code handling (Tier-1 bug #4) ----------------------------
def test_webshell_rc_parse_and_missing_sentinel(monkeypatch):
    from reap.transport import webshell as ws

    class FakeResp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body

    sess = ws.WebShellSession(url="http://t/sh.php")
    monkeypatch.setattr(ws.urllib.request, "urlopen",
                        lambda *a, **k: FakeResp(f"hello world\n{sess._marker}7".encode()))
    r = sess.exec("whoami")
    assert r.out == "hello world" and r.exit_code == 7

    # No sentinel (truncated/dead) must NOT read as success.
    monkeypatch.setattr(ws.urllib.request, "urlopen",
                        lambda *a, **k: FakeResp(b"partial no marker"))
    r2 = sess.exec("whoami")
    assert r2.exit_code == 127 and not r2.ok


# --- hash shapes ------------------------------------------------------------
def test_hash_shapes():
    from reap.patterns import looks_like_hash, nt_hash
    assert looks_like_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "md5_or_ntlm"
    assert looks_like_hash("$2b$12$" + "a" * 53) == "bcrypt"
    assert looks_like_hash("not a hash") is None
    combined = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    assert nt_hash(combined) == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert nt_hash("31d6cfe0d16ae931b73c59d7e0c089c0") == "31d6cfe0d16ae931b73c59d7e0c089c0"


# --- plugin capability metadata contract ------------------------------------
def test_php_plugin_capability_contract():
    from reap.modules.plugins.php import PhpPlugin
    from reap.correlation import _CAP_ACTIONS
    caps = PhpPlugin()._caps("APP_KEY=base64:" + "A" * 40 + "\n", "/app/.env")
    kinds = {f.credential.metadata["capability"] for f in caps}
    assert "laravel_appkey" in kinds
    assert kinds <= set(_CAP_ACTIONS)          # every emitted capability is known


# --- a new collector end-to-end (offline) -----------------------------------
def test_sudo_privesc_flags_nopasswd():
    from reap.modules.primitives.sudo_privesc import SudoPrivesc
    sess = FakeSession({"sudo -n -l": "(root) NOPASSWD: /usr/bin/vim"})
    findings = SudoPrivesc().collect(sess)
    assert any("NOPASSWD" in f.title for f in findings if f.severity == "high")


# --- raw shell sentinel exec (reverse/bind shells) --------------------------
def test_rawshell_exec_recovers_output_and_exit_code():
    import socket
    import threading
    from reap.transport.rawshell import RawShellSession

    a, b = socket.socketpair()
    sess = RawShellSession(sock=a, prime=False, shell="sh")   # inject socket, no network

    def fake_shell():
        b.recv(65536)                                          # consume the wrapped command
        b.sendall(("uid=0(root) gid=0(root)\n" + sess._marker + "0\n").encode())

    t = threading.Thread(target=fake_shell, daemon=True)
    t.start()
    result = sess.exec("id")
    t.join(timeout=5)
    assert result.exit_code == 0
    assert "uid=0(root)" in result.out
    assert sess._marker not in result.out                     # sentinel stripped from output
    a.close()
    b.close()
