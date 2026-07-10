"""LootStore — the normalized SQLite spine.

Everything writes here; the correlation engine and console read here. One DB per
engagement, persisting across pivots so correlation gets smarter with each hop.
Ingest is deduplicated so re-running modules doesn't spam the tables.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models import Credential, Finding, Service

# Addresses that mean "this same box" — a conn string to one of these points at
# the foothold, not a remote neighbor, so we don't register it or spray it.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


def _is_local(host: Optional[str]) -> bool:
    return (host or "").strip().lower() in _LOCAL_HOSTS


def _load_schema() -> str:
    """Load the canonical DDL from schema.sql (works installed or editable)."""
    try:
        from importlib.resources import files
        return files("reap.store").joinpath("schema.sql").read_text(encoding="utf-8")
    except Exception:  # pragma: no cover - fallback for odd layouts
        return (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")


# severity / type rank used by the reporter and `findings` view
_SEV_RANK = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
_TYPE_RANK = ("CASE type WHEN 'capability' THEN 0 WHEN 'credential' THEN 1 "
              "WHEN 'misconfig' THEN 2 ELSE 3 END")


class LootStore:
    # Columns added after v1 — ALTER older engagement DBs in place so an
    # existing store keeps opening.
    _EXPECTED_COLUMNS = {
        "services": {"remote_host": "TEXT"},
        "findings": {"note": "TEXT"},
    }

    def __init__(self, db_path: str = "reap.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_load_schema())
        self._ensure_columns()
        self.conn.commit()
        self._harden_perms()

    def _ensure_columns(self) -> None:
        for table, cols in self._EXPECTED_COLUMNS.items():
            existing = {r["name"] for r in
                        self.conn.execute(f"PRAGMA table_info({table})")}
            for col, decl in cols.items():
                if col not in existing:
                    try:
                        self.conn.execute(
                            f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                    except sqlite3.OperationalError:  # pragma: no cover
                        pass

    def _harden_perms(self) -> None:
        """The loot DB holds plaintext client secrets (passwords, full SSH
        keys). Restrict it to the owner. Best-effort: chmod is a no-op on
        Windows, and the DB should not live in a synced folder regardless."""
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:  # pragma: no cover
            pass

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    # -- hosts -----------------------------------------------------------------
    def get_or_create_host(self, address: str, os: Optional[str] = None) -> int:
        row = self.conn.execute(
            "SELECT id, os FROM hosts WHERE address=?", (address,)
        ).fetchone()
        if row:
            # Improve the stored OS when we learn a specific value: overwrite a
            # NULL or a stale 'unknown' (e.g. from a truncated first probe).
            if os and os != "unknown" and (not row["os"] or row["os"] == "unknown"):
                self.conn.execute("UPDATE hosts SET os=? WHERE id=?", (os, row["id"]))
                self.conn.commit()
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO hosts (address, os, first_seen) VALUES (?,?,?)",
            (address, os, self._now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def set_host_os(self, host_id: int, os: str) -> None:
        self.conn.execute("UPDATE hosts SET os=? WHERE id=?", (os, host_id))
        self.conn.commit()

    # -- services --------------------------------------------------------------
    def add_service(self, host_id: int, proto: str, port: Optional[int] = None,
                    product: Optional[str] = None, notes: Optional[str] = None,
                    remote_host: Optional[str] = None) -> int:
        row = self.conn.execute(
            "SELECT id FROM services WHERE host_id=? AND proto=? "
            "AND IFNULL(port,-1)=IFNULL(?,-1) AND IFNULL(remote_host,'')=IFNULL(?,'')",
            (host_id, proto, port, remote_host),
        ).fetchone()
        if row:
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO services (host_id, port, proto, product, notes, remote_host) "
            "VALUES (?,?,?,?,?,?)",
            (host_id, port, proto, product, notes, remote_host),
        )
        self.conn.commit()
        return cur.lastrowid

    # -- credentials -----------------------------------------------------------
    def add_credential(self, cred: Credential, host_id: Optional[int] = None) -> int:
        row = self.conn.execute(
            "SELECT id FROM credentials WHERE kind=? AND IFNULL(username,'')=IFNULL(?,'') "
            "AND secret=?",
            (cred.kind, cred.username, cred.secret),
        ).fetchone()
        if row:
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO credentials (kind, username, secret, source, host_id, metadata, "
            "verified_against) VALUES (?,?,?,?,?,?,?)",
            (cred.kind, cred.username, cred.secret, cred.source, host_id,
             json.dumps(cred.metadata or {}), json.dumps([])),
        )
        self.conn.commit()
        return cur.lastrowid

    def mark_verified(self, cred_id: int, service_id: int) -> None:
        row = self.conn.execute(
            "SELECT verified_against FROM credentials WHERE id=?", (cred_id,)
        ).fetchone()
        ids = json.loads(row["verified_against"] or "[]") if row else []
        if service_id not in ids:
            ids.append(service_id)
            self.conn.execute(
                "UPDATE credentials SET verified_against=? WHERE id=?",
                (json.dumps(ids), cred_id),
            )
            self.conn.commit()

    # -- findings --------------------------------------------------------------
    def add_finding(self, ftype: str, title: str, severity: str = "low",
                    detail: str = "", source_module: str = "",
                    host_id: Optional[int] = None) -> int:
        row = self.conn.execute(
            "SELECT id FROM findings WHERE type=? AND title=? "
            "AND IFNULL(host_id,-1)=IFNULL(?,-1) AND IFNULL(source_module,'')=IFNULL(?,'')",
            (ftype, title, host_id, source_module),
        ).fetchone()
        if row:
            return row["id"]
        cur = self.conn.execute(
            "INSERT INTO findings (type, severity, title, detail, source_module, host_id, "
            "created) VALUES (?,?,?,?,?,?,?)",
            (ftype, severity, title, detail, source_module, host_id, self._now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def set_finding_note(self, finding_id: int, note: str) -> bool:
        """Attach an operator annotation to a finding (console 'note' command)."""
        cur = self.conn.execute(
            "UPDATE findings SET note=? WHERE id=?", (note, finding_id))
        self.conn.commit()
        return cur.rowcount > 0

    def ingest(self, finding: Finding, host_id: Optional[int] = None) -> int:
        """Route a module-emitted Finding into the normalized tables: the linked
        service/credential (if any) to their tables, plus a findings row."""
        if finding.service:
            s = finding.service
            # A service parsed from a conn string may live on a *different*
            # host. Register that neighbor as a first-class discovered host and
            # record it on the service so correlation targets it (not the
            # foothold). A localhost/loopback conn string means the foothold
            # itself, so it's normalized to None.
            remote = s.host if (s.host and not _is_local(s.host)) else None
            if remote:
                self.get_or_create_host(remote)
            self.add_service(host_id, s.proto, s.port, s.product, s.notes,
                             remote_host=remote)
        if finding.credential:
            self.add_credential(finding.credential, host_id)
        return self.add_finding(
            finding.type, finding.title, finding.severity, finding.detail,
            finding.source_module, host_id,
        )

    # -- reads -----------------------------------------------------------------
    def get_hosts(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM hosts ORDER BY id").fetchall()]

    def get_services(self, host_id: Optional[int] = None) -> list[dict]:
        sql = ("SELECT s.*, h.address AS host FROM services s "
               "LEFT JOIN hosts h ON s.host_id=h.id")
        args: tuple = ()
        if host_id is not None:
            sql += " WHERE s.host_id=?"
            args = (host_id,)
        sql += " ORDER BY s.id"
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def get_credentials(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT c.*, h.address AS host FROM credentials c "
            "LEFT JOIN hosts h ON c.host_id=h.id ORDER BY c.id"
        ).fetchall()
        return [self._cred_row(r) for r in rows]

    def get_findings(self, ranked: bool = True) -> list[dict]:
        order = (f"ORDER BY {_SEV_RANK}, {_TYPE_RANK}, created"
                 if ranked else "ORDER BY datetime(created), id")
        rows = self.conn.execute(
            "SELECT f.*, h.address AS host FROM findings f "
            f"LEFT JOIN hosts h ON f.host_id=h.id {order}"
        ).fetchall()
        return [dict(r) for r in rows]

    def timeline(self) -> list[dict]:
        """Findings in discovery order, across hops."""
        return self.get_findings(ranked=False)

    @staticmethod
    def _cred_row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["metadata"] = json.loads(d.get("metadata") or "{}")
        d["verified_against"] = json.loads(d.get("verified_against") or "[]")
        return d

    def close(self) -> None:
        self.conn.close()
