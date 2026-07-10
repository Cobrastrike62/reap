"""Reporter: a ranked findings list and a cross-hop timeline, for both the
terminal and a markdown export. Boring and accurate by design.

Also emits machine-readable exports that feed the operator's other tools: JSON
(everything), hydra/netexec-ready user/pass lists, and a host:port target list."""
from __future__ import annotations

import json
from pathlib import Path

from .patterns import mask
from .store import LootStore

_SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}


class Reporter:
    def __init__(self, store: LootStore):
        self.store = store

    def findings(self) -> list[dict]:
        return self.store.get_findings(ranked=True)

    def credentials(self) -> list[dict]:
        return self.store.get_credentials()

    def timeline(self) -> list[dict]:
        return self.store.timeline()

    # -- terminal --------------------------------------------------------------
    def render_findings(self, console) -> None:
        from rich.table import Table
        table = Table(title="Ranked findings", expand=True)
        for col in ("Sev", "Type", "Title", "Host", "Module", "Detail"):
            table.add_column(col)
        for f in self.findings():
            sev = f.get("severity") or "low"
            table.add_row(f"[{_SEV_STYLE.get(sev, '')}]{sev}[/]", f["type"],
                          f.get("title", ""), f.get("host") or "-",
                          f.get("source_module") or "-", (f.get("detail") or "")[:80])
        console.print(table)

    def render_creds(self, console) -> None:
        from rich.table import Table
        table = Table(title="Credentials")
        for col in ("ID", "Kind", "User", "Secret", "Source", "Verified against"):
            table.add_column(col)
        svc_index = {s["id"]: s for s in self.store.get_services()}
        for c in self.credentials():
            verified = ", ".join(self._svc_label(svc_index, sid)
                                 for sid in c["verified_against"]) or "-"
            style = "bold green" if c["verified_against"] else ""
            table.add_row(str(c["id"]), c["kind"], c.get("username") or "-",
                          self._show_secret(c), (c.get("source") or "-")[:40],
                          f"[{style}]{verified}[/]" if style else verified)
        console.print(table)

    def render_timeline(self, console) -> None:
        from rich.table import Table
        table = Table(title="Timeline (discovery order, across hops)")
        for col in ("When", "Sev", "Type", "Title", "Host"):
            table.add_column(col)
        for f in self.timeline():
            table.add_row((f.get("created") or "")[:19], f.get("severity") or "",
                          f["type"], f.get("title", ""), f.get("host") or "-")
        console.print(table)

    # -- markdown --------------------------------------------------------------
    def to_markdown(self, redact: bool = False) -> str:
        lines = ["# reap engagement report", "", "## Ranked findings", "",
                 "| Severity | Type | Title | Host | Module | Detail |",
                 "|---|---|---|---|---|---|"]
        for f in self.findings():
            note = f.get("note")
            detail = (f.get("detail") or "")[:160]
            if note:
                detail = f"{detail}  _(note: {note})_"
            lines.append(f"| {f.get('severity', '')} | {f['type']} | "
                         f"{self._md(f.get('title'))} | {f.get('host') or '-'} | "
                         f"{f.get('source_module') or '-'} | "
                         f"{self._md(detail)} |")

        lines += ["", "## Credentials", "",
                  "| Kind | User | Secret | Source | Verified against |",
                  "|---|---|---|---|---|"]
        svc_index = {s["id"]: s for s in self.store.get_services()}
        for c in self.credentials():
            verified = ", ".join(self._svc_label(svc_index, sid)
                                 for sid in c["verified_against"]) or "-"
            secret = mask(c.get("secret") or "") if redact else self._show_secret(c)
            lines.append(f"| {c['kind']} | {c.get('username') or '-'} | "
                         f"{self._md(secret)} | "
                         f"{self._md((c.get('source') or '-')[:60])} | {verified} |")

        lines += ["", "## Timeline", ""]
        for f in self.timeline():
            lines.append(f"- `{(f.get('created') or '')[:19]}` "
                         f"**{f.get('severity', '')}** {f['type']}: "
                         f"{f.get('title', '')} ({f.get('host') or '-'})")
        return "\n".join(lines) + "\n"

    def export_markdown(self, path: str = "reap-report.md", redact: bool = False) -> str:
        Path(path).write_text(self.to_markdown(redact=redact), encoding="utf-8")
        return path

    # -- machine-readable exports ---------------------------------------------
    def export_json(self, path: str = "reap-report.json") -> str:
        """Everything, structured, for downstream tooling."""
        data = {
            "hosts": self.store.get_hosts(),
            "services": self.store.get_services(),
            "credentials": self.credentials(),
            "findings": self.findings(),
            "timeline": self.timeline(),
        }
        Path(path).write_text(json.dumps(data, indent=2, default=str),
                              encoding="utf-8")
        return path

    def export_creds_txt(self, prefix: str = "reap") -> list[str]:
        """Write hydra/netexec-ready lists: users, passwords, and user:pass.
        SSH-key blobs are excluded (they aren't spray material)."""
        users, secrets_, pairs = [], [], []
        seen_u, seen_s, seen_p = set(), set(), set()
        for c in self.credentials():
            u = (c.get("username") or "").strip()
            if u and u not in seen_u:
                seen_u.add(u); users.append(u)
            if c["kind"] in ("ssh_key", "capability"):
                continue
            s = c.get("secret") or ""
            if s and s not in seen_s:
                seen_s.add(s); secrets_.append(s)
            if u and s:
                pair = f"{u}:{s}"
                if pair not in seen_p:
                    seen_p.add(pair); pairs.append(pair)
        written = []
        for name, rows in ((f"{prefix}-users.txt", users),
                           (f"{prefix}-pass.txt", secrets_),
                           (f"{prefix}-userpass.txt", pairs)):
            Path(name).write_text("\n".join(rows) + ("\n" if rows else ""),
                                  encoding="utf-8")
            written.append(name)
        return written

    def export_targets_txt(self, path: str = "reap-targets.txt") -> str:
        """host:port lines (preferring a service's remote_host) + a proto view."""
        lines, seen = [], set()
        for s in self.store.get_services():
            host = s.get("remote_host") or s.get("host")
            port = s.get("port")
            if not host:
                continue
            key = (host, port, s.get("proto"))
            if key in seen:
                continue
            seen.add(key)
            hp = f"{host}:{port}" if port else host
            lines.append(f"{hp}\t{s.get('proto') or '-'}")
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""),
                              encoding="utf-8")
        return path

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _svc_label(idx: dict, sid: int) -> str:
        s = idx.get(sid)
        return f"{s['proto']}@{s['host']}:{s['port']}" if s else str(sid)

    @staticmethod
    def _show_secret(c: dict) -> str:
        if c["kind"] == "ssh_key":
            return "<ssh private key>"
        s = c.get("secret") or ""
        return s if len(s) <= 40 else s[:37] + "..."

    @staticmethod
    def _md(s) -> str:
        return (s or "").replace("|", "\\|").replace("\n", " ")
