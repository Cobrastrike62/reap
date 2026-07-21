# Changelog

## v1.6 — enum: interesting files & permissions + a dedicated listeners view

- **`interesting_files` — the linpeas "interesting permissions" pass.** `enum` now
  surveys writable `$PATH` directories, **root-owned files the current user can
  write**, world-writable files/dirs, and files the user owns in system locations.
  Framing is deliberate: "writable by root" is meaningless (root writes everything)
  and "owned by root" is most of the disk, so the module targets what the
  *unprivileged* user can write — the escalation gold being the root-owned +
  user-writable intersection. `run` persists the two direct privesc handles (a
  writable `$PATH` dir, a root-owned file you can write) as **high** misconfigs.
- **Scoped & fast by default**, with an escape hatch. The sweep hits a curated set
  of roots plus `$PATH`, pruning `/proc`,`/sys`,`/dev`,`/run`,`/snap` and capping
  results — quick even over a raw shell. `REAP_ENUM_FULLFS=1` sweeps the whole tree
  like linpeas. `$HOME`-rooted `$PATH` entries are excluded (your own `~/.local/bin`
  being writable is not privesc), and the entire sweep is skipped when you're root.
- **Listening sockets are now their own `enum` section.** `system_snapshot` splits
  the old combined connections dump into **listening sockets** (`ss -lntup`) and
  **established connections**, so open ports are called out instead of buried.
- 29 modules now register (was 28). Tests: 24 → 26.

## v1.5 — native enumeration (`enum`) + a target shell (`!` / `interact`)

- **`enum` — linpeas-style situational awareness, natively.** Surveys the active
  session and prints it to screen: processes, cron jobs (all sources: crontab,
  `cron.d`, periodic dirs, user spool, systemd timers), systemd/SysV services,
  network (interfaces / routes / connections / ARP / DNS / hosts), and kernel / OS /
  sudo versions. No binary to drop or hide, unlike the opt-in LinPEAS/WinPEAS
  wrappers. Screen-only by design (`enum [filter]` narrows by module) so it never
  clutters the loot DB. Five new collectors — `processes`, `cron_jobs`,
  `init_services`, `system_snapshot` (Linux) and `windows_enum` (Windows); 28
  modules now register (was 23).
- **The actionable subset is still persisted by `run`.** The same collectors emit
  ranked findings for what matters: a secret on a process/cron/service command line
  → credential (fed to correlation); a **writable** systemd unit / `ExecStart=`
  binary / cron target → high misconfig (classic privesc); an unquoted Windows
  service path → medium. Command-line password switches (`--password X`) are vetted
  so a `-passwd /path/to/file` reference isn't mistaken for a literal secret, and
  pseudo-fs paths (`/dev/null` &c.) are excluded from writability checks.
- **`!<cmd>` / `interact` — run terminal commands on the target from the console.**
  `!id`, `!ls -la /root` for one-offs; `interact` for a line-based remote prompt
  until `exit`/Ctrl-D. A per-session **virtual working directory** makes `cd`
  persist across commands on *every* transport, including SSH whose `exec` channel
  is otherwise one-shot. No PTY (no `top`/`vi`/interactive `sudo`) — same limit as
  the raw-shell adapter; stabilize in pwncat-vl for those. Unknown console verbs now
  hint at `!`/`interact` instead of a bare error. Tests: 16 → 24.

## v1.4 — port forwarding through raw shells (chisel)

- **`forward` now works over exec-only sessions** (raw reverse/bind shells,
  webshells), not just SSH. A raw shell is a single command channel and can't
  multiplex TCP streams, so reap orchestrates a **chisel reverse tunnel**: it runs
  a chisel server on the operator host and, through the shell, has the target pull
  chisel and run a reverse client that dials back out (firewall-friendly). The
  forwarded local port is registered so `correlate` reaches the internal service.
- Auto-detects the callback address from the caught shell (override with
  `REAP_LHOST`); resolves the chisel binary via `REAP_CHISEL` / `PATH`. Requires
  `wget` or `curl` on the target. SSH sessions still forward in-process (unchanged).
- Also silenced paramiko's background-thread logging (the "Error reading SSH
  protocol banner" traceback spam during credential-reuse testing).

## v1.3 — raw reverse/bind shell adapter

- **`RawShellSession` + `register listen` / `register bind`.** reap can now drive a
  raw caught shell directly, without upgrading it first. `listen <port>` opens a
  listener and catches a reverse shell (reap replaces `nc`); `bind <host> <port>`
  dials out to a bind shell. Each command is wrapped with a high-entropy sentinel so
  reap recovers the command's output and a real exit code over the bare socket — the
  same technique the webshell adapter uses, applied to TCP.
- No PTY, so interactive prompts don't work; reap only runs commands that return, so
  collection modules are unaffected. `--shell cmd` handles a Windows `cmd.exe` shell.
  Forwarding still needs SSH; for stability-sensitive work, upgrade to SSH.

## v1.2 — SSH port forwarding

- **`forward` / `unforward` / `forwards` commands.** Tunnel a target-internal
  service to `127.0.0.1:<local_port>` through the active SSH session via a
  paramiko `direct-tcpip` channel — same effect as `ssh -L`, but in-process and
  reusing the foothold reap already holds. The local endpoint is registered as a
  service so `correlate` reaches it. Reaches the foothold's own loopback services
  and any host reachable from it (one-hop pivot; loot store persists across hops).
- **Auto-forward on `run`.** Loopback-bound, correlate-able services discovered by
  `listening_services` (DB/SSH/WinRM/etc.) are forwarded automatically and
  registered for correlation. Opt out with `REAP_NO_AUTOFORWARD=1`.
- Forwarding needs an SSH-backed session (`register ssh` / pwncat handoff);
  `Session.open_forward()` raises `NotSupported` on webshell/WinRM. Forwards are
  torn down on exit. Tests: 15 → 16.

## v1.1 — improvement backlog (post-v1 review)

Applied the review backlog. All changes preserve the v1 design (collect →
correlate → rank → stop; modules never see the transport; new runtimes are
~30-line plugins). 23 modules now register (was 13). Tests: 6 → 15, all passing.

### Correctness (the bugs that silently cost pivots)
- **Connection-string creds now target the right host.** A `mysql://user:pw@db01`
  in a config is tested against `db01` (registered as a neighbor host), not the
  foothold IP. `Service.host` + `services.remote_host` carry it through; a
  `localhost` conn string still resolves to the foothold. *(was: silently missed
  the split web/DB pivot)*
- **Candidate usernames are prioritized, then capped** (discovered users →
  system users → defaults), so the real target account survives `max_users`.
  *(was: alphabetical sort-then-truncate could drop the box's real login user)*
- **Fingerprint no longer misfires to `os=unknown`** on a slow/timed-out first
  `uname` (which disabled every Linux collector): retry + speculative probe with
  promotion, plus a truncated-probe guard (`fingerprint_complete`).
- **Webshell never fakes success.** A missing/garbled exit-code sentinel returns
  127 (not 0); high-entropy per-session marker; regex-anchored parse; `shell=cmd`
  for Windows webshells.
- **MSSQL / FTP / SMB auth tests implemented** (were listed compatible but never
  run). Encrypted SSH keys are parsed once and paired with discovered passwords
  as passphrases (were silently treated as non-authenticating). DB clients closed
  in `finally` (were leaking on failure).
- **OS overwrite** on re-fingerprint; **conn-string info findings** no longer
  collapse distinct endpoints in dedup.

### New capability: pass-the-hash
- NTLM hashes are tested (not cracked) over SMB (impacket) and WinRM instead of
  being dropped. `smb` added as a correlatable service/proto.

### New collectors (+10 modules)
- **sudo_privesc** — `sudo -n -l`, non-standard SUID, capabilities, writable cron.
- **cloud_creds** — `~/.aws` secret key, `~/.kube`, `~/.docker` (decoded), gcloud.
- **pivot_targets** — `~/.ssh/config`, `known_hosts`, `/etc/hosts`, arp → Service
  rows with a remote host so correlation reaches neighbors.
- **db_artifacts** — `.sql`/`.sqlite` dumps → creds + hashes.
- **kerberos_sessions** — krb5cc/keytab + attachable tmux/screen sockets.
- **php** — Laravel `APP_KEY` / Symfony `APP_SECRET` as capabilities.
- **jwt_keys** — RS256 PEM signing keys as a `jwt_sign` capability.
- **windows_users** — `net user`/`net group` → correlation username seeds.
- **windows_registry** — Winlogon autologon, WinSCP/VNC (capability), PuTTY.
- **windows_loot** — PowerShell history, unattend, GPP cpassword (decrypted with
  the public static key), `cmdkey`, vault locate, SAM-theft hints as SYSTEM.

### Operator experience
- `export creds|targets|json` — hydra/netexec-ready user/pass lists, a host:port
  target list, and a full JSON dump.
- `search <regex>`, `note <id> <text>`, `hosts`, `import <nmap.xml>` (seed
  services pre-loot). `report [path] [redact]` masks secrets in the shared report.
- Driver parity: `reap_run.py webshell:<METHOD>:<PARAM>:<url>`.

### OPSEC / hygiene
- Correlation de-dupes attempts, skips already-verified pairs, probes reachability
  once (early-abort dead services), and exposes `no_spray` / `max_attempts_per_host`
  / `delay` for lockout-sensitive AD engagements.
- Loot DB `chmod 0600` on create. **The DB/report still hold plaintext client
  secrets — keep them out of synced folders (e.g. OneDrive).**

### Performance
- One shared secret-grep pass (`_scan_cache`) instead of three tree-walks across
  `secret_scanner` / `config_harvester` / `known_filenames`.
- SSH key parsed once per cred, not once per candidate username.

### Packaging
- `pip install -e '.[db]'` now includes mssql; new `.[win]` (impacket +
  cryptography) and `.[full]` extras.
- `install.sh` gains `--pipx` (global, editable command via pipx + `inject` for
  extras), `--full` / `--win` extra selectors, and `--trusted-host` (corporate
  TLS proxy). `--help` lists all flags. Default local-`.venv` behavior unchanged.
