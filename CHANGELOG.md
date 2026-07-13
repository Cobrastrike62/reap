# Changelog

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
