# FINDINGS_LOG

Running log of what each test box exposed and which primitive/plugin caught (or
missed) it. Every miss becomes a fix. Box specifics are genericized.

## Lab box A — PHP/Laravel CRM (web RCE → root)

**Chain:** vhost fuzz -> a self-hosted git service leaked a DB password in its
history -> reused on the CRM admin login -> an authenticated file-upload -> RCE
as www-data -> reap loots the real .env password -> SSH reuse as a low-priv user
-> a root-run sync script (path traversal) -> root.

| Stage | Loot | Caught by | Hit/Miss | Action |
|---|---|---|---|---|
| RCE foothold (www-data, nologin) | n/a | - | MISS (no adapter) | **Added `WebShellSession`** transport adapter (exec over webshell) |
| `/var/www/app/.env` real DB/app password | `<redacted>` | secret_scanner + known_filenames + config_harvester | HIT | - |
| root-run sync script (cron privesc) | script path | secret_scanner | HIT | - |
| .env-pass reused for SSH as a real user | pivot | correlation | **MISS** | correlation only tried root/admin/administrator. **Added `system_users` module** + correlation now seeds usernames from discovered /etc/passwd accounts. Re-test now flags it. |
| secret_scanner noise (minified JS, debugbar) | 76 findings, ~60 junk | secret_scanner | MISS (noise) | Added `--exclude-dir=build/assets/debugbar/cache` + `--exclude=*.min.js/css` |
| Heavy module greps over webshell channel | timeouts | - | MISS (perf) | TODO: per-transport scan-scope tuning (webshell/php has ~30s exec cap) |

## v1.1 backlog pass (see CHANGELOG.md)
Resolved:
- [x] Laravel `APP_KEY` capability — new `php` plugin (the CRM's .env had one).
- [x] Webshell exit-code reliability — missing sentinel now fails (127), not silent 0.
- [x] Correlation targeted the foothold for conn-string creds — now uses the DB host.
- [x] Username spray dropped the real account on big /etc/passwd — now prioritized.
- [x] Pass-the-hash — NTLM hashes tested over SMB/WinRM (were dropped).
- [x] `sudo -l` / SUID / writable-cron primitive — the root-cron privesc above would now rank.

Still open:
- secret_scanner: confidence scoring to rank real secrets above source-code matches.
- Per-transport command budget (chunk sweeps under a webshell's ~30s PHP cap) —
  partly mitigated by the single shared grep pass, not yet a hard budget.

## Validation profiles
- [x] LAMP-style reuse: app .env DB pass -> SSH reuse as a real user (lab box A).
- [ ] Node box: `.env` + process env + JWT-secret capability.
- [x] Web-RCE -> cred-reuse pivot (lab box A, via new WebShellSession).
