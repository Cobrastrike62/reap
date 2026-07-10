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
./install.sh --full          # creates .venv and installs reap with all optional backends
source .venv/bin/activate
reap
```

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
reap> run                                      # collect loot, then correlate
reap> creds                                    # recovered credentials + confirmed reuse
reap> findings                                 # ranked findings (capabilities first)
reap> report engagement.md                     # write the report
```

Pivoting? `register` the next host too. The loot store persists, so a credential found on one box is tested against every other box you register.

## How it works

reap is built in layers, each depending only on the one below it:

```
Console        register / run / correlate / forward / report
Correlation    credential-to-service reuse (incl. pass-the-hash) + capability findings
Modules        fingerprint + collection primitives + per-runtime plugins
Loot store     SQLite: hosts, services, credentials, findings
Transport      SSH / WinRM / webshell / pwncat handoff  (one exec contract)
```

Modules never see the transport. They run over a single `Session.exec()` contract, so the same collection works whether the session is SSH, WinRM, a webshell, or a handed-off pwncat shell.

## Attaching to a foothold

Pick the adapter that matches the access you already have:

| Access | Register with |
|---|---|
| SSH password or key | `register ssh <ip> <user> [<pass>] [--key PATH] [--port N]` |
| WinRM | `register winrm <ip> <user> <pass> [--ssl] [--port N]` |
| Web / command-injection RCE | `register webshell <url> [--param NAME] [--method GET\|POST] [--shell sh\|cmd]` |
| Raw reverse/bind shell | stabilize in pwncat-vl, drop an SSH key, then `register ssh` |

For a nologin web user such as `www-data`, the `webshell` adapter loots the host over the RCE while correlation finds the credential that gets you a real shell.

## Commands

| command | description |
|---|---|
| `register <adapter> …` | attach to a foothold and fingerprint it |
| `sessions` / `use <id>` / `hosts` | list sessions / switch the active one / list discovered hosts |
| `fingerprint [id]` | re-probe OS, privilege, runtimes |
| `run [id]` | collect loot, then correlate |
| `correlate` | re-test credentials against services, including pass-the-hash |
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

Services bound to a target's localhost — a database, an admin panel, a second SSH — aren't reachable from your machine. reap tunnels to them over the SSH session it already holds:

```
reap> forward 127.0.0.1 3306          # the foothold's own loopback MySQL
reap> forward 10.10.20.50 22 2222     # a second host, only reachable from the foothold
reap> correlate                        # tests discovered creds against the forwarded service
```

On `run`, reap also auto-forwards loopback-bound databases and services it discovers, so correlation can reach them. Forwarding needs an SSH-backed session.

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
