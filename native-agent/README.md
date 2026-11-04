# Agent development and manual connections

To use the agent, follow the [short walkthrough](../AGENT_QUICKSTART.md). Prepared Reap packages include everything needed to create one target file. Users do not install Go, choose a build artifact, or transfer separate credentials.

This page is for maintaining the agent or using an older manual connection method.

## How the one-file setup works

`agent` guides setup; `agent create HOST` is its command-line shortcut. Reap selects an included executable for the chosen target and appends a small validated connection record. The target runs that file without arguments. Creating it does not compile or download anything.

The record contains the operator address, port, random token and pinned public certificate fingerprint. It never contains the operator's TLS private key. Treat the generated executable as private because it contains its connection token. It is written with owner-only permissions on POSIX systems and refuses to overwrite an existing file.

Private listener identities and profile records live in `~/.local/share/reap/agents/`. `XDG_DATA_HOME` or `REAP_AGENT_HOME` can change that location. `agent listen` loads the most recently created profile; `agent list` and `agent show` expose saved profiles without displaying credentials. Closing Reap does not delete the profiles.

The executable trailer is UTF-8 JSON, followed by `REAPCFG1` and an unsigned four-byte big-endian JSON length. JSON is limited to 65,536 bytes. The agent checks version, required fields, field types, address, port, token and fingerprint before connecting. Repeated or unknown keys and malformed records fail before authentication. A configured agent rejects manual connection flags; create another file to change its address. `--help` and `--version` still work.

## Prepared downloads

A prepared release includes all supported target executables and their checksum manifest under `reap/data/native/`. The wheel, source distribution and ready ZIP carry these assets so normal installation requires only the Python operator dependencies. The current ready ZIP is `dist/reap-1.13.0-ready.zip`.

A plain Git checkout or `git archive` contains agent source but may lack ignored executable assets. It is useful for development. Users who want the agent should receive a prepared download rather than build instructions.

The explicit `Prepare release downloads` GitHub workflow tests and builds downloadable artifacts for review. It does not publish a public release automatically. Generated agent files, private profiles, certificates and engagement data are excluded from release packages.

## Maintainer build

Maintainers use the pinned Go 1.26.9 toolchain. This is a development requirement, not an installation step for users. With that toolchain already available:

```bash
python native-agent/build.py --package
python -m build
python tests/verify_prepared_release.py dist
python native-agent/package_release.py
```

`--package` builds all targets and stages verified assets into Python package data. `--package-only` stages an already built release without invoking Go. All targets must match the current Reap version and their SHA-256 digests before staging starts. The installed-wheel check runs outside the source checkout with no compiler on PATH and creates one-file agents for every target.

Builds set `CGO_ENABLED=0`, baseline `GOAMD64=v1`, `GOTOOLCHAIN=local` and `-trimpath`. Linux artifacts are checked for absent dynamic-loader/interpreter program headers. Release metadata records toolchain, source revision, dirty state, target and checksums. Source archives without Git can pass `--source-revision REVISION`; otherwise revision is `unknown` and dirty state is null. A checksum is a byte-integrity check, not publisher authentication.

## Older manual connection methods

Existing scripts can still use `agent prepare DIRECTORY`, which creates the Python agent kit, and `register agent-listen` or `register agent` with that kit. A Python target needs Python 3.9+. The new one-file setup is the normal path.

For an explicit target-side listener, prepare a native kit on the operator:

```text
agent prepare /tmp/manual-kit --type native --platform linux --arch amd64
```

Copy that kit's `reap-agent`, `token.txt`, `cert.pem` and `key.pem` into a private target directory. On the target:

```bash
./reap-agent --bind 0.0.0.0 --port 7443 --token-file ./token.txt --cert ./cert.pem --key ./key.pem
```

In Reap on the operator:

```text
register agent TARGET-IP 7443 --bundle /tmp/manual-kit
```

This advanced mode intentionally has multiple files. Windows selects `--platform windows --arch amd64` and uses `reap-agent.exe`. Linux ARM selects `--arch arm64`. Unconfigured release executables also retain explicit connect-back flags for existing scripts.

## Runtime behavior and testing

Agents remain in the foreground at the existing account's privileges, serve one authenticated session and exit on close or interruption. No persistence, automatic reconnection or PTY is installed. Existing version-1 framed TLS/token sessions, certificate pinning before token transmission, one-minute listener window and serialized requests remain in place.

Linux needs `/bin/sh` and the shell tools used by collectors; its executable has no glibc dependency. Windows uses `cmd.exe` and assigns suspended commands to Job Objects before resuming them. Existing command deadlines, separate 512 KiB captures, real exit codes, timeout code 124 and output-cap code 125 remain. Linux process groups stop ordinary command descendants; deliberately detached processes that leave the group are outside that guarantee.

Linux service probing still negotiates `probe_tcp_v1`: explicitly supplied discovered TCP endpoints only, 12 selected by default, 24 maximum, 55 seconds total, and a shared 64 KiB read allowance per endpoint. Redirects are recorded without following them. TLS metadata is observational, with `identity_verified: false`. Windows service probing is unsupported.

The one-file workflow is exercised against real Linux and Windows executables, including filenames with spaces. An isolated Alpine target receives the generated executable without credential companion files and runs it with no arguments. That target has no Python, Go, compiler, glibc or OpenSSL CLI; a compiled loopback HTTP fixture verifies fingerprinting, procfs socket discovery, service probing and saved enumeration. The Windows command and cleanup tests run natively. ARM64 execution is tested under QEMU user-mode emulation rather than physical ARM hardware.

Developer checks:

```bash
python -m pytest -q
cd native-agent
go test -race ./...
go vet ./...
```

The existing Python-agent and manual-mode fixtures are retained. CI configuration adds prepared-package checks; local verification does not imply a remote CI run has completed. Back up the local Kali source, environment and engagement data before applying an update.
