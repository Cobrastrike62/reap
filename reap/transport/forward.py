"""Local SSH port forwarding (direct-tcpip) over an existing paramiko Transport.

Same effect as ``ssh -L <local>:<rhost>:<rport>``, but in-process and reusing a
session reap already holds — so reap can reach a target's loopback-only services
(and hosts only reachable from the pivot) and correlate against them without a
separate ``ssh -L``.

CONSTRAINT: reap never initiates access. Forwarding runs only over a
session the operator already registered, and only to hosts/services reachable
from that foothold — it is a convenience over the existing channel, not a new
way in.
"""
from __future__ import annotations

import select
import socket
import threading


class LocalForward:
    """A running ``127.0.0.1:local_port`` listener that pipes each connection to
    ``remote_host:remote_port`` through a paramiko ``Transport`` via a
    ``direct-tcpip`` channel. Runs in daemon threads; call :meth:`stop` to close."""

    def __init__(self, transport, remote_host: str, remote_port: int,
                 local_port: int = 0, bind_host: str = "127.0.0.1"):
        self.transport = transport
        self.remote_host = remote_host
        self.remote_port = int(remote_port)
        self.bind_host = bind_host
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((bind_host, int(local_port)))
        self._server.listen(16)
        self.local_port = self._server.getsockname()[1]

        self._accept = threading.Thread(target=self._serve, daemon=True)
        self._accept.start()

    def _serve(self) -> None:
        self._server.settimeout(1.0)
        while not self._stop.is_set():
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(client, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _handle(self, client: socket.socket, addr) -> None:
        try:
            chan = self.transport.open_channel(
                "direct-tcpip", (self.remote_host, self.remote_port), addr)
        except Exception:
            client.close()
            return
        if chan is None:
            client.close()
            return
        try:
            while not self._stop.is_set():
                r, _, _ = select.select([client, chan], [], [], 1.0)
                if client in r:
                    data = client.recv(4096)
                    if not data:
                        break
                    chan.sendall(data)
                if chan in r:
                    data = chan.recv(4096)
                    if not data:
                        break
                    client.sendall(data)
        except Exception:
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass

    def is_alive(self) -> bool:
        return (not self._stop.is_set() and self.transport is not None
                and self.transport.is_active())

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except Exception:
            pass

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<LocalForward 127.0.0.1:{self.local_port} -> "
                f"{self.remote_host}:{self.remote_port}>")
