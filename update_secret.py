#!/usr/bin/env python3
"""把本地文件内容写回 GitHub 仓库 Actions Secret（供 kimi_web_auth token 轮换写回）。

环境变量:
  GH_PAT             有 repo 权限的 Personal Access Token
  GITHUB_REPOSITORY  owner/repo（Actions 里由 ${{ github.repository }} 提供）
  SECRET_NAME        要更新的 Secret 名称，如 KIMI_WEB_AUTH
  SECRET_FILE        本地文件路径，其内容将被加密后写入 Secret
"""
import base64
import json
import os
import urllib.request

from nacl import encoding, public

API = "https://api.github.com"


def _req(method, url, pat, body=None):
    req = urllib.request.Request(
        url, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {pat}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def main():
    pat = os.environ["GH_PAT"]
    repo = os.environ["GITHUB_REPOSITORY"]
    name = os.environ["SECRET_NAME"]
    path = os.environ["SECRET_FILE"]
    with open(path, "rb") as f:
        value = f.read()

    key_info = _req("GET", f"{API}/repos/{repo}/actions/secrets/public-key", pat)
    pk = public.PublicKey(key_info["key"].encode(), encoding.Base64Encoder)
    encrypted = public.SealedBox(pk).encrypt(value)
    _req("PUT", f"{API}/repos/{repo}/actions/secrets/{name}", pat,
         {"encrypted_value": base64.b64encode(encrypted).decode(),
          "key_id": key_info["key_id"]})
    print(f"secret {name} updated for {repo}")


if __name__ == "__main__":
    main()
