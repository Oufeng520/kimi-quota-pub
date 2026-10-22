#!/usr/bin/env python3
"""一次性播种：把当前（必要时先刷新）kimi 网页 token 加密写入 broker retained 消息。

SCF 函数以 broker retained `kimi/quota/auth` 为 token 唯一来源；本脚本由
seed.yml 手动触发执行一次，完成从 GitHub Secret 到 broker 的迁移。

环境变量:
  KIMI_WEB_AUTH_FILE  本地 token 文件（由 secret 恢复，刷新后覆盖写回）
  TOKEN_KEY           64 位十六进制 AES-256 密钥
  MQTT_USERNAME / MQTT_PASSWORD
"""
import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt
from Crypto.Cipher import AES

HOST = os.environ.get("MQTT_HOST", "l4fc8fa9.ala.cn-shenzhen.emqxsl.cn")
PORT = int(os.environ.get("MQTT_PORT", "8883"))
TOPIC_AUTH = os.environ.get("MQTT_TOPIC_AUTH", "kimi/quota/auth")
AUTH_FILE = os.environ.get("KIMI_WEB_AUTH_FILE", "kimi_web_auth.json")

WEB_REFRESH_URL = "https://auth.kimi.com/api/account.gateway.v1.AuthService/RefreshToken"
WEB_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "connect-protocol-version": "1",
    "x-msh-platform": "web",
    "x-msh-version": "2.3.0",
    "x-msh-device-id": "7611043427060396034",
    "R-Timezone": "Asia/Shanghai",
    "X-Language": "zh-CN",
}


def _jwt_exp(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return 0


def refresh_if_needed(auth):
    exp = _jwt_exp(auth["access_token"]) or auth.get("expires_at", 0)
    if time.time() < exp - 240:
        print("access_token 仍有效，无需刷新")
        return False
    body = json.dumps({"refresh_token": auth["refresh_token"]}).encode()
    req = urllib.request.Request(WEB_REFRESH_URL, data=body, method="POST", headers=WEB_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"网页会话刷新失败 HTTP {e.code}")
    out = {
        "access_token": d.get("accessToken") or d.get("access_token"),
        "refresh_token": d.get("refreshToken") or d.get("refresh_token") or auth["refresh_token"],
        "expires_at": int(time.time()) + 900,
    }
    if not out["access_token"]:
        raise RuntimeError("网页会话刷新响应异常")
    auth.clear()
    auth.update(out)
    print("access_token 已刷新（refresh_token 轮换）")
    return True


def main():
    with open(AUTH_FILE, encoding="utf-8") as f:
        auth = json.load(f)
    refresh_if_needed(auth)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth, f)

    key = bytes.fromhex(os.environ["TOKEN_KEY"])
    nonce = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(
        json.dumps(auth, separators=(",", ":")).encode())
    blob = base64.b64encode(nonce + tag + ct).decode()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id="kimi-quota-seed", protocol=mqtt.MQTTv311)
    client.username_pw_set(os.environ.get("MQTT_USERNAME", "oufeng"),
                           os.environ["MQTT_PASSWORD"])
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    client.connect(HOST, PORT, keepalive=30)
    client.loop_start()
    time.sleep(1.0)
    info = client.publish(TOPIC_AUTH, blob, qos=1, retain=True)
    info.wait_for_publish(timeout=10)
    time.sleep(0.5)
    client.loop_stop()
    client.disconnect()
    print(f"broker seeded: {TOPIC_AUTH} retained 已写入（AES-GCM 加密）")


if __name__ == "__main__":
    main()
