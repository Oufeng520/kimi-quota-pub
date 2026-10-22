#!/usr/bin/env python3
"""Kimi 额度定时发布任务：获取额度 -> 发布到 EMQX（ESP32-P4 看板订阅刷新）。

由 GitHub Actions 每 10 分钟调用一次（见 .github/workflows/quota.yml）；
也可本地手动运行：
  MQTT_PASSWORD='xxx' python kimi_quota_job.py

网页会话凭据读写同目录 kimi_web_auth.json（由 Secrets 注入 / 运行后写回，不入库）。
MQTT 连接参数走环境变量：MQTT_HOST / MQTT_PORT / MQTT_USERNAME / MQTT_PASSWORD(必填)。
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt

HOST = os.environ.get("MQTT_HOST", "l4fc8fa9.ala.cn-shenzhen.emqxsl.cn")
PORT = int(os.environ.get("MQTT_PORT", "8883"))
USERNAME = os.environ.get("MQTT_USERNAME", "oufeng")
PASSWORD = os.environ.get("MQTT_PASSWORD", "")
TOPIC = os.environ.get("MQTT_TOPIC", "kimi/quota")
CLIENT_ID = os.environ.get("MQTT_CLIENT_ID", "kimi-quota-job-gh")

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quota_job.log")

# Kimi Code CLI 额度接口（本地兜底数据源；GitHub runner 上一般不存在）
CRED_FILE = os.path.expanduser("~/.kimi-code/credentials/kimi-code.json")
USAGE_URL = "https://api.kimi.com/coding/v1/usages"      # global 区: api.kimi.ai
OAUTH_TOKEN_URL = "https://auth.kimi.com/api/oauth/token"  # global 区: auth.kimi.ai
OAUTH_CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098"
REFRESH_MARGIN_S = 450  # 与 CLI 一致：剩余寿命 <450s 才刷新
LOCAL_TZ = timezone(timedelta(hours=8))


def _load_credentials():
    with open(CRED_FILE, encoding="utf-8") as f:
        return json.load(f)


def _save_credentials(cred):
    tmp = CRED_FILE + f".tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cred, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CRED_FILE)


def _refresh_access_token(cred):
    """refresh_token 每次轮换：成功后必须立即写回。失败抛 RuntimeError。"""
    body = urllib.parse.urlencode({
        "client_id": OAUTH_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": cred["refresh_token"],
    }).encode()
    req = urllib.request.Request(
        OAUTH_TOKEN_URL, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json",
                 "User-Agent": "kimi-code-cli/1.0"},
    )
    last_err = None
    for attempt, backoff in enumerate((0, 1, 2, 4)):
        if backoff:
            time.sleep(backoff)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
            out = dict(cred)
            out["access_token"] = d["access_token"]
            out["refresh_token"] = d["refresh_token"]  # 轮换，必须覆盖
            out["expires_in"] = int(d["expires_in"])
            out["expires_at"] = int(time.time()) + int(d["expires_in"])
            out["token_type"] = d.get("token_type", "Bearer")
            if d.get("scope"):
                out["scope"] = d["scope"]
            _save_credentials(out)
            return out
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode()[:200]
            except Exception:
                pass
            if e.code in (401, 403) or "invalid_grant" in detail:
                raise RuntimeError(
                    f"refresh_token 已失效（HTTP {e.code} {detail}），请在 Kimi Code CLI 重新 /login")
            last_err = f"HTTP {e.code} {detail}"
        except (urllib.error.URLError, OSError) as e:
            last_err = str(e)
    raise RuntimeError(f"token 刷新失败：{last_err}")


def _get_fresh_token():
    cred = _load_credentials()
    if time.time() < cred.get("expires_at", 0) - REFRESH_MARGIN_S:
        return cred["access_token"]
    log("access_token 临近过期，执行刷新")
    return _refresh_access_token(cred)["access_token"]


def _get_usages(token):
    req = urllib.request.Request(
        USAGE_URL,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/json",
                 "User-Agent": "kimi-code-cli/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _iso_to_local(iso, fmt):
    """ISO8601 UTC -> 东八区字符串。"""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(LOCAL_TZ)
    return dt.strftime(fmt)


# --- kimi.com 网页会话（月度总额度数据源，与官方控制台"用量进度"一致） ---
WEB_AUTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kimi_web_auth.json")
WEB_REFRESH_URL = "https://auth.kimi.com/api/account.gateway.v1.AuthService/RefreshToken"
WEB_STATS_URL = "https://www.kimi.com/apiv2/kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats"
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
        import base64
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return 0


def _web_fresh_token():
    """读网页会话凭据；access_token 临近过期（<240s）时用 refresh_token 换新并写回。"""
    with open(WEB_AUTH_FILE, encoding="utf-8") as f:
        auth = json.load(f)
    exp = _jwt_exp(auth["access_token"]) or auth.get("expires_at", 0)
    if time.time() < exp - 240:
        return auth["access_token"]
    body = json.dumps({"refresh_token": auth["refresh_token"]}).encode()
    req = urllib.request.Request(WEB_REFRESH_URL, data=body, method="POST", headers=WEB_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"网页会话刷新失败 HTTP {e.code}（需重新登录 kimi.com 并重新导出 token）")
    out = {
        "access_token": d.get("accessToken") or d.get("access_token"),
        "refresh_token": d.get("refreshToken") or d.get("refresh_token") or auth["refresh_token"],
        "expires_at": int(time.time()) + 900,
    }
    if not out["access_token"]:
        raise RuntimeError("网页会话刷新响应异常")
    with open(WEB_AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f)
    return out["access_token"]


def _fetch_via_web():
    """网页控制台同款接口：一次返回总额度/5小时/7天及各自重置时间。"""
    headers = dict(WEB_HEADERS)
    headers["Authorization"] = f"Bearer {_web_fresh_token()}"
    req = urllib.request.Request(WEB_STATS_URL, data=b"{}", method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.load(r)

    bal = d.get("subscriptionBalance")
    if not isinstance(bal, dict):
        raise RuntimeError(f"网页额度响应缺 subscriptionBalance: {json.dumps(d)[:300]}")
    r5 = d.get("ratelimitCode5h") or {}
    r7 = d.get("ratelimitCode7d") or {}
    out = {
        # 用量为 0 时后端会省略 ratio 字段，缺省一律按 0 处理（2026-10-20 误报 84.57% 的根因）
        "total": round(float(bal.get("amountUsedRatio") or 0) * 100, 2),
        "total_code": round(float(bal.get("kimiCodeUsedRatio") or 0) * 100, 2),
        "code5h": round(float(r5.get("ratio") or 0) * 100, 2),
        "code7d": round(float(r7.get("ratio") or 0) * 100, 2),
    }
    if bal.get("expireTime"):
        out["reset_total"] = _iso_to_local(bal["expireTime"], "%m-%d %H:%M")
    if r5.get("resetTime"):
        out["reset_5h"] = _iso_to_local(r5["resetTime"], "%H:%M")
    if r7.get("resetTime"):
        out["reset_7d"] = _iso_to_local(r7["resetTime"], "%m-%d %H:%M")
    log(f"quota fetched (web subscriptionBalance): {json.dumps(out, ensure_ascii=False)}")
    return out


def fetch_kimi_quota():
    """查询真实 Kimi 额度并映射为看板载荷。

    返回 dict：total / code5h / code7d（已用百分比），reset_total / reset_7d（MM-DD HH:MM），
    reset_5h（HH:MM）。updated 由发布方填当前时间。
    优先走网页控制台接口（含月度总额度，用量为 0 的字段按 0 处理）；
    失败则退回 CLI 接口（仅 5h/7d 真实值，拿不到月度总额度时不发布 total）。
    """
    try:
        return _fetch_via_web()
    except Exception as e:
        log(f"WARN web 通道失败，退回 CLI 通道: {e}")
    d = _get_usages(_get_fresh_token())
    usages = d.get("usages") or {}
    l5 = usages.get("limit_5h") or {}
    l7 = usages.get("limit_7d") or {}
    lm = usages.get("limit_month_total") or {}

    out = {}
    if "used_ratio" in l5:
        out["code5h"] = round(float(l5["used_ratio"]) * 100, 2)
    if l5.get("reset_time"):
        out["reset_5h"] = _iso_to_local(l5["reset_time"], "%H:%M")
    if "used_ratio" in l7:
        out["code7d"] = round(float(l7["used_ratio"]) * 100, 2)
    if l7.get("reset_time"):
        out["reset_7d"] = _iso_to_local(l7["reset_time"], "%m-%d %H:%M")

    if "used_ratio" in lm:
        out["total"] = round(float(lm["used_ratio"]) * 100, 2)
        if lm.get("reset_time"):
            out["reset_total"] = _iso_to_local(lm["reset_time"], "%m-%d %H:%M")
        src = "limit_month_total"
    else:
        # 不再用 booster 钱包冒充总额度（会显示严重偏离的错误值）；
        # 拿不到月度总额度时宁可不带 total 字段，看板保持上次显示
        src = "cli_no_total"

    missing = [k for k in ("code5h", "code7d") if k not in out]
    if missing:
        raise RuntimeError(f"CLI 额度响应缺字段 {missing}: {json.dumps(d)[:300]}")
    log(f"quota fetched ({src}): {json.dumps(out, ensure_ascii=False)}")
    return out


def log(msg):
    line = f"[{datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def publish(payload):
    data = json.dumps(payload, ensure_ascii=False)
    state = {"ok": False, "err": None}
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=CLIENT_ID,
                         protocol=mqtt.MQTTv311)
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)

    def on_connect(c, u, flags, rc, props=None):
        state["ok"] = (getattr(rc, "value", 0) == 0)
        if not state["ok"]:
            state["err"] = f"connect rc={rc}"

    client.on_connect = on_connect
    try:
        client.connect(HOST, PORT, keepalive=30)
    except Exception as e:
        return False, f"connect exception: {e}"
    client.loop_start()
    t0 = time.time()
    while not state["ok"] and state["err"] is None and time.time() - t0 < 10:
        time.sleep(0.1)
    if not state["ok"]:
        client.loop_stop()
        return False, state["err"] or "connect timeout"

    info = client.publish(TOPIC, data, qos=1)
    try:
        info.wait_for_publish(timeout=10)
    except Exception as e:
        client.loop_stop()
        return False, f"publish exception: {e}"
    time.sleep(0.3)
    client.loop_stop()
    client.disconnect()
    return True, f"mid={info.mid}"


def main():
    if not PASSWORD:
        log("FAIL: 未设置 MQTT_PASSWORD 环境变量（应由 GitHub Secrets 注入）")
        return 1
    try:
        payload = fetch_kimi_quota()
    except Exception as e:
        log(f"FAIL fetch quota: {e}")
        return 1
    payload["updated"] = datetime.now(LOCAL_TZ).strftime("%H:%M:%S")
    if "total" in payload:
        payload.setdefault("total_code", 0.0)  # CLI 兜底通道无 Code 拆分，按 0 处理
    else:
        payload.pop("total_code", None)  # total 缺失时 total_code 一并省略，避免拆分比例与总量不一致
    ok, detail = publish(payload)
    if ok:
        log(f"OK published {TOPIC} <= {json.dumps(payload, ensure_ascii=False)} ({detail})")
        return 0
    log(f"FAIL publish {TOPIC}: {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
