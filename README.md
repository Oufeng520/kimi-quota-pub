# kimi-quota-pub

定时查询 Kimi 额度并通过 MQTT（EMQX Serverless）发布到 `kimi/quota`，
供 ESP32-P4 看板订阅刷新。由 GitHub Actions 每 10 分钟运行一次，不依赖本机开机。

## 工作原理

1. 从仓库 Secret `KIMI_WEB_AUTH` 恢复 kimi.com 网页会话凭据到 `kimi_web_auth.json`；
2. `kimi_quota_job.py` 调网页控制台接口取总额度 / Code-5h / Code-7d 用量与重置时间，
   经 TLS 8883 发布到 EMQX；
3. 若运行中 access_token 刷新（refresh_token 可能轮换），把新的凭据加密写回
   `KIMI_WEB_AUTH` Secret（`update_secret.py`，用 `GH_PAT` 鉴权）。

## 需要的 Secrets

| Secret | 内容 |
| --- | --- |
| `KIMI_WEB_AUTH` | `kimi_web_auth.json` 全文（access_token / refresh_token） |
| `MQTT_USERNAME` | EMQX 用户名 |
| `MQTT_PASSWORD` | EMQX 密码 |
| `GH_PAT` | 有 `repo` 权限的 classic PAT，用于写回轮换后的 token |

## 运维

- 失败时 GitHub 会发邮件通知；网页 refresh_token 失效时需重新导出
  `kimi_web_auth.json` 并更新 Secret。
- 长时间（60 天）无仓库活动的仓库，GitHub 可能自动停用定时 workflow，
  到 Actions 页手动 re-enable 即可。
- 本地调试：`MQTT_PASSWORD='xxx' python kimi_quota_job.py`
  （需先放一份有效的 `kimi_web_auth.json` 在同目录，该文件已 gitignore）。
