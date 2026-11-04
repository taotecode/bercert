# bercert

自动维护七牛云、又拍云 CDN 证书，与 [1Panel](https://1panel.cn/) 证书库保持同步。

程序会对比每个 CDN 域名实际使用的证书和 1Panel 中的证书：过期、缺失或临近过期时，自动上传并绑定匹配的证书；如果 1Panel 没有覆盖该域名的证书，则调用 1Panel 申请（ACME DNS-01 / HTTP-01），失败后持续重试直到成功。

English docs: [README.md](README.md)

## 特性

- 支持七牛云 CDN、又拍云 CDN
- 精确 SAN 优先、单层通配符匹配
- `scan` 与 `renew --dry-run` 只读
- 缺证书时自动在 1Panel 申请
- 申请失败按间隔重试，直到成功
- 内置每日调度，时区跟随服务器；失败后 10 分钟重试
- 复用已上传的同到期时间证书，避免重复上传
- 绑定后回读服务商状态验证
- 纯标准库，无第三方依赖，单二进制部署

## 工作流程

1. 从 1Panel 读取证书、ACME 账户和 DNS 账户。
2. 从七牛/又拍云读取域名与当前绑定证书的到期时间。
3. 判断：健康、续期、申请、无可用证书。
4. 上传（或复用）并绑定，最后回读域名状态验证。

## 安装

```bash
go build -trimpath -o bin/bercert ./cmd/bercert
```

交叉编译 Linux：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/bercert-linux-amd64 ./cmd/bercert
```

## 配置

复制 `.env.example` 为 `.env`（已被 gitignore）：

| 变量 | 说明 |
|---|---|
| `PANEL_BASE_URL` | 1Panel 地址，如 `https://panel.example.com` |
| `PANEL_API_KEY` | 1Panel API 密钥 |
| `PANEL_ISSUE_CERT` | 无匹配证书时是否调用 1Panel 申请 |
| `PANEL_ACME_ACCOUNT_ID` | ACME 账户 ID；留空取第一个 |
| `PANEL_DNS_ACCOUNT_ID` | DNS 账户 ID；留空取第一个 |
| `PANEL_ISSUE_TIMEOUT` | 单次申请等待时间，默认 `15m` |
| `PANEL_ISSUE_RETRIES` | 每次运行申请重试次数，默认 `3`，`0` 表示无限 |
| `PANEL_ISSUE_RETRY_DELAY` | 重试间隔，默认 `2m` |
| `QINIU_AK` / `QINIU_SK` | 七牛密钥 |
| `UPYUN_TOKEN` | 又拍云 Bearer Token，用于读取证书状态 |
| `UPYUN_USERNAME` / `UPYUN_PASSWORD` | 又拍云控制台账号，上传/绑定证书时必需 |
| `RENEW_BEFORE_DAYS` | 剩余有效期少于多少天时续期，默认 `30` |
| `INCLUDE_DOMAINS` / `EXCLUDE_DOMAINS` | 逗号分隔的域名白/黑名单 |

创建又拍云 Token：

```bash
curl -X POST https://api.upyun.com/oauth/tokens \
  -d username="$UPYUN_USERNAME" -d password="$UPYUN_PASSWORD" \
  -d "code=$(openssl rand -hex 16)" -d "name=bercert" -d scope=global
```

返回值中的 `access_token` 填入 `UPYUN_TOKEN`。

## 命令

```bash
bercert doctor                  # 只读自检三条链路
bercert scan                    # 只读巡检
bercert renew --dry-run         # 预演
bercert renew                   # 执行
bercert schedule --at 04:17     # 内置每日调度（服务器本地时区）
bercert daemon --interval 24h   # 简单循环
bercert version
```

公共参数：`--provider qiniu|upyun|all`、`--domain a.com,b.com`、`--renew-before 30d`、`--force`、`--issue`/`--no-issue`、`--retry-until-success`、`--allow-uncovered`、`--json`。

`RENEW_BEFORE_DAYS=30` 会更新服务商提示“有效期不足 30 天”的证书；设为 `15` 可收紧窗口，设为 `0` 则只更换已过期证书。单次运行可用 `--renew-before 15d` 覆盖配置。

退出码：`0` 健康/无需操作，`1` 有待处理项、执行失败或存在无法覆盖的证书。

## 每日调度

`bercert schedule` 启动时先执行一次，之后每天 `--at` 指定的时间执行，使用 `time.Local`（服务器时区）。某一轮有失败时，会在 `--failure-retry`（默认 10 分钟）后重试，直到整轮成功，再恢复每日节奏。

systemd 部署：

```bash
scp bin/bercert-linux-amd64 root@panel-host:/tmp/bercert
scp .env root@panel-host:/tmp/bercert.env
scp -r deploy root@panel-host:/tmp/bercert-deploy
ssh root@panel-host '/tmp/bercert-deploy/install.sh /tmp/bercert /tmp/bercert.env'
```

安装脚本会把二进制和权限为 `0600` 的 `.env` 放到 `/opt/bercert`，移除旧的 timer，并启用 `bercert.service`。

```bash
systemctl status bercert.service
journalctl -u bercert.service -f
```

## 安全

- `.env`、证书和私钥已在 `.gitignore` 中，禁止提交。
- API Key 与服务商密钥应只授权给运行 bercert 的主机。
- `scan` 与 `renew --dry-run` 只读；不希望自动申请时使用 `--no-issue`。
- 服务商凭据只需证书/域名权限，不要使用账户级管理员权限。

## 限制

- 又拍云开放 API Token 可以读取证书状态，但上传返回 `22308 Insufficient authority caused by scope`。bercert 使用 `UPYUN_USERNAME`/`UPYUN_PASSWORD` 登录 `console.upyun.com` 完成上传和绑定，Token 只用于读取。
- 通配符只覆盖一层：`*.example.com` 不覆盖 `a.b.example.com`。
- 七牛绑定后边缘生效需要 5–10 分钟；程序以 API 回读状态为准。
- 1Panel 申请需要可用的 ACME 账户；DNS-01 还需要对该域名所在区域有权限的 DNS 账户。

## 许可证

MIT，见 [LICENSE](LICENSE)。
