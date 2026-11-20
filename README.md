# OpenNoFrp

一个专注于"云服务器全端口映射到本地 + 保留客户端真实源IP"的轻量级内网穿透方案。

## 为什么不用现成的 frp？

frp 的 `remotePort` 转发在多层 NAT/Docker 网络环境下，本地服务收到的连接源 IP 会变成 frpc 所在机器的内网 IP（或 TCP 层面直接丢失原始客户端 IP），这在需要按 IP 做限流/封禁/统计的场景（如游戏服务器、Web 服务）里是硬伤。

OpenNoFrp 采用**本地 TPROXY 透明代理**方案，让本地服务**完全无需任何改造**（不要求支持 Proxy Protocol、不要求解析任何自定义协议头），`accept()`/`recvfrom()` 直接拿到的对端地址就是真实公网客户端 IP。详见 `docs/01-架构设计.md`。

## 快速开始与一键安装

### 1. 云服务器端 (Server) 部署

从官方 Release 下载发布脚本和证明包。下面的命令需要支持 `gh attestation verify` 的 [GitHub CLI](https://cli.github.com/)。

```bash
repo=YearnstudioHorizon/OpenNoFrp
tag=$(gh release view --repo "$repo" --json tagName --jq .tagName)
gh release download "$tag" --repo "$repo" \
  --pattern linux-server-install.sh --pattern release-attestation.jsonl
gh attestation verify linux-server-install.sh --repo "$repo" \
  --bundle release-attestation.jsonl --signer-workflow "$repo/.github/workflows/release.yml" \
  --source-ref "refs/tags/$tag" --deny-self-hosted-runners &&
  sudo bash linux-server-install.sh
```

面板默认监听 `127.0.0.1:8080`。可以用 `ssh -L 8080:127.0.0.1:8080 user@server` 转发端口完成本地管理。安装新客户端、生成迁移命令时，设置明确的 HTTPS 外部地址 `public_base_url`，并使用证书有效的面板 HTTPS 或可信 HTTPS 反向代理。

### 2. 内网客户端 (Client) 接入

通过配置好的 HTTPS 地址登录面板，点击 **「接入新机器」**。在内网机器上运行面板生成的命令。脚本在 root 执行前完整下载，通过发布证明校验客户端产物，并用一次性令牌和固定的服务端指纹完成注册。Linux 和 macOS 目标机器都需要 GitHub CLI。

macOS 通过 launchd 托管。源 IP 保留依赖 Linux TPROXY，macOS 默认以普通模式转发。若后端根据源 IP 授权，客户端可设置 `[server] strict_source_ip = true`，让请求源 IP 保留的规则在无法保留时拒绝流量。

## 服务端一键迁移（点对点）

通过 HTTPS 登录源面板，在 **「账号设置」→「迁移到新服务器」** 生成迁移命令并在新的 Linux 主机运行。SQLite 一致性快照、配置、证书和 ACME 缓存通过 HTTPS 直连传送。迁移令牌有效期为 30 分钟，在准备好一致性快照、开始发送包之前一次性消费。已登录的浏览器会话和迁移令牌在目标服务器上需要重新创建。确认新服务、TLS 和反向代理正常后再切换 DNS 和控制流量。

## 临时 VPN 接入

在管理面板的「临时 VPN」页面选择目标机器和有效期，下载 Windows / Linux
接入程序与配置，即可通过 `10.203.0.1:<原端口>` 访问该机器 `127.0.0.1`
上的 TCP / UDP 服务。支持到期断开和手动撤销，详细说明见 [临时 VPN](docs/temporary-vpn.md)。
Server 和内网 Client 都需使用包含此功能的版本。

## 安全与加密特性

- **端到端 TLS 加密信道**：服务端与客户端之间全量握手、心跳与转发数据流均基于 TLS 1.3/1.2 加密传输，杜绝明文窃听与公网嗅探。
- **SHA-256 证书指纹锁定 (Certificate Pinning)**：服务端自动生成长效自签名证书并导出 SHA-256 指纹；客户端严格校验对端指纹，防止中间人劫持 (MITM)。支持 TOFU (Trust On First Use，首次使用自动信任) 及面板一键安装命令自动附带指纹。
- **纯用户态云端**：云服务器端仅运行普通用户态网络转发，**永远不碰内核网络配置**（不修改 iptables/路由表/sysctls），避免误操作失联。
- **受控客户端隔离**：客户端具备目标地址边界防御，严格限定本地回环转发，阻断内网跳板渗透。

## 在线更新与国内加速镜像

### 1. 一键检查与在线自更新 (Self-Update)
使用支持发布证明的 GitHub CLI 验证更新。命令会在替换前启动新二进制检查版本，并留下同目录的 `.bak` 供回滚。通过安装脚本配置并已运行的 Linux systemd 服务会自动重启并检查健康状态，失败时恢复旧二进制；其他安装方式手动重启对应服务。
```bash
# 服务端一键自更新
sudo /opt/opennofrp-server/opennofrp-server update

# 客户端一键自更新
sudo /opt/opennofrp-client/opennofrp-client update
```
Web 管理面板首页也集成了“检查更新”功能，可实时获取 GitHub 最新发行公告。

### 2. 国内 GitHub 加速镜像
针对国内部分服务器或本地网络访问 GitHub 缓慢、连接超时的情况，发行二进制允许走镜像。经官方仓库和发布工作流证明的清单用于校验文件长度和 SHA-256。镜像地址前缀为：
```
https://mirror.yearnstudio.cn/
```
示例：
- 官方链接：`https://github.com/YearnstudioHorizon/OpenNoFrp/releases/download/v0.1.2/opennofrp-client-linux-amd64`
- 加速链接：`https://mirror.yearnstudio.cn/https://github.com/YearnstudioHorizon/OpenNoFrp/releases/download/v0.1.2/opennofrp-client-linux-amd64`

> [!NOTE]
> **自动回退保障**：客户端的一键安装脚本及 `update` 自更新命令已内置双重保障。当直连 GitHub 官方源超时或失败时，会尝试从 `mirror.yearnstudio.cn` 获取二进制，元数据仍取自官方 Release。

> [!IMPORTANT]
> **隐私声明**：除了 Cloudflare 基础设施自动产生的基础网络日志外，我们的镜像加速代理服务**绝不收集、记录、分析或存储任何用户请求内容、传输数据或隐私信息**。

## Docker 容器兼容性

**`docker run -p` 标准端口映射（bridge 模式）无需任何改动即可保留真实源 IP**——OpenNoFrp Client 会自动检测目标端口属于宿主机进程还是某个容器，如果是容器，会用 `setns(2)` 让代理进程本身进入该容器的网络命名空间运行（即"netns-worker"），而不是要求你把容器改成 `--network host`。这个方案已经过真实 Go 代码端到端验证（含并发压测），完整技术细节和踩坑记录见 `docs/01-架构设计.md` 第六节。

## 目录结构

```
OpenNoFrp/
├── README.md              本文件
├── docs/                  详细设计文档、风险评估、部署手册
├── .github/workflows/     GitHub Actions 自动化构建与多架构打包发布
├── server/                云服务器端程序源码（Go，含 Web 管理面板、TLS 监听器）
├── client/                本地客户端程序源码（Go，含 TPROXY helper、netns-worker）
├── pkg/                   共享协议包（protocol、tlsutil、updater、version）
└── install/               一键安装/卸载脚本（Linux）
```

## 安全版本升级

- 旧服务端在升级前将明文 `panel_addr` 改为 `127.0.0.1`，并移除任何 HTTP `public_base_url`。如果配置了 fCaptcha，将实例改为 HTTPS 或暂时切换到内置验证。直连 HTTPS 面板需设置成对的 PEM 证书和私钥。
- 使用同机 HTTPS 反向代理时，保持后端监听回环，只把代理地址写入 `panel_trusted_proxies`，例如 `127.0.0.1/32`。代理必须覆盖 `X-Forwarded-Proto` 和 `X-Real-IP`。转发规则也要显式配置各自的可信代理 CIDR，才能采用代理提供的访客 IP。
- 新装的 Linux Server 和 Client 使用带 `-server`、`-client` 后缀的独立安装、配置和状态目录。服务端安装器可以保留旧服务端配置和数据库。客户端安装器遇到旧的共享目录服务单元会停止升级。迁移此类主机时，先审核旧客户端单元及其程序的来源和所有权，尤其是 `ExecStopPost`，然后停用旧单元并恢复旧网络设置。安装新客户端后重新注册，或从可信备份将客户端配置与凭据复制到 `/etc/opennofrp-client`。卸载按组件清理。默认保留配置和数据。
- Linux 客户端启用源 IP 保留前会先安装回环入口防护，并在磁盘记录策略路由、防火墙和 sysctl 改动。正常退出和 systemd 停止时使用同一套清理，启动时恢复上一次遗留的记录。默认使用策略路由表 `42141`、优先级 `12141` 与标记 `0x40000000`。
- 首个带发布证明的正式版本需要通过验证后的安装脚本或手工构建升级。新版本的安装与更新要求该证明存在。旧客户端若依赖 TOFU，证书指纹会保存到独立的 `server-pin.toml`，凭据撤销后仍保留。
- 正式部署前，在与生产分离的端口上确认 HTTPS、管理入口、控制通道和客户端网络恢复。Linux 本地安装脚本的服务健康检查失败时会恢复其旧二进制与单元。

## 状态

开发中已完成：
- ✅ 端到端 TLS 通道加密与 SHA-256 证书指纹绑定 (Certificate Pinning)
- ✅ 共享协议包、Client/Server 核心代码、TPROXY helper
- ✅ netns-worker 宿主/bridge 容器自动感知
- ✅ macOS 客户端（launchd 托管，普通转发版；源 IP 保留后续版本支持）
- ✅ 服务端一键点对点迁移（配置/数据库/证书打包，一次性令牌）
- ✅ 单体 Go 二进制 + SQLite + 内嵌 Web 控制面板（带证书指纹展示与更新提示）
- ✅ GitHub Actions 自动交叉编译多平台架构发布 (amd64 / arm64)
- ✅ 命令行一键检查与自更新 (`opennofrp-server update` / `opennofrp-client update`)
- ✅ 国内镜像加速自动回退与一键部署脚本优化
- ✅ HTTP 反向代理规则（按域名/路径共享端口、WebSocket/SSE、真实 IP 提取、自定义不可用页面）
- ✅ HTTPS（ACME 自动证书 / 自定义证书 / HTTP 自动跳转）与 TLS 透传（按 SNI 分流，不解密）
- ✅ HTTP 路由选项：剥离路径前缀、Host 改写、自定义请求/响应头、Basic Auth、IP 白名单、端口级 404 页面
- ✅ 规则级防护：IP 黑白名单、单 IP 并发与速率限制、规则带宽上限
- ✅ 可选 Proxy Protocol v1/v2、UDP 源 IP 保留、端口段规则
- ✅ 规则统计、Prometheus `/metrics`、REST API（`/api/v1/*`）与 API 令牌
- ✅ 面板安全：CSRF 校验、回环或 HTTPS 面板、登录会话持久化
- ✅ 客户端能力协商（旧版 Client 自动降级并在面板提示升级）
- ✅ CI：gofmt / go vet / go test -race / govulncheck / 多架构交叉编译

详细设计见 `docs/03-产品形态设计.md`。
