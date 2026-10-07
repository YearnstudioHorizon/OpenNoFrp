# OpenNoFrp

一个专注于"云服务器全端口映射到本地 + 保留客户端真实源IP"的轻量级内网穿透方案。

## 为什么不用现成的 frp？

frp 的 `remotePort` 转发在多层 NAT/Docker 网络环境下，本地服务收到的连接源 IP 会变成 frpc 所在机器的内网 IP（或 TCP 层面直接丢失原始客户端 IP），这在需要按 IP 做限流/封禁/统计的场景（如游戏服务器、Web 服务）里是硬伤。

OpenNoFrp 采用**本地 TPROXY 透明代理**方案，让本地服务**完全无需任何改造**（不要求支持 Proxy Protocol、不要求解析任何自定义协议头），`accept()`/`recvfrom()` 直接拿到的对端地址就是真实公网客户端 IP。详见 `docs/01-架构设计.md`。

## 快速开始与一键安装

### 1. 云服务器端 (Server) 一键部署
在 Linux 云服务器上执行以下命令（自动检测系统架构并拉取最新版本安装，后台自动注册为 systemd 守护进程）：
```bash
# 官方源直接安装
curl -fsSL https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash

# 国内网络加速安装 (推荐)
curl -fsSL https://mirror.yearnstudio.cn/https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash
```
> 安装完成后，终端将自动打印管理后台地址（默认 `http://<服务器公网IP>:8080`）、初始随机管理员密码与 TLS 证书指纹。

### 2. 内网客户端 (Client) 一键接入
浏览器打开云服务器后台登录，点击 **“接入新机器”**，控制台将自动生成一条内置一次性注册令牌与安全指纹的一键命令：
```bash
curl -fsSL "http://<服务器IP>:8080/install_client.sh?token=<TOKEN>&fingerprint=<FINGERPRINT>" | sudo bash
```
内网客户端无需任何手动配置，命令执行完毕即刻完成 TLS 安全通道握手并连接就绪。

## 安全与加密特性

- **端到端 TLS 加密信道**：服务端与客户端之间全量握手、心跳与转发数据流均基于 TLS 1.3/1.2 加密传输，杜绝明文窃听与公网嗅探。
- **SHA-256 证书指纹锁定 (Certificate Pinning)**：服务端自动生成长效自签名证书并导出 SHA-256 指纹；客户端严格校验对端指纹，防止中间人劫持 (MITM)。支持 TOFU (Trust On First Use，首次使用自动信任) 及面板一键安装命令自动附带指纹。
- **纯用户态云端**：云服务器端仅运行普通用户态网络转发，**永远不碰内核网络配置**（不修改 iptables/路由表/sysctls），避免误操作失联。
- **受控客户端隔离**：客户端具备目标地址边界防御，严格限定本地回环转发，阻断内网跳板渗透。

## 在线更新与国内加速镜像

### 1. 一键检查与在线自更新 (Self-Update)
无需手动重新下载二进制，随时随地在终端一键升级至 GitHub 最新版本：
```bash
# 服务端一键自更新
sudo opennofrp-server update

# 客户端一键自更新
sudo opennofrp-client update
```
Web 管理面板首页也集成了“检查更新”功能，可实时获取 GitHub 最新发行公告。

### 2. 国内 GitHub 加速镜像
针对国内部分服务器或本地网络访问 GitHub 缓慢、连接超时的情况，可在任何 GitHub 链接（包括 Releases 下载文件、raw 源码等）前加上镜像加速前缀：
```
https://mirror.yearnstudio.cn/
```
示例：
- 官方链接：`https://github.com/YearnstudioHorizon/OpenNoFrp/releases/download/v0.1.2/opennofrp-client-linux-amd64`
- 加速链接：`https://mirror.yearnstudio.cn/https://github.com/YearnstudioHorizon/OpenNoFrp/releases/download/v0.1.2/opennofrp-client-linux-amd64`

> [!NOTE]
> **自动回退保障**：客户端的一键安装脚本及 `update` 自更新命令已内置双重保障。当直连 GitHub 官方源超时或失败时，会**自动无缝切换**至 `mirror.yearnstudio.cn` 镜像下载，无需人工干预。

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

## 部署安全流程（强制，不可跳过）

1. `safety/preflight-check` —— 部署前置检查：探测目标端口是否被占用、探测 SSH 连接当前状态、生成回滚记录点
2. 在**全新的独立端口**上先部署一个最小可用实例（不接管任何现有流量）
3. 验证新实例工作正常、且不影响现有 SSH/frpc/frpc2/Docker 网络后，才允许你决定是否逐步迁移现有转发规则
4. 每一次服务器端变更都通过 `safety/watchdog` 脚本包裹：如果变更后 N 秒内本地探测不到服务器心跳，自动执行预先记录的回滚操作

## 状态

开发中已完成：
- ✅ 端到端 TLS 通道加密与 SHA-256 证书指纹绑定 (Certificate Pinning)
- ✅ 共享协议包、Client/Server 核心代码、TPROXY helper
- ✅ netns-worker 宿主/bridge 容器自动感知
- ✅ 单体 Go 二进制 + SQLite + 内嵌 Web 控制面板（带证书指纹展示与更新提示）
- ✅ GitHub Actions 自动交叉编译多平台架构发布 (amd64 / arm64)
- ✅ 命令行一键检查与自更新 (`opennofrp-server update` / `opennofrp-client update`)
- ✅ 国内镜像加速自动回退与一键部署脚本优化
- ✅ HTTP 反向代理规则（按域名/路径共享端口、WebSocket/SSE、真实 IP 提取、自定义不可用页面）
- ✅ HTTPS（ACME 自动证书 / 自定义证书 / HTTP 自动跳转）与 TLS 透传（按 SNI 分流，不解密）
- ✅ HTTP 路由选项：剥离路径前缀、Host 改写、自定义请求/响应头、Basic Auth、IP 白名单、端口级 404 页面
- ✅ 规则级防护：IP 黑白名单、单 IP 并发与速率限制、规则带宽上限
- ✅ 多后端负载均衡与故障转移（轮询/随机/主备 + TCP 健康检查）
- ✅ 可选 Proxy Protocol v1/v2、UDP 源 IP 保留、端口段规则
- ✅ 规则统计、Prometheus `/metrics`、REST API（`/api/v1/*`）与 API 令牌
- ✅ 面板安全：CSRF 校验、可选面板 HTTPS、登录会话持久化
- ✅ 客户端能力协商（旧版 Client 自动降级并在面板提示升级）
- ✅ CI：gofmt / go vet / go test -race / 多架构交叉编译

详细设计见 `docs/03-产品形态设计.md`。
