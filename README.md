# OpenNoFrp

一个专注于"云服务器全端口映射到本地 + 保留客户端真实源IP"的轻量级内网穿透方案。

## 为什么不用现成的 frp？

frp 的 `remotePort` 转发在多层 NAT/Docker 网络环境下，本地服务收到的连接源 IP 会变成 frpc 所在机器的内网 IP（或 TCP 层面直接丢失原始客户端 IP），这在需要按 IP 做限流/封禁/统计的场景（如游戏服务器、Web 服务）里是硬伤。

OpenNoFrp 采用**本地 TPROXY 透明代理**方案，让本地服务**完全无需任何改造**（不要求支持 Proxy Protocol、不要求解析任何自定义协议头），`accept()`/`recvfrom()` 直接拿到的对端地址就是真实公网客户端 IP。详见 `docs/01-架构设计.md`。

## 设计约束（务必先读）

本项目的拓扑中有两类角色，安全约束完全不同：

- **云服务器端（Server）**：风险不可控。只做纯用户态收发字节 + 转发一小段自定义元数据（原始客户端 IP:端口），**永远不碰内核网络配置**——不使用 TUN/TAP、不使用 TPROXY、不修改 iptables/nftables/路由表/内核网络参数。原因：如果云服务器只能通过 SSH 管理且无带外手段，网络配置写错会导致永久失联。
- **本地 Client 端**：运行在你完全可控（可物理访问或至少有独立带外管理手段）的机器上，**会使用 TPROXY + `ip rule` 策略路由 + `IP_TRANSPARENT` socket**，这是实现"目标服务零改造、源 IP 保留"的必要技术手段。所有新增的 `iptables-legacy` 规则、路由表项、sysctl 参数改动都严格限定在本项目专用的命名空间内（专用表名/专用 fwmark），安装/卸载采用白名单精确增删，不做批量 flush。

详细的风险分级和回滚流程见 `docs/02-风险评估与回滚方案.md`；TPROXY 技术选型、Docker 兼容性边界见 `docs/01-架构设计.md`。

## Docker 容器兼容性

**`docker run -p` 标准端口映射（bridge 模式）无需任何改动即可保留真实源 IP**——OpenNoFrp Client 会自动检测目标端口属于宿主机进程还是某个容器，如果是容器，会用 `setns(2)` 让代理进程本身进入该容器的网络命名空间运行（即"netns-worker"），而不是要求你把容器改成 `--network host`。这个方案已经过真实 Go 代码端到端验证（含并发压测），完整技术细节和踩坑记录见 `docs/01-架构设计.md` 第六节。

## 目录结构

```
OpenNoFrp/
├── README.md              本文件
├── docs/                  详细设计文档、风险评估、部署手册
├── server/                云服务器端程序源码（Go）
├── client/                本地客户端程序源码（Go，含 TPROXY helper、netns-worker）
├── safety/                安全验证脚本（部署前置检查、连接可用性探测、自动回滚）
└── install/               一键安装/卸载脚本（Linux）
```

## 部署安全流程（强制，不可跳过）

1. `safety/preflight-check` —— 部署前置检查：探测目标端口是否被占用、探测 SSH 连接当前状态、生成回滚记录点
2. 在**全新的独立端口**上先部署一个最小可用实例（不接管任何现有流量）
3. 验证新实例工作正常、且不影响现有 SSH/frpc/frpc2/Docker 网络后，才允许你决定是否逐步迁移现有转发规则
4. 每一次服务器端变更都通过 `safety/watchdog` 脚本包裹：如果变更后 N 秒内本地探测不到服务器心跳，自动执行预先记录的回滚操作

## 状态

🚧 开发阶段。架构设计与 TPROXY 方案（含 host 模式和 Docker bridge 模式的 netns-worker 方案）已在隔离 KVM 虚拟机沙箱中用真实 Go 代码做端到端验证（详见 `docs/01-架构设计.md` 第六节）。已完成：共享协议包、Client/Server 核心代码、TPROXY helper、netns-worker 正式整合进 Client 主流程（`rulesync` 按目标端口自动检测运行模式：宿主进程 / host-network 容器 / bridge 容器 netns-worker）、环境自动检测、Linux 安装/卸载脚本、Go 单体二进制 + SQLite + 内嵌 Web 管理面板（规则增删改/启停端口、注册 Client/生成一键安装命令、保留端口白名单）。待办：UDP 源 IP 保留（当前 UDP 只做普通反向代理）、容器重启自动感知、Windows 客户端、按 netns 而非按端口管理 worker 生命周期。尚未在任何真实生产服务器上部署。
