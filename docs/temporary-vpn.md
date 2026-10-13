# 临时 VPN

管理员可在面板的「临时 VPN」页面授权临时访问某台内网机器的
`127.0.0.1` 全部 TCP / UDP 端口。接入设备访问 `10.203.0.1:<端口>`，
服务实际连接到选定内网 Client 的 `127.0.0.1:<同一端口>`。
不需要为每个端口创建公网隧道，目标地址固定为本机回环地址。

服务端和内网 Client 均需更新到包含此功能的版本。旧 Client 不会显示为可选目标。
这里的「本机」是 Client 进程所在网络命名空间；Docker 中运行 Client 时，
`127.0.0.1` 指容器本身，访问宿主机回环服务应使用 host 网络模式部署 Client。

## 使用

1. 选择在线目标机器，填写名称，选择有效期（15 分钟、1 小时、4 小时或 24 小时）。
2. 下载接入程序及本次生成的 `opennofrp-vpn.json`，放在同一目录。
3. Windows x64 使用管理员 PowerShell：

   ```powershell
   .\opennofrp-vpn-windows-amd64.exe -config .\opennofrp-vpn.json
   ```

   Windows ARM64 使用 `opennofrp-vpn-windows-arm64.exe`，Windows x86（32 位）使用
   `opennofrp-vpn-windows-386.exe`，运行方式相同。请优先使用与系统架构一致的版本。

   Linux x64 使用 root 权限（ARM64 替换文件名为 `opennofrp-vpn-linux-arm64`）：

   ```sh
   chmod +x opennofrp-vpn-linux-amd64
   sudo ./opennofrp-vpn-linux-amd64 -config ./opennofrp-vpn.json
   ```

4. 例如访问目标的 HTTP 服务 `127.0.0.1:8080`，浏览器打开 `http://10.203.0.1:8080`。
   SSH、数据库等也使用 `10.203.0.1` 和原服务端口。
5. 按 Ctrl+C 正常断开，或在面板撤销凭据。到期自动断开。

## 可选 HOST 别名

创建接入时可填写 `HOST 别名`，例如 `local`。程序在服务端认证成功、
虚拟网卡配置完成后，将 `local` 写入接入设备的系统 hosts 文件，指向 `10.203.0.1`。
之后可直接打开 `http://local:8080`，或使用 `ssh 用户名@local`。
配置中使用 `"hosts": ["local"]`；最多 8 个别名，面板使用逗号分隔。
留空时不修改 hosts，旧配置继续按原方式使用 IP 地址。

也可在启动时指定别名，覆盖配置中的 `hosts`：

```powershell
.\opennofrp-vpn-windows-amd64.exe -config .\opennofrp-vpn.json -host local
```

```sh
sudo ./opennofrp-vpn-linux-amd64 -config ./opennofrp-vpn.json -host local,dev.internal
```

程序不会覆盖已有的不同 IP 映射；遇到冲突会报错退出并清理本次创建的网卡。
已有相同 IP 的映射会保留。新条目带有每次启动独有的注释标记，正常退出、
到期或被撤销时，仅删除本次添加且未被别人修改的条目，不恢复整份旧文件。
拒绝使用 `localhost`、IP 地址、不合法的域名以及服务器控制地址作为别名。
写入保持原文件权限和所有者，Linux 支持绑定挂载的 hosts 文件。
Windows 写入及清理后刷新系统 DNS 缓存；Linux 不重启解析服务。
浏览器和应用自身的缓存可能需要重新打开连接。

强制结束进程或设备断电时无法保证清理；若条目残留，可在系统 hosts 中删除
对应 `# OpenNoFrp temporary VPN ...` 标记的行。Linux 为 `/etc/hosts`，
Windows 为系统目录下的 `System32\drivers\etc\hosts`。

Windows 接入程序内置官方 Wintun 0.14.1 对应架构（AMD64 / ARM64 / x86）的签名 DLL，首次运行解压到程序目录，
该目录需要可写；若已有不同内容的 `wintun.dll`，请放到单独目录再运行。
Linux 需要 `iproute2`、可用的 `/dev/net/tun` 和 root / 相应网络权限。
macOS、IPv6 及其它 IP 协议暂不支持。

只添加 `10.203.0.1/32` 的临时路由，不设置默认网关、DNS 或系统代理。
接入程序检查该地址是否已存在专用路由，冲突时拒绝启动；一次连接一台目标机器。
应确认现有网络没有使用该地址作为重要服务地址，再自行连接。
本功能不代理目标机器的其他内网 IP，也不会让只能访问 `localhost` 的应用自动改用虚拟地址。
目标服务自身的认证机制仍然适用。ICMP 回应来自接入程序的虚拟协议栈，不能代表目标服务健康。

## 凭据与连接

配置携带服务器控制端点、TLS 证书指纹、临时凭据和到期时间。
证书指纹固定校验，配置仅在创建后显示一次；数据库只保存临时凭据的 SHA-256 哈希。
凭据授予所选机器全部回环 TCP / UDP 端口的访问权限，应像密码一样保管。
同一凭据最多一个在线接入程序；服务端对每个接入最多允许 128 个并发端口流。
撤销及目标离线每秒检查，关闭接入会同时终止端口流。
UDP 流空闲两分钟后关闭，后续数据可重新建立流。

该功能使用独立 TLS + yamux 连接接入 Server，再复用 Server 与目标 Client 的已认证连接。
接入设备用 Wintun / Linux TUN 虚拟网卡和 gVisor 用户态 IPv4 TCP/IP 栈处理流量。
TCP / UDP 会由目标 Client 建立到回环服务的新连接；目标服务看到的来源是本机回环地址。

## 发布和托管

发布工作流生成 `opennofrp-vpn-windows-amd64.exe`、`opennofrp-vpn-windows-arm64.exe`、
`opennofrp-vpn-windows-386.exe`、`opennofrp-vpn-linux-amd64`、
`opennofrp-vpn-linux-arm64`，同时打入对应平台压缩包。
面板默认跳转到最新 GitHub Release 的同名文件，发布包含对应产物的版本前该链接不可用。
可把这些文件放进 Server 的 `client_bin_dir`，GitHub 无法访问时使用页面中的服务器备用下载。
备用入口为 `/vpn/download/<平台>?source=local`；未托管对应文件时返回 404。

Wintun 来自官方 <https://www.wintun.net/> 的 `wintun-0.14.1.zip`，
原始压缩包 SHA-256：`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`。
随附许可见 `vpn/internal/network/assets/WINTUN-LICENSE.txt`，发布包同样包含许可。
WireGuard Go / Wintun Go 绑定以及 gVisor 按各项目许可证使用（对应版本见 `go.mod`）。

自动测试使用模拟 TUN 和独立 TCP/IP 栈验证 TCP 收发及取消清理；
交叉编译覆盖 Windows AMD64 / ARM64 / x86。未进行真实网卡 / 路由变更测试。
