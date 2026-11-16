# sbnpm · 同域名 Reality Vision / Hysteria2 / TUIC

适用于 Debian 12/13、Ubuntu 22.04/24.04 等使用 APT 和 systemd 的 VPS。需要 sing-box 1.12 或更新版本。缺少核心时，安装器使用 sing-box 官方 APT 源安装。项目配置三个协议，可用 `sb` 打开中文管理菜单。

## 在 VPS 上安装

一句话从 GitHub 拉取安装，不用再手动传文件：

```bash
rm -rf /tmp/sbnpm-main /tmp/sbnpm.tar.gz &&
curl -fsSL https://github.com/980wl/sbnpm/archive/refs/heads/main.tar.gz -o /tmp/sbnpm.tar.gz &&
mkdir -p /tmp/sbnpm-main &&
tar -xzf /tmp/sbnpm.tar.gz -C /tmp/sbnpm-main --strip-components=1 &&
cd /tmp/sbnpm-main
```

之后按下面两种情况之一运行安装器。解压目录只用于运行安装器。安装程序在 `/opt/sbnpm`，配置在 `/etc/sbnpm`，systemd 单元在 `/etc/systemd/system`，快捷命令在 `/usr/local/bin`。重启后已启用的服务会随系统启动。

离线或无法访问 GitHub 时，可改用项目 ZIP：上传到 VPS 的 `/tmp`，解压后进入 `sbnpm` 目录（没有 `unzip` 时先运行 `sudo apt-get update && sudo apt-get install -y unzip`）。

### VPS 已运行 Docker 版 Nginx Proxy Manager

```bash
sudo bash install.sh --cert-mode npm --domain node.example.com
sb
```

把 `node.example.com` 换成已在 NPM 中启用 HTTPS 的实际域名。省略 `--domain` 可在交互终端选择检测到的域名。该域名的 DNS A/AAAA 应直达 VPS，使用 Cloudflare DNS 时请设为 DNS only。

安装器读取 Docker 的 `/etc/letsencrypt` 与 `/data` 挂载，扫描 `live/npm-*`、`custom_ssl/npm-*` 和生成的站点配置。可复用的证书须有匹配的 SAN、可信完整链和可读取的匹配私钥。NPM 的 Proxy Host 需实际用该域名提供 TLS 1.3。

### VPS 没有 NPM

```bash
sudo bash install.sh --domain node.example.com --email admin@example.com
sb
```

已有匹配的本机证书时优先复用。首次签发由 Certbot 使用 HTTP-01，需要 TCP 80 可绑定、从公网可达，并且 DNS 正确。后续由 Certbot 负责续期，sbnpm 定时同步。若检测到 NPM 但没有合格证书，默认模式会要求先在 NPM 中签发。

### 已有旧版项目或其他 `sb` 命令

从新版压缩包运行 `sudo bash install.sh` 可迁移旧版 sbnpm。原 UUID、Reality 密钥及主端口会沿用，升级后请重新导出客户端节点以更新 SNI。

如果终端里已有其他项目的 `sb`，默认使用 `sbnpm` 进入本项目菜单。如需让 `sb` 指向本项目，可运行以下命令。

```bash
sudo bash install.sh --claim-sb
hash -r
sb
```

已有的 `/usr/local/bin/sb` 会备份为 `/usr/local/bin/sb.pre-sbnpm`，卸载本项目时恢复。其他路径下的旧命令仍可通过原绝对路径执行。

## 同域名 Reality 如何连接

| 位置 | 默认示例 |
|---|---|
| VLESS 节点连接地址 | `node.example.com:8443` |
| 客户端 Reality SNI | `node.example.com` |
| 服务端 `reality.handshake.server` | `node.example.com` |
| 服务端握手实际连接 | 本机可达的 NPM HTTPS 入口，通常为 `127.0.0.1:443` |
| 无 NPM 时的握手入口 | 自带的回环 HTTPS 服务，默认 `127.0.0.1:18443` |

普通代理流量默认使用 VPS 的系统 DNS。sing-box 为握手单独解析域名。优先尝试 NPM 发布的 HTTPS 端口，并可尝试 Docker 网络中的容器地址。启动检查会用普通 TLS 客户端访问 Reality 主端口，以验证回落能拿到所选域名的有效证书。Reality 用自己的公私钥认证节点。Hysteria2 和 TUIC 加载从 NPM 或 Certbot 复制的证书。无 NPM 时，内置回环 HTTPS 服务也加载这套证书，提供 TLS 1.3 和 HTTP/1.1。

如果 NPM 的容器 IP 变化，选菜单 **7** 重新识别。也可手动指定入口。

```bash
sudo sbnpm refresh-origin --origin-address 127.0.0.1 --origin-port 443
```

Reality 主端口与备用端口不能与 HTTPS 握手入口使用同一个 TCP 端口。默认由 NPM 在 443 提供网站，Reality 在 8443 提供节点。网站与节点共用域名。

如需使用内置 HTTPS 源站的 IPv6 回环，可运行 `sudo sbnpm refresh-origin --local-origin-address ::1`。也可在安装时传入同一选项。`--origin-address` 用于已经运行的 HTTPS 入口。`--origin-port` 可单独指定内置源站端口。

已安装旧版时，解压新版后运行 `sudo bash install.sh` 更新脚本及源站服务文件，沿用现有安装信息。

## 查看运行版本与节点二维码

输入 `sb` 后，菜单顶部显示脚本版本 `v2.6` 及 systemd 主进程实际运行的 sing-box 版本。服务停止时显示「未运行」。选择 **2**，VLESS Reality、Hysteria2 和 TUIC v5 的主端口节点分别显示链接和二维码。用客户端的扫码导入功能扫描对应二维码。二维码包含与链接相同的节点凭据，在 VPS 上由 `qrencode` 生成。终端较窄时可加宽窗口；也可以复制链接导入。

```bash
sudo sbnpm nodes --qr
```

## 管理端口与跳跃间隔

输入 `sb`。菜单 **3** 更改主端口，**4** 管理多端口复用、Hysteria2 跳跃端口及端口跳跃间隔（秒），**5** 导出 Hysteria2 跳跃客户端配置，**6** 查看指定端口的固定节点。主端口和备用端口均可设为 1024–65535，Hysteria2 端口跳跃间隔支持 5–3600 秒（默认 30 秒）。

| 协议 | 默认主端口 | 备用端口行为 |
|---|---|---|
| Reality Vision | TCP 8443 | 多个 TCP 端口接入同一节点，客户端可选择固定端口 |
| Hysteria2 | UDP 24443 | 多个 UDP 端口接入同一监听，支持的客户端可按设定间隔自动跳跃 |
| TUIC v5 | UDP 24444 | 多个 UDP 端口接入同一节点，客户端可选择固定端口 |

数字端口可以同时用于 TCP 和 UDP。例如 TCP 30000 可给 Reality，同时 UDP 30000 给 Hysteria2。Hysteria2 和 TUIC 的 UDP 主端口及备用端口必须互不重叠。备用端口通过本项目独立的 nftables NAT 表转发，端口变更会检查现有监听和 Docker 发布端口。使用备用端口的 VPS 内核需支持 nftables NAT。若外部防火墙工具刷新整个规则集，可重启 `sbnpm` 恢复本项目规则。云安全组需放行客户端实际访问的端口和传输协议。本机防火墙对重定向后的流量需允许对应主端口。

```bash
sudo sbnpm ports reality --port 19443
sudo sbnpm ports reality --add '30000,30100-30102'
sudo sbnpm ports hy2 --add '30000,31000-31020' --hop-interval 15
sudo sbnpm ports hy2 --hop-interval 20
sudo sbnpm ports tuic --extra '32000-32002'
sudo sbnpm nodes --protocol reality --port 30000
sudo sbnpm hop-profile --format uri
sudo sbnpm hop-profile
```

最后两条分别输出 Hysteria2 多端口链接及 sing-box 客户端的单个出站对象。将 JSON 对象加入客户端配置的 `outbounds`，并按客户端设置选择该出站。多端口链接需客户端支持导入；普通固定节点可通过菜单 **2** 或 **6** 导出。节点链接和出站对象含认证信息，请妥善保存。

设置 Hysteria2 跳跃端口后，sbnpm 会把客户端出站对象保存到 `/etc/sbnpm/hysteria2-hop-outbound.json`（权限 `0600`，含节点密码）。文件中的 `server_ports` 包括主端口和所有跳跃范围，`hop_interval` 为所设定的秒数（默认 `30s`）。主端口、范围或跳跃间隔变更时会重写文件，仅修改跳跃间隔不会重启服务端进程，清空跳跃端口会删除文件。请把该对象加入客户端的 `outbounds`，或用菜单 **5** 导出跳跃链接。已导入的客户端配置需要重新导入或手动更新。

## Ubuntu / 内核 BBR 检测与节点传输协议自适应优化

安装时及在 `sb` 菜单选择 **12**（或运行 `sudo sbnpm optimize-bbr`）时，脚本会自动检测当前 Ubuntu/Debian 版本、Linux 内核版本及 `tcp_bbr` 模块代数（BBRv3 / BBRv2 / BBRv1），加载 `tcp_bbr` 与 `sch_fq`，写入 `/etc/sysctl.d/99-sbnpm-bbr.conf` 开启 BBR + `fq` 队列及 32MB QUIC UDP 缓冲队列，并根据 BBR 内核代数联动调优三协议传输配置：

| BBR 内核版本 | 内核 sysctl 调优 | Reality Vision (TCP) | Hysteria2 (QUIC) | TUIC v5 (QUIC) |
|---|---|---|---|---|
| **BBRv3** | `bbr`/`bbr3` + `fq`，`tcp_ecn=1`，32MB UDP 缓冲 | 启用 `tcp_fast_open` + `tcp_multi_path` | `bbr_profile="aggressive"`（1.14+）、`udp_fragment=true` | `congestion_control="bbr"`、`heartbeat="8s"`、`udp_fragment=true` |
| **BBRv2** | `bbr2`/`bbr` + `fq`，`tcp_ecn=1`，32MB UDP 缓冲 | 启用 `tcp_fast_open`，内核 ≥5.19 启用 `tcp_multi_path` | `bbr_profile="standard"`（1.14+）、`udp_fragment=true` | `congestion_control="bbr"`、`heartbeat="10s"`、`udp_fragment=true` |
| **BBRv1**（Ubuntu 22.04/24.04 默认内核） | `bbr` + `fq`，`tcp_ecn=2`（被动 ECN），32MB UDP 缓冲 | 启用 `tcp_fast_open`，Ubuntu 24.04+ / 内核 ≥6.1 启用 `tcp_multi_path` | `bbr_profile="standard"`（1.14+）、`udp_fragment=true` | `congestion_control="bbr"`、`heartbeat="10s"`、`udp_fragment=true` |
| **无内核 BBR**（受限容器） | 跳过受限 sysctl | 保守标准 TCP | `bbr_profile="conservative"`（1.14+） | 用户态 QUIC `bbr`、`heartbeat="15s"` |

## 晚高峰 UDP 抗 QoS 优化（菜单 13 / `udp-optimize`）

针对运营商在晚高峰对持续 UDP/QUIC 流量实施的 DPI 特征限速、单端口限流及高丢包，可在 `sb` 菜单选择 **13** 或通过命令行开启：

```bash
# 一键开启晚高峰抗限速预设（开启 Salamander 混淆 + 10s–20s 随机高频端口跳跃 + 内核 UDP 队列调优）
sudo sbnpm udp-optimize --preset peak

# 设置客户端晚高峰真实可用带宽（开启 Hysteria2 Brutal 恒定速率抗丢包，例如上行 50 Mbps / 下行 300 Mbps）
sudo sbnpm udp-optimize --up-mbps 50 --down-mbps 300

# 恢复默认标准 QUIC 模式
sudo sbnpm udp-optimize --preset reset
```

## 重新安装（沿用原域名或更换新域名，菜单 14 / `reinstall`）

在 `sb` 菜单选择 **14**（或执行 `sudo sbnpm reinstall`），可选择沿用原域名重新安装（重置所有节点 UUID、Reality 密钥对与密码）或更换为新域名重新安装。新配置启动检查失败时会自动回滚至原有运行配置。

```bash
# 沿用原域名重新安装并重置节点密钥
sudo sbnpm reinstall --keep-domain

# 更换新域名重新安装
sudo sbnpm reinstall --domain new.example.com
```

## 切换双栈 / 单栈监听模式（菜单 15 / `listen-mode`）

在 `sb` 菜单选择 **15**（或执行 `sudo sbnpm listen-mode`），可在保留全部节点 UUID、密钥和端口的前提下，一键在 **IPv4 + IPv6 双栈 (`::`)** 与 **仅 IPv4 单栈 (`0.0.0.0`)** 之间切换，并自动同步更新 nftables 备用端口转发规则。

```bash
# 切换为 IPv4 + IPv6 双栈监听
sudo sbnpm listen-mode ::

# 切换为仅 IPv4 单栈监听
sudo sbnpm listen-mode 0.0.0.0
```

## 状态与维护

```bash
sudo sbnpm status
sudo sbnpm optimize-bbr
sudo sbnpm list-domains
sudo sbnpm sync-cert
sudo journalctl -u sbnpm -u sbnpm-origin -n 80 --no-pager
sudo systemctl list-timers sbnpm-cert-sync.timer
```

配置变更先做检查，再启动并检查监听。启动失败时尝试恢复上一次配置与服务，首次启动失败时清理安装记录，可修正后重跑安装器。更改主端口或同步新证书会短暂中断现有连接。

### 原地更新 sing-box 核心

在 `sb` 菜单选择 **11**，核对当前版本和上游最新稳定版，再输入 `UPDATE`。也可运行 `sudo sbnpm update-core`。更新器从官方 GitHub 发布页获取 Linux amd64 或 arm64 构建，校验 SHA-256 和二进制版本，再用新核心检查当前配置。切换后会检查运行中的服务。启动或握手检查失败时，自动切回原核心。更新期间运行中的节点会短暂断开，节点配置和证书继续使用现有文件。

如果现有菜单缺少运行版本或节点二维码，解压新版 ZIP 并进入 `sbnpm` 目录，执行以下命令。

```bash
sudo bash install.sh --update-menu
sb
```

这个操作替换菜单脚本并在缺少时安装 `qrencode`，适用于已安装的 sbnpm。后续更新核心直接用菜单第 11 项。VPS 需能访问 GitHub API 和官方发布文件下载地址。

### 彻底卸载

在 `sb` 菜单选择 **10**，再输入 `REMOVE` 确认。也可运行 `sudo sbnpm remove`。卸载会停用本项目的服务与证书同步定时器，移除配置、节点密钥、证书副本、端口转发规则、BBR sysctl 配置文件、脚本及快捷命令。如果曾备份原来的 `sb`，卸载时会恢复。共享的 sing-box 核心、APT 软件源、NPM、Certbot 和原始证书会保留。服务账户只在有本项目创建记录且 UID/GID 仍匹配时删除，旧版安装的无记录账户会保留。

## 测试和参考
GitHub Actions 包含一项 Ubuntu VPS 模拟部署测试，使用真实 sing-box、systemd 和 nftables 检查安装、同域名 HTTPS 回落、端口变更及三协议连接。测试证书和配置仅在一次性运行环境中生成。

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
python3 -m py_compile sbnpm.py
```

- [Nginx Proxy Manager 官方 Docker 配置](https://nginxproxymanager.com/setup/)
- [sing-box 官方 APT 安装](https://sing-box.sagernet.org/installation/package-manager/)
- [sing-box TLS 和 Reality 配置](https://sing-box.sagernet.org/configuration/shared/tls/)
- [Hysteria2 端口跳跃](https://www.hy2.app/docs/advanced/Port-Hopping/)
- [sing-box-yg 参考项目](https://github.com/yonggekkk/sing-box-yg)

许可证为 MIT。
