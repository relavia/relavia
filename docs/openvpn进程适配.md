# OpenVPN 独立进程适配（阶段 2 承接工程项）

结论先行：**OpenVPN 进程适配器已交付（`core/openvpn`），VPN Gate 节点的准入代码路径已从 `tcp-connect` 升级出 `handshake-verified` 级别。** 本机自起的真实 OpenVPN 服务端上，适配器完成了完整 TLS 握手并到达管理接口 CONNECTED（证据见第 3 节，含分级与卡点原文）。两项仍未达成且不预称：经真实 TUN 设备的负载流量（沙箱封 TUN 创建与 UDP，原文证据在案）、对真实 VPN Gate 服务器的公网实握（公网验收项）。app 服务层的协议分发接线（UI 连接路径）是下一步（第 7 节），本步交付的是引擎级连接能力与准入路径。

## 1. 形态与许可证边界

- 集成形态按 Step 2 许可证审计裁定 F-1：OpenVPN 2.x 为 **GPL-2.0-only**，只能以**独立可执行文件**随附分发、臂长协作（配置文件 / 命令行 / 管理接口），**绝不链接进 GPLv3 主二进制**，不改其源码入仓。本包不含任何 OpenVPN 代码，只实现驱动协议。
- 适配器实现 `kernel.Adapter` 同一接口（未改接口本身），并与 sing-box 适配器同构地提供全保真入口 `StartNode / ValidateSpec / TestHandshakeNode`（统一模型 `specnode.Node` 直入）。占位模型路径（`Start/ValidateConfig/TestHandshake`）经 `specnode.FromKernel` 转换：占位模型装不下配置全文与证书，该路径会以精确的 invalid_config 拒绝 OpenVPN 全文节点（与 Step 7 对 WireGuard/OpenVPN 的口径一致），绝不近似生成错误配置。
- 版本下限 **2.5.0**：适配器依赖协商数据密码（`--data-ciphers`，2.5+）与稳定的管理接口行为；低于下限的二进制被显式拒绝并给出升级指引，不带病驱动。

## 2. 设计

### 2.1 二进制定位（locate.go）

搜索顺序即契约（捆绑形态优先，保证发行包行为一致）：显式 `Options.BinaryPath`（权威、失败不绕）→ 应用目录 `openvpn/`、`bin/`、目录本身（捆绑官方二进制的位置）→ `SearchDirs` → PATH。命中后实跑 `--version` 解析横幅并校验下限。缺失/过旧一律 `KindPlatformUnavailable` + 用户可执行的文案（找了哪些路径、装什么版本、或用捆绑包），**无静默降级、无模拟握手**。`Capabilities().Platform.TUN` 以「可定位到二进制」为真值来源——没有进程就没有隧道，不谎报。

### 2.2 配置生成（genconfig.go）

- **全文模式（VPN Gate 形态）**：`.ovpn` 原文透传，仅做受控改写。下表指令一律剥离/改写并记录进 `rewritten` 诊断列表：管理接口全家（`management*`，端点归适配器）、守护与重定向（`daemon/syslog/log/status/writepid`，输出归适配器捕获）、提权面（`user/group/chroot/setenv*`）、**一切执行钩子（`plugin`、`up/down/route-up/ipchange/tls-verify/auth-user-pass-verify/client-connect/client-disconnect/learn-address` 等）——节点数据不得借配置体获得代码执行**（与 Step 14 插件自律同源）。`auth-user-pass <file>` 改写为裸形式（凭据改走管理接口问答，不落文件）。
- **结构化模式**：按字段拼装（`client/dev tun/proto/remote/remote-cert-tls server`、cipher/data-ciphers/auth、`<ca>/<cert>/<key>/<tls-auth>/<tls-crypt>` 内联块、`key-direction`、redirect-gateway/block-outside-dns、`auth-user-pass`）。`proto tcp→tcp-client`（tcp4/tcp6→tcp4-client/tcp6-client）；无 CA 证书直接 invalid_config（TLS 无从验证，openvpn 本身也会拒）。
- 两种模式统一在文末追加适配器管理块（端点 + `management-query-passwords`，有凭据时加 `auth-nocache`）；OpenVPN 对多数指令取最后出现者，管理块必胜。
- 生成文件只存在于每会话私有目录（0700 / 文件 0600），会话结束整目录删除。密码从不写入配置文件（结构化模式单测断言）、不进 argv。

### 2.3 管理接口（mgmt.go）

行协议客户端：单读协程分流实时通知（`>STATE/>BYTECOUNT/>PASSWORD/>HOLD/>FATAL`）与命令应答（END / SUCCESS / ERROR 终止）。用途：CONNECTED 状态通知（Start/TestHandshake 的唯一成功判据，不靠日志猜测）、BYTECOUNT 计数（`QueryTraffic` 数据源，in=下行/out=上行）、凭据问答（`username/password "Auth"`，带转义；节点无凭据而服务端索要时立即分类失败）、hold release、私钥口令请求（统一模型无该字段 → 显式失败码 `private_key_password_required`，不假装支持）、`signal SIGTERM` 优雅停机。

端点形态：unix 平台用会话目录内 unix 域套接字（文件权限即访问控制）；Windows（`!unix`）用回环 TCP + 随机口令文件（0600）——无认证的管理端口即使在回环上也会把隧道控制权交给任意本地进程，故口令强制。

### 2.4 进程监督与失败分类（process.go）

- 子进程独立进程组（unix），停止路径：管理 SIGTERM → 进程组 SIGTERM → SIGKILL，`Wait` 回收后才返回（防僵尸）；运行中被监视协程盯住 `done`，异常退出立即把适配器置 `StateFailed` 并保留分类原因（UI 与断网保护层据此反应，隧道不静默消失）。
- 输出双路捕获后**脱敏**（节点用户名/口令原文替换为 `***`）才进应用日志；同时扫描硬失败模式与管理状态共同喂分类器（首个分类为准）。分类码（稳定字符串，经 `openvpn.CodeOf` 取回；握手结果里以消息前缀承载）：

| 码 | 含义 | kernel Kind |
|---|---|---|
| `auth_failed` | 服务端拒绝凭据（AUTH_FAILED / auth-failure） | handshake_failed |
| `auth_credentials_missing` | 服务端索要凭据而节点没有 | handshake_failed |
| `private_key_password_required` | 客户端私钥带口令（本适配器不支持） | handshake_failed |
| `tls_verify_failed` | 服务端证书验证失败 | handshake_failed |
| `tls_handshake_failed` | TLS 握手失败 | handshake_failed |
| `connection_failed` | 连接层失败 | handshake_failed |
| `tun_unavailable` | TUN/TAP 设备打不开（设备/权限） | platform_unavailable |
| `config_rejected` | openvpn 拒绝配置（Options error） | invalid_config |
| `connect_timeout` | 超时未见 CONNECTED | timeout |
| `management_failed` | 管理接口未起来（测试本身无法进行，作 Go error） | network |
| `process_exited` | 进程提前退出/致命错误 | network |

- 握手等待有界（默认 45 s）：野生配置常带 `resolv-retry infinite` 等无限重试，等待上限在本适配器，不在子进程；认证/TLS 类硬失败不等重试、立即返回。

### 2.5 与 Step 12 断网保护的衔接

分工不变（与 sing-box 适配器同一口径）：断网保护执行器管「非隧道出口阻断」，本适配器管「隧道进程」。落点：① `Options.KillSwitchReport` 实时咨询执行器报告——仅 `ReadinessEnforceable` 时能力矩阵才报 KillSwitch=true，且 Start 被请求 KillSwitch 而不可执行时以 platform_unavailable 拒绝（不裸奔）；② 隧道进程死亡 → 适配器即时 `StateFailed`+分类原因，应用层 Controller 据引擎状态收紧阻断（与 singbox 的 killswitch 钩子同一机制）；③ 路由由子进程随其 TUN 设备生灭——进程死，推送路由随设备消失，不存在残留路由绕过执行器；适配器自身从不添加任何兜底/旁路路由。④ Stop 在进程回收完成后才返回，应用层不存在「以为已断、进程犹存」的窗口。

### 2.6 能力矩阵口径

矩阵只含 OpenVPN 一行（native/tcp/udp 传输，TLS 与静态密钥两类安全层，UDP 可承载）。平台：TUN=二进制可定位；SystemProxy=false（进程隧道无此形态，Start 显式拒绝该模式并指明由 sing-box 适配器承担）；IPv6=false（保守：适配器自身不供给 IPv6，全文配置自带者不在此承诺内）。

## 3. 握手实证（分级，如实标注）

沙箱能力探测（2026-11-13，本机实测，原文）：

- openvpn：apt 索引基本不可用（多数镜像 Ign），改由官方 Ubuntu 归档直拉 `openvpn_2.6.9-1ubuntu4_amd64.deb` 解包运行（归档 SHA256 与索引登记值比对一致：`73bb9039c930d2…`）；版本 2.6.9 / OpenSSL 3.0.13。
- UDP：回环 `sendto` 即 `Operation not permitted`（Errno 1）——沙箱在系统调用层封 UDP（与 Step 7/11 既有证据一致）。
- TUN：`/dev/net/tun` 节点存在，但 `TUNSETIFF` ioctl 返回 `Operation not permitted`；`mknod` 亦被拒。**真实 TUN 设备在本沙箱不可创建。**
- 对策（OpenVPN 自家测试台同款形态）：服务端与客户端均用 TCP + `dev null` + `ifconfig-noexec/route-noexec`。TLS 握手、证书认证、tls-auth HMAC、数据通道密钥协商全部真实执行；null 设备不承载负载流量。

证据分级：

| 级 | 内容 | 状态 |
|---|---|---|
| L0 | 配置生成/改写/脱敏（单测 6 项，含 VPN Gate 形态样本的剥离断言、结构化金丝雀、口令不入配置断言） | ✅ 本机 |
| L1 | 管理接口协议（进程内假服务端：状态/计数/口令问答转义/hold/FATAL，单测 4 项） | ✅ 本机 |
| L2 | 进程生命周期与失败分类（假二进制：缺失显式失败、AUTH_FAILED 分类、管理接口超时回收，单测 11 项含定位 5 项） | ✅ 本机 |
| L3 | **适配器级真实握手**： rig 测试自起真实 OpenVPN 服务端（Go 生成测试 CA，服务端证书带 serverAuth EKU、客户端 clientAuth），适配器 `TestHandshakeNode` 实握成功（延迟 4.29 s，含进程启动与 openvpn 连接节奏）、`StartNode` 到达 running、管理接口状态原文 `CONNECTED,SUCCESS,10.8.0.2,…`、客户端日志 `Initialization Sequence Completed` + `Data Channel: Cipher 'AES-256-GCM' initialized`；反例（错 CA）分类为 `tls_verify_failed` 的 handshake_failed 结果 | ✅ 本机（rig PASS，10.9 s；CI 由新增 `openvpn-rig` 作业复跑） |
| L3+ | 计数校验：Start 会话期间管理 BYTECOUNT **非零且双向移动**（up=3000 / down=2963 字节）——已建立的 AES-256-GCM 数据通道上 keepalive 流量被计数，证明计数链路贯通而非恒零摆设 | ✅ 本机 |
| L4 | 经真实 TUN 设备的**负载**转发与路由生效 | ❌ 环境封死（TUNSETIFF/UDP 的 EPERM 原文如上）——真机/特权环境验收项，脚本即 rig（`RELAVIA_OPENVPN_RIG_DEV=tun` 切换即可在有 TUN 的环境复跑同一测试） |
| L5 | 对真实 VPN Gate 服务器的公网握手与连接 | ❌ 公网验收项（沙箱出网受限），未做、不预称 |

CI：新增独立作业 `openvpn-rig`（装发行版 openvpn 后以 `RELAVIA_OPENVPN_RIG=1` 跑 rig），不改动任何既有作业语义；本轮 CI 基线正在跑，该作业待推送后以其实跑结论为准。

## 4. VPN Gate 准入升级（Step 14 出入 1 的关闭）

- 级别枚举新增 `handshake-verified`（`plugins/vpngate/probe_handshake.go`）：严格高于 `tcp-connect` 与 `none`，只有经适配器到达管理 CONNECTED 才可获得。
- `HandshakeProber.ProbeHandshake`：TCP 节点先走原 TCP 探针预筛（不可达不启进程）；UDP 节点直达握手；握手失败时保留已达级别并在 Detail 里写明分类码，**引擎缺失/未接线时明确报错、绝不降级冒充可达性结论**。
- Step 14 文档 §6 已加追记；插件 README 测活条目已同步。**公网口径不变**：在 L5 验收通过前，UI 仍须把 VPN Gate 节点标注为「可导入、可测活」，不得宣称已可连接——引擎级可连接 ≠ 公网实证可连接。

## 5. 发行形态（Windows 捆绑清单）

- 捆绑官方 OpenVPN 社区版二进制（安装包取自官方发布通道，GPG/签名校验）置于应用目录 `openvpn/`（适配器搜索首位）；版本 ≥2.5.0，逐项登记（版本、来源、SHA-256）在 `THIRD_PARTY_NOTICES.md` 新增的「OpenVPN / Wintun 捆绑登记」表，任一栏空不得出包。
- 随附 OpenVPN 的 COPYING 与 GPLv2 全文及对应源码获取途径；保留商标归属说明，不暗示 OpenVPN Inc 背书。
- Wintun 只用 wintun.net 官方未修改签名 DLL（校验和登记同表），随附 Prebuilt Binaries License；**因含该专有 DLL 与 OpenVPN 二进制，发行包不得宣称「100% 开源」**，官网与包内明示（可复现构建例外项同 Step 15 口径）。
- macOS/Linux 不捆绑：依赖系统包管理器 OpenVPN，适配器 PATH 兜底定位；下载页注明依赖。

## 6. Android 路线（仅评估，不写代码）

现代 Android 上外部进程路线不可行：应用不能执行自带二进制（targetSdk 的 W^X 与 SELinux 域限制），openvpn 可执行文件无从落地。可行路线只有进程内 JNI 库一条，候选与评估要点：

- **OpenVPN 3 核心库（首选候选）**：纯客户端库，官方以 AGPL-3.0 / MPL-2.0 双许可分发（Step 2 审计 §2.3）；取 MPL-2.0 一侧与 GPLv3 路线兼容，但**采用前必须对仓库 LICENSE 原文做专项复核**（审计既定前置）。其 ClientAPI 自带 TunBuilder 抽象——可直接对接 VpnService 的 fd 与 protect() 语义（与 libbox 绑定的桥形态同构，可复用 Step 10/12 的衔接点设计）。
- **ics-openvpn 路线（排除）**：其 OpenVPN 2.x JNI 形态整体 GPLv2，与 GPLv3 应用同进程组合触碰 Step 2 审计红线，不采用。
- 工程评估要点（立项时逐项过）：NDK/CMake 工具链与 AAR 体积（asio 等依赖）、TunBuilder 的 DNS/路由回推完整性、与 Step 12 lockdown 的合流点（同 libbox 的 `LockdownBridge` 位置）、上游维护节奏与安全公告跟踪、GPLv3 对应源码义务（组合体开源即满足）。

## 7. 未完成 / 待验清单

1. **L4 真机/特权环境**：真实 TUN 负载转发、推送路由/DNS 生效、断网保护联动实测（rig 已备 `RELAVIA_OPENVPN_RIG_DEV=tun` 开关）。
2. **L5 公网**：真实 VPN Gate 节点握手与连接（抽若干 TCP/UDP 节点，含其 `resolv-retry infinite` 配置在适配器超时口径下的行为复核）。
3. **app 服务层接线（下一步）**：`app/service` 现只有 sing-box 引擎；需按节点协议分发的路由引擎（openvpn 节点 → 本适配器，其余 → sing-box），并把 `HandshakeProber` 接入 VPN Gate 列表的准入刷新。完成后 UI 才可按 L5 结果改标注。
4. **Windows 真机**：捆绑二进制定位顺序、Wintun 在场时的 TUN 建立、管理端口（TCP+口令形态）实测——本步的 `!unix` 端点代码仅经交叉编译验证，未在 Windows 实跑。
5. 加密客户端私钥（口令保护）不支持：统一模型无私钥口令字段，如需支持须先走模型 RFC。
6. UDP 节点在公网的握手行为（本沙箱 UDP 全封，rig 只有 TCP 证据）随 L5 一并验。
