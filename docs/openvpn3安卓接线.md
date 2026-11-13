# OpenVPN 3 安卓接线：设计与实现（阶段 3）

- 目标：安卓端能连接 OpenVPN 节点（主要是 VPN Gate 池节点），走完「同意 → 建隧道」编排；语义与桌面进程适配器一致。
- 前置：许可证门（`docs/openvpn3许可证审查.md`，取 MPL-2.0 侧）、构建尖峰（`docs/openvpn3构建尖峰.md`）。
- 一句话架构：**会话由安卓原生侧承载**（OpenVPN 3 核心编入 `libovpn3android.so`，其 TunBuilder 回调对接既有 `RelaviaVpnService` 的 VpnService.Builder）；**Go 服务层保持唯一调度**：DispatchEngine 的安卓 OpenVPN 槽位从 `UnavailableEngine` 换成经桥接调原生侧的 `ovpn3Engine`，槽位语义（CanConnect / Start / Stop / Status / 测活）与桌面分发同口径。

## 1. 分层与文件

```
UI（不变） ── svc.Connect/TestHandshake ──▶ DispatchEngine
                                              │ openvpn 槽位
                                       ovpn3Engine（app/libboxbind）
                                              │ ① 同意：platform.BridgeVPNService.Prepare
                                              │ ② 渲染：openvpn.RenderProfile（core 共享构建器）
                                              │ ③ 桥：Ovpn3Bridge（gomobile 接口，Kotlin 实现）
                                              ▼
                        Ovpn3BridgeImpl ──▶ RelaviaVpnService（ACTION_OVPN3_START）
                                              │ Ovpn3Client : ClientAPI_OpenVPNClient
                                              │   （核心类即 TunBuilder 本身）
                                              ├─ socket_protect ──▶ VpnService.protect(fd)
                                              ├─ tun_builder_establish ──▶ Builder.establish() → fd
                                              └─ event/log ──▶ Libboxbind.notifyOvpn3* ──▶ ovpn3Engine
```

| 文件 | 角色 |
|---|---|
| `core/openvpn/render.go`（新） | 导出 `RenderProfile`：复用桌面同一套 profile 构建器（全文本透传的受控改写 / 结构化拼装），但不带进程适配器的 management 块；凭据以独立字段返回，永不写进 profile 文本。附带 `builtConfig.authRequired` 新字段（透传模式下 auth-user-pass 存活但节点无凭据时，桌面靠 management 问答兜底，本路径无 management，必须在渲染期以 `auth_credentials_missing` 拒绝）与 `WrapClassified`（把稳定错误码包进 *kernel.Error 使既有 `CodeOf` 可解包） |
| `app/libboxbind/ovpn3.go`（新） | `Ovpn3Bridge` 接口（Kotlin 实现）+ 注册表 + Kotlin→Go 事件汇（`NotifyOvpn3Event/Traffic/Log`，与既有 `NotifyTunRevoked` 同构） |
| `app/libboxbind/ovpn3engine.go`（新） | 桥接引擎：实现 `service.Engine` 全口（Capabilities / ValidateSpec / StartNode / Stop / Status / TestHandshakeNode / QueryTraffic / MixedAddr）+ `ConnectAvailable`（供 DispatchEngine.CanConnect 真实口径） |
| `app/libboxbind/session.go`（改 1 处） | 装配：安卓 OpenVPN 槽位 `NewAndroidOpenVPNEngine()` → `newOvpn3Engine(logSink)`。`app/cmd/relavia-android` 是无壳逻辑构建，仍用诚实不可用槽位（正确：那里没有原生侧可注册） |
| `android/openvpn3/`（新） | 构建胶水（尖峰文档 §1） |
| `android/.../Ovpn3Client.kt`（新） | 核心会话驱动：eval → provide_creds → 阻塞 connect；TunBuilder 累积参数；event/log 转发 Go |
| `android/.../Ovpn3BridgeImpl.kt`（新） | 桥的 Kotlin 实现 + 单会话控制器；`registerIfAvailable()`：`System.loadLibrary("ovpn3android")` 成功才注册——.so 不在包里时引擎保持诚实不可用 |
| `android/.../RelaviaVpnService.kt`（增量） | 实现 `Ovpn3TunHost`：从 TunSpec 建 Builder、出 fd、protect、关闭；`ACTION_OVPN3_START/STOP` 两条新意图；会话线程 + 每 2 秒流量轮询转发；onRevoke/onDestroy/ACTION_STOP 均联动 requestStop |
| `android/.../ShellBridgeImpl.kt`（改 1 处） | `ShellRuntime.ensureStarted` 在注册 ShellBridge 后挂 `Ovpn3BridgeImpl.registerIfAvailable()` |

UI 零改动：连接按钮本来就按 `CanConnect` 真实口径放行/禁用——桥注册成功（.so 在包内）后池节点在安卓自动变为可点连接，桥缺席时保持原诚实禁用与原因文案。

## 2. 编排序列（连接一个池节点）

1. UI `svc.Connect(nodeID)` → Service.mu 串行 → DispatchEngine 按节点协议选 ovpn3Engine（CanConnect = 桥已注册）。
2. 引擎 `start`：状态置 starting → **同意**：`platform.BridgeVPNService{}.Prepare`（壳的同意闩：已有同意直接过，未有则 ConsentActivity 拉系统 VPN 对话框；拒绝 → `android.ErrPermissionDenied` 原样上抛，UI 既有文案）。刻意在原生会话之前：核心的 TunBuilder establish 在服务内发生时同意已就位，不会在核心线程里卡系统对话框。等待用脱离调用方取消的上下文 + 既有 `tunStartTimeout` 上限（人读对话框的时间不吃连接超时）。
3. **渲染**：`openvpn.RenderProfile`（与桌面同一构建器：剥离 daemon/management/脚本钩子等不安全指令并记录 rewritten；凭据不入文本）。auth 需求无凭据 → 此步以 `auth_credentials_missing` 拒绝，不惊动原生侧。
4. **过桥**：`bridge.StartOvpn3Session(text, username, password)` → Kotlin 存 pending + `startForegroundService(ACTION_OVPN3_START)` → 服务起会话线程：`Ovpn3Client.runSession`：`eval_config`（失败 → 合成致命事件 PROFILE_ERROR 回 Go）→ 有用户名则 `provide_creds` → 阻塞 `connect()`。
5. 核心回调：`socket_protect` → `protect(fd)`（核心自身套接字绕隧道，防自环）；服务器推参数 → TunBuilder 累积 → `tun_builder_establish` → 服务 Builder（地址/DNS/路由/reroute/MTU）→ `establish()` → fd 回核心，隧道成立。
6. 核心发 `CONNECTED` 事件 → Kotlin 转发 `notifyOvpn3Event` → 引擎等候通道命中 → 状态 running，StartNode 返回。服务侧每 2 秒 `transport_stats()` → `notifyOvpn3Traffic(bytesOut, bytesIn)` → 引擎计数（QueryTraffic 真实口径，UI 已连接屏的「本会话流量」卡自此在 OpenVPN 会话下有真数据；无会话时计数为零值开始时间，不编造）。
7. 断开：UI/通知断开 → 引擎 Stop → `bridge.StopOvpn3Session` → 控制器 `client.stop()` + STOP 意图兜底 → 核心收尾发 DISCONNECTED、会话线程退出、服务 stopTunnelLocal。系统撤销（onRevoke）→ requestStop 联动，引擎侧经 DISCONNECTED/状态查询感知，不留假「已连接」。
8. 超时与失败：引擎等 CONNECTED 的上限 = `openvpn.DefaultConnectTimeout`（45 秒，与桌面同值）→ 到期停核心并以 `connect_timeout` 分类失败；致命事件即时分类（下节表）。

## 3. 错误口径（与桌面稳定错误码对齐）

原生事件名/信息 → `classifyNativeEvent` → `openvpn.WrapClassified(码, *kernel.Error)`，`openvpn.CodeOf(err)` 可解包，UI/日志与桌面同一套码：

| 原生侧信号 | 稳定码 | kernel.Kind |
|---|---|---|
| PROFILE_ERROR / 含 CONFIG | `config_rejected` | invalid_config |
| AUTH_FAILED | `auth_failed` | handshake_failed |
| 含 TIMEOUT | `connect_timeout` | timeout |
| 含 VERIFY / CERT | `tls_verify_failed` | handshake_failed |
| 含 TLS / SSL | `tls_handshake_failed` | handshake_failed |
| 含 TUN / ROUTE | `tun_unavailable` | platform_unavailable |
| 等待超时（引擎侧） | `connect_timeout` | timeout |
| DISCONNECTED 先于 CONNECTED | `connection_failed` | network |
| 其余致命事件 | `connection_failed` | network |
| 桥未注册（.so 不在包内） | ——（`UnavailableEngine` 同语义） | platform_unavailable |
| 同意被拒 | `android.vpn_permission_denied`（既有） | （既有分类） |

渲染期另有：`auth_credentials_missing`（invalid_config）、节点非 OpenVPN/协议不支持（unsupported）——均与桌面 ValidateSpec 同口径。

## 4. 测活语义

`TestHandshakeNode`：进程内核心没有「只握手不建隧道」的廉价探针，测活即一次真会话（连上 CONNECTED 即测得延迟，随即 Stop）——这与桌面 rig 用 management CONNECTED 作证的形状一致，`handshake-verified` 准入等级在安卓上含义不打折。用户会话进行中测活显式拒绝（wrong_state 结果，不打扰在用隧道）；桥缺席时返回 platform_unavailable 结果（失败是结果不是 Go error，遵 kernel.HandshakeResult 契约）。

## 5. 测试与编译门（本分支实测）

- Go：`core/openvpn` render 测试 5 项（透传安全改写与桌面同源、无 management 残留、凭据不入文本、无凭据分类拒绝、proto 判定、拒绝非 OpenVPN 节点）；`app/libboxbind` 引擎测试 7 项（假桥 + 假同意绑定器：无桥诚实不可用、同意→CONNECTED 全程与凭据隔离、同意拒绝、AUTH_FAILED 分类、测活自拆、ValidateSpec/凭据门、45 秒上限可注入缩短后的超时分类与停核心）。core 与 app 两模块全量测试绿（2026-11-14）。
  - 观察记录：`core/openvpn` 桌面 rig 的 `TestAuthFailureClassification` 在本机约 1/10 偶发（management 就绪竞速），基线 `ac71db3` 同测同概率（各 9/10），与本次改动无关（生成配置文本逐字未变，genconfig 全套测试为证）；与既有 `TestDownloadCanceledLeavesNothing` 同列偶发清单。
- Kotlin：手工等价流水线编译门通过——kotlinc 把壳全部 Kotlin 源 + Gio vendored Java 对 `android.jar`(34) + **真实 SWIG 生成 Java 类** + libboxbind/androidx 存根（仅本地校验用，不入库）联合编译，零错误，Ovpn3* class 全产出。真实 Gradle 构建随合并后 CI android 作业验证。
- 宿主机原生侧：尖峰 E1–E5（SWIG 生成、javac、核心链接、JNI .so 构建、JVM 加载 eval 冒烟）全过（尖峰文档 §2）。

## 6. 残余与边界（如实，未验不冒充）

- **真机端到端未验**：真机上 .so 加载、同意对话框、池节点真实连接、流量计数、断开/撤销回收——全部等用户真机门；公网 VPN Gate 实握（L5）同理。本分支只把路修到「可点连接并走完编排的代码与编译证据齐备」。
- **安卓交叉构建未在本地跑**（无 NDK）：尖峰文档 §5 的 CI 作业草案是合并前置，绿了才算 .so 真能进 APK。
- `tun_builder_exclude_route` 返回拒绝（false）：API 33 前 Builder 无 exclude-route 表达，接受而不执行等于静默降级，故拒绝让核心回退——全隧道池节点不受影响，分流型 profile 在安卓的该选项不生效，属已知边界。
- DNS 选项解析为尽力而为：`tun_builder_set_dns_options` 读不出时记日志并继续（隧道本身优先），可能出现个别服务器推 DNS 未落地的情形，真机阶段重点观察。
- 单会话：控制器与引擎都是单槽（引擎层 wrong-state 已挡并发），与产品现状（单活动节点）一致。
- 流量统计 2 秒轮询：核心 transport_stats 为会话累计值，转发即累计口径，与 QueryTraffic 的累计语义一致。
- `Ovpn3Client` 的 CPUUsage 导出闲置（尖峰文档 §1.3），不影响功能。
