# Step 12：断网保护（Kill Switch）

状态：**策略层、状态机、Linux nftables 执行器、适配器衔接、双平台骨架均已交付并通过本机可及层级的验证；Windows / Android 的真机强制生效验证挂账（见 §9），未冒充通过。**

Governing source：方案书 §5.4（全局断网保护）、§8.1（安全口径：断网保护）、§8.2（Windows 与 Android 均为 v1.0 平台）、第 14 章 Step 12 原文——「交付双平台 kill switch；验收：强杀隧道、断网、休眠唤醒等场景下无直连流量泄露（抓包验证）」。Step 7 文档中适配器 `Platform.KillSwitch` 自报 false 是本步的起点，本步交付后该自报改为由真实状态源驱动（§6），默认构建仍如实报 false，理由见 §3。

代码落点：

| 部件 | 路径 |
|---|---|
| 语义、状态机、策略编译、执行器接口 | `core/killswitch/`（纯 Go 标准库，无第三方依赖） |
| Linux nftables 执行器 | `core/killswitch/enforcer_linux.go` |
| 规则描述导出工具 | `core/killswitch/nftdump/`（CLI：`-platform nft\|iptables\|windows\|android`） |
| 适配器衔接（加性 hook） | `core/singbox/`（`Options.KillSwitchReport`、`Adapter.KillSwitchReadiness()`） |
| 平台骨架 | `app/platform/killswitch*.go`（Windows netsh 执行骨架、Linux 包装、其余平台 Unsupported、Fake） |
| 真机/特权环境验证脚本 | `scripts/killswitch-check.sh` |

未改动：`spec/`、`core/kernel` 接口、Step 11 的 `core/routecfg` 语义。

---

## 1. 语义定义（规范性）

### 1.1 启用档位（三档）

| 档位 | 语义 |
|---|---|
| `ModeOff`（关闭） | 功能停用。永不下发规则；一切会话事件均为 no-op。 |
| `ModeWhenConnected`（连接时） | 自连接会话开始之时起阻断，持续到用户**显式断开**为止。隧道崩溃、断网、休眠唤醒都不解除阻断。 |
| `ModeAlwaysOn`（常开） | 只要该设置开启即阻断：会话之前、会话之间、用户断开之后都阻断。断开只结束会话，永不结束阻断；只有用户显式停用本功能（Disable）才解除。 |

### 1.2 阻断范围

阻断生效期间，**一切不经隧道接口出站的流量一律丢弃**，明确包括：

- **DNS**：域名解析必须走隧道（与 Step 11 的 DNS 策略一致），否则失败——**刻意不设 53 端口例外**。任何「放行系统 DNS」的口子都会在隧道死亡时变成直连解析泄露。
- **IPv6**：编译出的规则集位于 inet 合一族（nftables）/ 全配置文件（Windows），不存在「只挡 v4、v6 裸奔」的形态。

### 1.3 例外白名单（完全列举，未列即丢弃）

1. 环回流量；
2. 经隧道接口（默认接口名 `relavia0`）出站的流量；
3. 内核自身连接隧道端点的通道：当前会话节点的服务器地址与端口。端点**必须是 IP 字面量**——主机名必须在会话开始前解析完毕（规则生效后解析本身会被阻断）；解析结果变化时调用方须重新下发 Config；
4. 局域网/私有地址段——**仅当** `Config.AllowLAN` 打开时（用户开关，默认关）。

### 1.4 与 Step 11 routecfg 的边界（重要）

Kill switch **不是路由规则的一部分**，是独立的失效保护层：

- `routecfg` 决定流量在客户端数据通路**内部**往哪走，编译为 sing-box 的 route/DNS 片段，由内核逐连接求值。内核进程死亡，这些片段随之消失。
- `killswitch` 决定在受保护会话存在期间，流量**是否被允许离开主机**（隧道之外），编译为操作系统防火墙规则（Windows 防火墙策略、Linux nftables）或映射到平台机制（Android 系统 lockdown）。它不消费 `routecfg.Policy`、不产出任何 sing-box 片段；两层之间唯一的共享物是节点身份（端点例外来自所连节点，由调用方解析后传入）。

内核死亡正是本层存在的理由：操作系统级的阻断必须活得比请求它的进程久——因此状态机**先持久化意图、再调用执行器**，并在进程重启后恢复（§2 的 I3/I4）。

注：`AllowLAN` 与 routecfg 的私有地址直连分流是两回事：前者管「能不能出主机」，后者管「出去往哪走」，互不替代。

---

## 2. 状态机

状态：`off`（关闭）/ `armed`（已布防：阻断生效、隧道未起或会话间隙）/ `engaged`（已接合：阻断生效且隧道在用）/ `recovering`（恢复中：阻断生效，正在从故障/重启中恢复）。

事件：`SessionStart`、`TunnelUp`、`TunnelDown(reason)`、`Wake`、`UserDisconnect`、`Disable`、`Restore`（进程启动时按持久化意图恢复）。

不变量（全部有故障注入单测覆盖，见 §8）：

- **I1** 阻断在 armed / engaged / recovering 三态恒生效；仅 off 不阻断。
- **I2** 通往 off 的出口只有两个：连接时档位下的 `UserDisconnect`，以及任意档位下的 `Disable`。隧道崩溃、断网、唤醒、进程被强杀——任何故障事件都不解除阻断。
- **I3** 阻断意图**先持久化、后调用执行器**（fail-closed）：崩溃发生在两者之间，重启 Restore 时仍按已持久化的意图恢复阻断。
- **I4** `Wake` 与 `Restore` 在返回前先重新下发规则；下发失败置 `Degraded=true` 并保持意图，**绝不**以「恢复失败」为由解除阻断或报告安全。
- **I5** 三个阻断态下发的是**同一份规则集**，状态迁移本身不触碰执行器——迁移过程不存在规则空窗。

补充语义：

- 持久化记录为 engaged 的进程被强杀后，Restore 进入 `recovering` 并标注 `ReasonProcessKilled`，重新下发规则后等待隧道状态重新确认。
- 执行器 Apply 失败时（如 SessionStart 时）：状态保留意图并标 Degraded，错误显式返回给调用方，不静默降级为无保护运行。
- `ModeOff` 完全惰性：不持久化、不下发、事件 no-op。
- 仅修改 Config（未走 Disable）不得冲掉已持久化的阻断意图（单测 `TestRestoreBlockingIntentSurvivesBareConfigChange`）。

持久化：`Store` 接口；`FileStore` 为 JSON 文件、临时文件 + rename 原子替换、权限 0600；`MemoryStore` 供测试。

---

## 3. 就绪分级（如实口径，方案书 §3.3 诚实原则）

强制生效的就绪程度分三级，**永不向上取整**：

| 级别 | 含义 |
|---|---|
| `ReadinessUnavailable` | 无 Controller/执行器接入。 |
| `ReadinessPolicyReady` | 状态机与编译出的平台规则就绪且已测，但所接执行器不是真实平台执行器（Fake，或平台实现仅为编译验证级骨架）。 |
| `ReadinessEnforceable` | 接入了真实平台执行器（如 Linux nftables 执行器；未来的、经真机验证的 Windows 防火墙/WFP 实现）。 |

本步交付的默认构建处于 **PolicyReady**：策略层完整真实，但尚无生产级 Windows/Android 执行器接线。因此适配器对外的 `Platform.KillSwitch` 仍报 **false**（§6）——「策略就绪」不等于「平台可强制」，不提前报 true。

---

## 4. 策略编译：平台规则映射

`Compile(Config) → Descriptors` 为确定性编译（端点排序、输出稳定），一份 Config 同时产出四种平台描述：

### 4.1 Linux nftables（`LinuxNFT`）

- 独占表 `relavia_ks`，output 链 `priority -100`，策略 accept + 末尾 `counter drop` 兜底；
- 放行序：`oif "lo"` → 隧道接口 `oifname "relavia0"` → 每端点一条 `ip/ip6 daddr + tcp/udp dport counter accept` → （AllowLAN 时）私有段放行 → 末尾全丢弃；
- iptables 等价命令序列（`LinuxIPTables`）一并产出，供无 nft 环境的测试与降级路径使用。

### 4.2 Windows 防火墙（`WindowsRuleSet`，描述级）

- 语义映射：全配置文件（Domain/Private/Public）默认出站动作置 `block`，再以统一前缀 `Relavia KillSwitch: ` 的放行规则开例外（环回、隧道接口对应的程序/接口、端点地址:端口、AllowLAN 时的本地子网）。
- 本步只产出**规则集描述**；`app/platform` 的 netsh 命令构建器由该描述生成命令序列（§7）。描述中如实标注：改动默认出站动作会影响整机其它程序，真机接入时必须保存并恢复用户原有入站/出站策略，不得无痕覆盖（列入 §9 挂账）。

### 4.3 Android（`AndroidMapping`，语义映射）

- 机制：`system-lockdown`——映射到系统「始终开启 VPN + 阻断未走 VPN 的连接」（lockdown）模式。Android 的 lockdown 是**系统级开关**，应用不能静默开启，必须由用户在系统设置中手动打开；映射描述中明确携带 `RequiresUserOptIn: true` 与设置入口 Intent（`android.settings.VPN_SETTINGS`）。
- 诚实边界：用户未开启 lockdown 时，本层**没有**保证——映射描述显式写明该缺口（`TestCompileAndroidMappingHonest` 断言之），UI 不得在未开启时显示「断网保护已生效」。
- 应用侧义务（映射中列明）：检测 lockdown 状态并在未开启时引导用户；监听 VPN 被撤销（revocation）事件并视为隧道故障处理。

---

## 5. Android 桥接口提案（对 Step 10）

Step 10 交付时其平台桥（`app/platform/vpn.go` 的 `VPNBinder`）尚在并行开发中，本步按任务书以**接口提案**形式只写自己一侧（`core/killswitch/android.go`），未改动 Step 10 的任何文件：

```go
type LockdownBridge interface {
    LockdownState() (LockdownState, error) // Unknown / Enabled / Disabled
    OpenLockdownSettings() error           // 拉起系统 VPN 设置页
    Revocations() <-chan struct{}          // VPN 被系统/用户撤销事件
}
```

`AndroidReadiness(bridge)` 辅助函数把桥状态折算为 §3 的就绪级别：lockdown 未开启最高只到 PolicyReady。

现状更新：Step 10 的 `vpn.go` 已出现在工作区（其提交由 Step 10 自行完成）。该桥管 VpnService 生命周期（consent、establish、fd），lockdown 状态读取不在其中——本提案的 `LockdownBridge` 与之正交，建议整合期在 `app/platform` 与 `VPNBinder` 并列落地，由 Kotlin 壳同一注册点注入。整合动作列入 §10 未完成项（跨步协调，不在本步单方面改对方文件）。

---

## 6. 适配器衔接（core/singbox）

加性改动，不改 `core/kernel` 接口：

- `Options.KillSwitchReport func() killswitch.Report`：真实状态来源（通常为 `killswitch.Controller.Report`）。适配器在 Start 时**实时**咨询，而非用构造期快照。
- `Capabilities().Platform.KillSwitch` 改由该来源驱动：仅当来源报告 `ReadinessEnforceable` 时为 true；无来源接入（本步交付的所有构建）保持 Step 7 的 false。
- 新增 `Adapter.KillSwitchReadiness()` 供 UI/诊断展示分级（unavailable / policy-ready / enforceable）。
- Start 在请求 kill switch 而来源未达 enforceable 时，仍以 `platform_unavailable` 拒绝，错误文案更新为指向本文件。

单测（`killswitch_hook_test.go`，3 例全过）：无来源 → false + ReadinessUnavailable；接入 PolicyReady 的 Controller → 仍 false 且 Start 被拒；接入 Enforceable 桩 → 能力报 true 且真实 Start 成功。

---

## 7. 平台实现骨架（app/platform）

| 文件 | 内容 | 状态 |
|---|---|---|
| `killswitch.go` | 平台无关 `KillSwitch` 接口 + Windows netsh 命令纯函数构建器（Apply/Remove 序列、CIDR→点分掩码换算） | 已测（构建器、移除、换算、Fake、接口形状） |
| `killswitch_windows.go` | netsh 执行骨架 | **仅编译验证**（含 GOOS=windows 全量构建）；`Enforceable()` 如实返回 false，真机验证前不接生产 |
| `killswitch_linux.go` | 包装 `core/killswitch` 的 NFTEnforcer；`Available()` = 系统存在 nft | 本机实测可用（§8.2） |
| `killswitch_other.go` | 非 Windows/Linux 平台的 Unsupported 实现 | 返回不可用，不假装 |
| `killswitch_fake.go` | FakeKillSwitch（测试/逻辑验证构建） | 已测 |

工厂文件（`factory_*.go`）本步未动，避免与并行 Step 10 冲突；骨架接线（factory 注册）留待整合期。

---

## 8. 实测证据（分层，如实标注）

### 8.1 环境实测结论（先行实测，结论入档）

沙箱实测（2026-11-12）：

- 身份为 root（uid=0），但能力集被剥离：`capsh` 显示 effective 集为空，`cap_net_admin`、`cap_net_raw` 在禁止集内；
- 初始命名空间内 `ip netns add` 失败（setns: Operation not permitted）、`nft add table` 失败（Operation not permitted）；`setns`/`nsenter`/`ip netns` 被沙箱在 seccomp 层拦截；
- **`unshare -Urn`（用户+网络命名空间）可用**：其内可 up 环回、建 veth 对、建 nftables 表与链——规则层验证可及；
- **非环回流量在沙箱内全局不可生成**：初始命名空间与新建 netns 内，对任何非环回目的的 TCP connect / UDP sendto 均在 syscall 层返回 EPERM（`[Errno 1] Operation not permitted`）；环回 TCP 正常。同命名空间 veth 地址、跨命名空间 veth 对端均复现。与 Step 7 记录的 UDP 全局 EPERM 现象一致。判定：命名空间之上的出口策略（cgroup/LSM 级）拦截，命名空间无法绕过。

**结论：netns 可用于「规则被内核接受并回读」的验证，不可用于「真实流量阻断计数」的验证。** 后者在本地证据中降级为规则集语义断言 + 状态机故障注入（§8.3），完整流量 rig 以脚本形式交付特权环境执行（§8.4），本地运行如实报 ENV-BLOCKED（退出码 2，与 FAIL 的 1 严格区分）。

### 8.2 内核接受级证据（本机实测，PASS）

- `TestCompiledRulesetKernelAcceptance`：编译出的真实 nftables 规则集在 `unshare -Urn` 命名空间内被内核加载并回读成功（回读 464 字节，含 `counter drop` 兜底）。
- `TestNFTEnforcerInNamespace`：NFTEnforcer 自我再执行进入命名空间，完成 Apply → Applied 回读 → Remove 全程往返。
- `scripts/killswitch-check.sh` 本机运行：`STEP kernel-acceptance: PASS`。

### 8.3 规则集与状态机级证据（本机实测，PASS）

`core/killswitch` 全套 24 个测试通过，要点：

- 策略编译：阻断范围完整性（`TestCompileNFTBlockScope`）、**无 DNS 例外**（`TestCompileNFTNoDNSException`）、AllowLAN 开关（`TestCompileNFTLANtoggle`）、编译确定性（`TestCompileDeterministic`）、Windows 描述与 Android 映射诚实性（`TestCompileWindowsDescriptor`、`TestCompileAndroidMappingHonest`）、Config 校验（`TestConfigValidate`，含主机名端点被拒）；
- 故障注入状态机：隧道崩溃保持阻断、隧道掉线+断网保持阻断、**进程强杀后 Restore 恢复 engaged→recovering**、armed 态强杀恢复、干净 off 保持 off、**休眠唤醒先重下发规则且永不先行解除**、唤醒下发失败只降级不解除、连接时档位用户断开解除、常开档位用户断开**不**解除、Disable 任意档位解除、无故障事件能解除阻断（穷举表）、SessionStart 下发失败显式报错、ModeOff 完全惰性、裸改 Config 不冲掉持久化意图。

### 8.4 流量级验证（脚本交付，本机 ENV-BLOCKED）

`scripts/killswitch-check.sh`（bash 语法校验通过）在特权环境（真机/特权 CI runner）执行完整 rig：

- Phase 0：环境探针 + 用 nftdump 生成 rig 规则集（端点 192.168.12.1:9999、隧道接口 relavia0）；
- Phase 1：规则集内核加载与回读断言；Phase 1b：流量生成探针（区分 ENV-BLOCKED 与 FAIL）；
- Phase 2 双命名空间流量 rig：S0 基线对照（无规则时可达）→ S1 规则生效 → S2 端点例外 TCP+UDP 可达 → S3 直连目标被挡（以**服务端到达计数器** + 客户端 drop 计数器双向断言隧道外零包通过）→ S4 DNS（UDP+TCP 53）被挡 → S5 隧道路径（10.99.0.1）放行 → S6 **隧道被杀**（接口 down + 默认路由还原物理口）后仍被挡 → S7 IPv6 被挡 → S8 拆除后对照恢复。

本机运行结果：Phase 1 PASS；Phase 2 报 `ENV-BLOCKED`（探针证据 `BLOCKED [Errno 1] Operation not permitted`），退出码 2。**该 rig 尚未在任何特权环境实跑过——S0–S8 全部条目在真机/CI 特权环境首跑通过前，均属未验证，不得引用为已通过。**

### 8.5 全量回归（本机，2026-11-12）

- `core`：build + vet + test（无标签）全过；`core/singbox` 带官方标签（`with_quic with_utls with_wireguard with_gvisor`）全过，含 Step 11 泄露用例与本步 3 个 hook 用例；既有 `TestAdapterPlatformGates` 仍过；
- `app`：build + vet + test 全过；`GOOS=windows` 全量构建过；`GOOS=android ./platform/` 构建过；
- `spec/tests/validate.py`：ALL OK（正例 14/14、反例 9/9）。

---

## 9. 真机挂账清单（未验，不得冒充通过）

| # | 条目 | 环境要求 |
|---|---|---|
| W-1 | Windows 防火墙骨架真机执行：netsh 序列实际生效、规则回读、Remove 后完整还原 | Windows 真机（管理员） |
| W-2 | Windows 默认出站动作改动对整机的影响与用户原策略的保存/恢复（含入站策略不受损）验证 | Windows 真机 |
| W-3 | Windows 下强杀客户端进程后，规则残存 + 重启 Restore 恢复的端到端验证（含抓包确认零直连） | Windows 真机 + 抓包 |
| W-4 | Windows 休眠/唤醒、网卡切换、系统重启场景的阻断连续性抓包验证（Step 12 验收原文场景） | Windows 真机 + 抓包 |
| A-1 | Android lockdown 真机：用户开启系统 lockdown 后，强杀 App/隧道崩溃时零直连（抓包/计数器） | Android 真机 |
| A-2 | Android 未开启 lockdown 时的 UI 诚实呈现（不得显示已保护）与引导流程 | Android 真机 |
| A-3 | Android VPN 撤销（revocation）事件到本层故障处理的贯通（依赖 §5 桥整合） | Android 真机 |
| T-1 | `scripts/killswitch-check.sh` Phase 2（S0–S8）在特权环境首跑并归档结果 | 特权 Linux / CI 特权 runner |
| T-2 | 公网环境泄露复检：kill switch 生效下走 Step 11 的公网泄露检测项（WebRTC 等真机待办项与此合并执行） | 真机 + 公网 |

## 10. 未完成项

1. **生产执行器接线**：Windows 骨架经 W-1/W-2 验证后才可将 `Enforceable()` 置真并注册进 factory；在此之前默认构建 `Platform.KillSwitch=false` 是正确状态，不是缺陷。
2. **§5 桥整合**：与 Step 10 协调把 `LockdownBridge` 落到 `app/platform`（与 `VPNBinder` 并列），并把 Android Controller 的状态源接到壳注册点。
3. **CI 特权 job**：把 `scripts/killswitch-check.sh` 接入 CI 的特权 runner 作业（普通 runner 预期输出 ENV-BLOCKED/退出码 2，不得配成失败）。
4. **UI 接线**：三档档位开关、AllowLAN 开关、就绪分级呈现（含 Android 未开 lockdown 的诚实文案）属客户端整合范畴，本步只交付策略层与状态来源。
5. 已知小项：`core/singbox/step11_leak_test.go` 工作区中有一处 gofmt 空格修正（非本步改动，未纳入本步提交），留待其归属步骤或整合期顺带处理。
