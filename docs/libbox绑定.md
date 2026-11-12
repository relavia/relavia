# libbox 绑定（Android 真 TUN 的最后一公里）

> 阶段 1 挂账、阶段 2 承接工程项。基线 main=90b22cb（开工时 HEAD
> 已前进至 f0c3028，Step 15/16 在途工作在工作树中；本项的提交
> 边界处理见 §9）。承接文档：docs/step10-Android客户端MVP.md
> （未完成项第 1 条）、docs/阶段1-汇总验收.md 第 2/4 节、
> docs/step7-sing-box集成.md（sing-box v1.14.4 锁定口径）。

## 0. 结论分层（先说清做到哪一层）

| 层 | 状态 | 证据 |
|---|---|---|
| (a) 代码层 | **完成** | Go 桥包 app/libboxbind + core/singbox 的 CompileTunConfig 落地；全部可写单测本地全绿（含真实 libbox 运行时在本机的启停与 TUN 负控，§7.1）；Kotlin 壳四文件对 gobind 真实生成门面做 kotlinc 类型检查零错误（§7.2）；GOOS=android 交叉编译门已扩展覆盖 libboxbind 并本地通过；core/app/plugins 既有测试与 i18ncheck 全绿、零回归、零新增词条 |
| (b) CI 层 | **作业就绪，未实跑** | .github/workflows/ci.yml 的 android 作业已按 §5 定义（gomobile 安装 → bind 出 AAR → 合并 APK → 静态验包 → 构件上传）；app 作业测试步已加链接旗标。本项不推送，CI 实跑结论以主会话推送后为准，**不预称通过**；预期证据形态见 §5.3 |
| (c) 真机层 | **未做，列清单** | 真 TUN 贯通、真实流量、后台保活等见 §8，仍属 Step 15 真机清单（承接 Step 10 的 A-2/A-4/A-5/A-6） |

一句话：绑定代码与 CI 作业已齐备且静态自洽；「真 TUN 已通」只有
在 CI 出 AAR/合并 APK 且真机跑 §8 清单之后才成立，现在不成立。

## 1. API 查实依据（全部读自 v1.14.4 实际源码，非文档印象）

源码位置：本机模块缓存
`~/go/pkg/mod/github.com/sagernet/sing-box@v1.14.4/experimental/libbox/`
（platform.go / service.go / command_server.go / setup.go /
config.go / tun.go / iterator.go），sing-tun
`~/go/pkg/mod/github.com/sagernet/sing-tun@v0.9.7-.../tun.go`，
以及上游仓库 Makefile 与 cmd/internal/build_libbox（2026-11-13
在线取 v1.14.4 标签原文核对）。

### 1.1 关键签名（与任务简报口径的出入先行登记）

- PlatformInterface 的保护开关真名是
  **UsePlatformAutoDetectInterfaceControl()**（简报写作
  UsePlatformAutoDetectControl，以源码为准）。
- `NewCommandServer(handler, platformInterface)`；服务生命周期
  `StartOrReloadService(configContent string, options *OverrideOptions)` /
  `CloseService()`。
- **`OverrideOptions` 必须非 nil**：libbox 1.14.4 的
  StartOrReloadService 无条件解引用 `options.AutoRedirect`，
  传 nil 在库内空指针 panic——本机单测实测复现后修正为传空
  结构体（app/libboxbind/service.go 有注释与回归覆盖：该测试
  若再传 nil 会直接 panic 失败）。
- `libbox.Setup(*SetupOptions)`：BasePath/WorkingPath/TempPath、
  FixAndroidStack（Android 必开，golang/go#68760 规避，上游
  SFA 实践）、LogMaxLines。它会把进程 stderr 重定向到工作目录
  的崩溃日志——故本包的 Setup 只登记路径，真正的 libbox.Setup
  延迟到首次启服务时（ShellRuntime 注释同理）。
- CommandServer.Start()（gRPC 命令监听）**不开**：壳内无人讲
  命令协议，生命周期由进程内直调驱动；多开一个本地 socket
  纯属攻击面。此裁定写在 service.go 头部。
- `CheckConfig(configContent)` 不是纯语法检查：它用桩平台
  **完整构造**一遍 box（连出站密钥材料都验）——本机实测
  SS2022 的 8 字节假密钥在此被拒（bad key length, required 32）。
  本包单测因此使用真实 32 字节密钥，并以它作为「编译产出被
  真实 libbox 接受」的机验证据。
- PlatformInterface 全 25 方法逐一对照 platform.go 原文实现
  （platform.go 有 `var _ libbox.PlatformInterface` 编译断言）；
  TunOptions / RoutePrefix / NetworkInterface / ConnectionOwner /
  Notification / WIFIState 的字段与迭代器形状（StringIterator
  含 Len() int32）均按原文。
- **fd 的 dup 语义**（service.go 的 platformInterfaceWrapper）：
  OpenInterface 调我方 OpenTun 拿到 fd 后，先 getTunnelName(fd)
  再 `dup(fd)`——sing-tun 拥有并关闭副本，原 fd 归平台侧。这
  是 §2.3 待决 fd 对账成立的源码依据。
- **DNS 派生**（sing-tun tun.go）：auto_route 且未显式 dns_mode
  时 DNSModeOrDefault=hijack；未显式 dns_address 时平台 DNS
  地址=tun 首地址+1。我们的 tun 地址 172.18.0.1/30 派生出
  172.18.0.2，与 DefaultTUNRequest 的 DNSServers 按构造成立
  同值（§2.5）。

### 1.2 工具链与构建参数（上游自身口径）

- gomobile：上游 Makefile `lib_install` 锁定
  **github.com/sagernet/gomobile 的 gomobile+gobind @ v0.1.13**
  （SagerNet 分叉，非 golang.org/x/mobile 上游）。CI 与脚本按
  此版本安装。（sing-box 的 go.mod 里 gomobile 库版本为
  v0.1.12，属图谱版本，与工具版本的小幅错位是上游自身状态，
  工具以 Makefile 为准。）
- bind 参数形态取上游 build_libbox：`-target android
  -androidapi 24 -javapkg <pkg>`；我们绑定自己的门面包，
  javapkg 定为 **org.relavia**（生成包 org.relavia.libboxbind，
  与 applicationId 同命名空间），输出名 libboxbind.aar，
  -androidapi 24 与壳 minSdk 一致。
- 标签：Step 7 官方四标签（with_quic/with_utls/with_wireguard/
  with_gvisor）**原样保留**；libbox 绑定**追加**上游自家
  libbox 构建同款的两枚链接机制标签 badlinkname、
  tfogo_checklinkname0 与 ldflags `-checklinkname=0`。原因
  实测：libbox 的 internal/oomprofile、internal/runtimeinfo
  以 //go:linkname 引用受限运行时符号（runtime/pprof.
  parseProcSelfMaps、runtime.allgs），无此旗标时链接直接失败
  （本机两次实测报错原文入 §7.3）；上游 ffi.json 的 ldflags
  同样带 -checklinkname=0。两枚标签不启用任何协议功能，
  能力矩阵与 Step 7 完全一致——这是与「与 Step 7 标签口径
  一致」的唯一出入，性质与理由如上，登记在此。

## 2. 桥设计

### 2.1 分工裁定（谁实现 PlatformInterface 的哪一半）

libbox 的 PlatformInterface 只能由 Go 侧对象实现（它注册进
CommandServer）。裁定：**Go 侧实现全部接口方法，Kotlin 侧不
碰 libbox 类型**；Go 实现里凡需 Android 平台能力者，一律经
ShellBridge（§2.2）回调 Kotlin。这样 Kotlin 只依赖生成的门面
（Libboxbind + ShellBridge + TunParams 三个类型），libbox 的
类型系统不外泄到壳。

| 文件 | 职责 |
|---|---|
| app/libboxbind/libboxbind.go | 门面导出（gomobile 安全类型面）、ShellBridge 接口、TunParams、桥注册表 |
| app/libboxbind/service.go | CommandServer 单例生命周期（懒 Setup、启停/重载、handler 实现） |
| app/libboxbind/platform.go | PlatformInterface 全实现：OpenTun（待决 fd/直连两路）、protect 转发、连接归属、接口枚举/监听、Wi-Fi、通知、诚实拒绝项 |
| app/libboxbind/binder.go | Step 10 编排端点：shellBinder（platform.VPNBinder）、tunHandle、tunStarter（android.TunnelStarter） |
| app/libboxbind/session.go | App 会话装配（store/service/i18n/编排）与 StartSession/StopSession/SessionStatus/Localize |
| core/singbox/tuncompile.go | CompileTunConfig：TUN 形态配置编译（§2.4） |
| android/.../ShellBridgeImpl.kt | ShellBridge 的 Kotlin 实现 + ShellRuntime 引导 |
| android/.../RelaviaVpnService.kt | 桥驱动的接口建立/关闭、前景通知、onRevoke |
| android/.../MainActivity.kt | 会话驱动、桥授权（ACTION_CONSENT）流程 |
| android/.../GoBridge.kt | 门面防御性封装（替代原 JNI external 占位） |

门面导出面（全部为 gomobile 安全类型）：Setup / RegisterShellBridge /
StartService / CloseService / ServiceRunning / StartSession /
StopSession / SessionStatus / Localize / NotifyDefaultInterface /
NotifyTunRevoked。PlatformInterface、handler、binder、starter
均为**未导出**类型，不跨绑定边界。

### 2.2 ShellBridge（Kotlin 实现的 12 方法）

Prepare（授权状态/经 Activity 拉起授权，120s 有界等待）、
EstablishTun(TunParams)→fd、CloseTun、ProtectSocket(fd)→bool、
Teardown、ConnectionOwnerUid（API 29+ getConnectionOwnerUid）、
PackagesForUid、StartInterfaceMonitor/StopInterfaceMonitor
（ConnectivityManager 默认网络回调）、WifiState、PostNotification、
CancelNotification。列表型参数（DNS/路由）以逗号拼接字符串过桥
——gomobile 结构体不能带切片（仅 []byte 例外），每个条目都是
不含逗号的 IP/CIDR 文本，无歧义。

并发与死锁规则（ShellBridgeImpl.kt 头部成文）：桥方法跑在
gomobile 线程、等待一律有界；桥方法**不得**回调触碰会话状态
的门面入口（会话锁在连接全程被编排持有，会死锁）；仅两处安全
例外——Localize（Go 侧改走原子指针读译者，无锁，session.go 的
trAtomic 即为此设）与系统网络回调的单向通知转发。

### 2.3 fd 流向与待决 fd 对账（不推翻 Step 10 状态机）

Step 10 编排顺序原样保留：Prepare → Establish →
starter.StartWithTUN(node, fd) →（失败全量回滚）→ Disconnect
三段逆序。对账发生在 starter 内部：

1. 编排先经 VPNBinder（=shellBinder→桥）建立接口，拿到原始 fd
   与 TUNHandle（归属：壳的 ParcelFileDescriptor）；
2. tunStarter 以 CompileTunConfig 编译配置，把 fd 以
   setPendingFD 泊入 platformImpl，再调 StartOrReloadService；
3. box 启动 tun 入站时调 OpenTun：**待决 fd 优先**——返回泊入
   fd，libbox 包装层 dup 之（§1.1），副本归 sing-tun，原 fd
   不动；
4. 断开时编排先 starter.Stop（CloseService，副本随 box 关闭），
   再 handle.Close → 桥 CloseTun 关闭原 PFD，最后 Teardown
   停服务。三段各自幂等，无双重关闭冒险。

直连回退路：无待决 fd 时（如进程重启后单独 StartService），
OpenTun 把 TunOptions 翻译成 TunParams 经桥直接建立，fd 记为
directEstablished，服务停止时由 platform 侧 CloseTun 释放。
两条路的归属差异在 platform.go 的 onServiceStopped 成文并有单测。

### 2.4 配置衔接（不另造格式）

CompileTunConfig 与既有 compileConfig 是同胞：同一份 sing-box
JSON、同一节点出站构造（重构抽出的 applyNodeOutbounds 共用，
桌面路径行为经既有测试证明不变）、同一支持门与输入门
（checkSupported/checkCompileInputs）。差异仅三处，各有理由：

1. 入站由 loopback mixed 换为 tun（address/mtu 与
   DefaultTUNRequest 镜像、auto_route+strict_route、stack
   gvisor）；
2. route 强制 `auto_detect_interface: true`——桌面配置没有、
   也不需要这个键；Android 上它是 protect 链路的总开关（§3）；
3. 不写 experimental.cache_file：桌面侧因多实例共享工作目录
   必须显式指定，libbox 实例独占其工作路径、自管缓存文件。

Step 11 片段经 scratch map 移植：Fragment.ApplyTo 先落到临时
map，route 取出后**克隆**再注入 auto_detect_interface（共享
片段对象绝不被改，单测断言），dns 原样装入。会话默认策略=
routecfg.DefaultTUNPolicy()（Step 11 的 TUN 默认安全配置，与
桌面同一策略源）；app/service 尚未向桌面引擎接用户策略（既有
状态），本项不越界改它，starter 保留 fragment 注入点。
DNS 模式/地址不显式写：按 §1.1 的派生规则（hijack + 172.18.0.2），
显式再写一遍只会制造第二事实源；DNS 的实际策略（远端经隧道
优先等）由片段的 dns 段承载。

配置镜像关系以测试钉死（app/libboxbind 的
TestTunConfigMatchesShellRequest）：CompileTunConfig 的 tun
地址/MTU ≡ DefaultTUNRequest ≡ 壳建立参数；且产出经
libbox.CheckConfig 全构造接受（IPv4/IPv6 × 片段有无）。

### 2.5 PlatformInterface 的诚实分级

真实现：OpenTun、AutoDetectInterfaceControl（Use 开关=桥已
注册时为真）、FindConnectionOwner（桥的 API 29+ 平台 API；
libbox 自带的 procfs 解析在 Android 10+ 的 SELinux 下对应用
进程不可靠，故不用，这也是平台 API 存在的意义；uid 未知报
错使规则求值按「未匹配」处理而非错认）、GetInterfaces
（net.Interfaces + 名称启发式类型，DNS/网关无平台来源则留空
不猜）、默认接口监听（桥回调转发）、ReadWIFIState（壳因权限
集冻结恒回空——见 §8 注记——nil 是 libbox 支持的「无状态」）、
SendNotification/CancelNotification（桥转发壳通知）。

明确不支持（报错而非假装）：tun 的 include/exclude_package、
route range、http_proxy（v1 壳只建全应用接口；静默丢弃包名
规则是能力造假）；邻居监听；平台 shell/bridge/SFTP/SSH 主机
密钥（桌面级能力，与本产品无关）；LocalDNSTransport 回 nil
（libbox 源码确认仅非 nil 时才注册，属支持的配置）；系统
代理状态回 Available=false（Android 无系统代理模式，Step 10
口径不变），SetSystemProxyEnabled 报错；TriggerNativeCrash
刻意不实现（发布绑定里不留自崩钩子）。

### 2.6 会话装配

session.go 与 app/cmd/relavia-android（Gio 逻辑入口）同构：
store 路径 <base>/Relavia/store.json（镜像
service.DefaultStorePath 的布局）、同一引擎日志接法、同一语言
回退；差异仅 starter/binder 为生产实现 + 默认 TUN 策略片段。
一个既有状态如实记下：store 若被口令锁定（Step 13），重启后
SelectedNodeID 为空，StartSession 报「no node selected」——与
Gio 逻辑构建同一行为，解锁 UI 接线是 Step 13 的既有挂账，
不在本项范围、不因本项变差。

## 3. protect 与 fd 流向图

```
        用户点连接 / Gio 面调用 StartSession
                      |
        Go: android.Shell.Connect（Step 10 编排，状态机未动）
          |  ① Prepare ──桥──> Kotlin: VpnService.prepare
          |                     已授权→true；未授权→MainActivity
          |                     (ACTION_CONSENT) 系统对话框→闩锁回结果
          |  ② Establish ─桥──> Kotlin: RelaviaVpnService 建立接口
          |      TunParams(172.18.0.1/30, DNS 172.18.0.2, MTU 9000)
          |                     Builder.establish() → PFD（壳持有）
          |  ③ starter.StartWithTUN(node, fd)
          v
   CompileTunConfig(node, DefaultTUNPolicy 片段 + auto_detect_interface)
          |  setPendingFD(fd) → CommandServer.StartOrReloadService
          v
   libbox box 启动 tun 入站 → PlatformInterface.OpenTun
          |  返回待决 fd → 包装层 getTunnelName + dup(fd)
          |  sing-tun 持有副本；原 fd 仍归壳 PFD
          v
   运行期出站拨号（每次）: 路由 auto_detect_interface
          |  → PlatformInterface.AutoDetectInterfaceControl(sockfd)
          └──────桥──────> Kotlin: VpnService.protect(sockfd) ★
                      
   ★ protect 是防环路的关键：默认路由已进 TUN 后，未 protect 的
     出站 socket 会被系统再次送进 TUN——隧道连向自己。protect
     把内核自身的 socket 排除在 VPN 之外，拨号才真正出得去。
     本链全程显式：配置键（编译器注入）→ libbox 内部回调 →
     平台接口（本包）→ 桥 → VpnService.protect，任一环缺失都
     表现为拨号失败而非静默环路（单测 TestPlatformProtectDelegation
     与「protect 拒绝必须报错」断言覆盖 Go 侧两环）。

   断开（逆序）：CloseService（副本关闭）→ Handle.Close → 桥
   CloseTun（原 PFD 关闭）→ 桥 Teardown（服务停止）
   系统撤销（onRevoke）：NotifyTunRevoked → 先 CloseService
   （副本已随接口死亡）→ 会话尽力回滚 → 壳本地收尾（幂等）
```

## 4. 诚实契约升级（原占位失败路径的去向）

| 构建形态 | TUN 行为 | 定位 |
|---|---|---|
| **合并 APK**（CI：bind→shell） | 桥在进程启动即注册（ShellRuntime），binder/starter 为生产实现；TUN 不可用**只剩真实失败**：授权拒绝（Prepare=false→编排的 typed permission 错误）、接口建立失败（establish 抛错/回 null）、protect 拒绝、box 启动失败 | 唯一发行形态 |
| 纯 Kotlin 壳构建（无 AAR） | 门面类缺失被 GoBridge 防御性捕获→「未绑定」降级（引导资源文案、不建隧道） | 仅壳开发变体；**进不了发行**：Gradle 依赖 libs/libboxbind.aar，缺 AAR 时 Kotlin 编译直接失败（§5），不存在「不小心打出无数据面 APK」的路径 |
| Gio 逻辑 APK（gogio） | 不装 libboxbind：编排仍走 UnavailableTunnelStarter + FakeVPNService（自带 android.fake_vpn_notice 标注） | 逻辑验证构建，从一开始就明示 fake，与发行构建物理隔离（不同入口、不同产物名） |
| 主机单测 | fake bridge 注入；另有真实 libbox 在本机启停非 TUN 配置 + TUN 负控 | 测试专用 |

原「libbox 未绑定」占位失败（UnavailableTunnelStarter 作为
Android 默认 starter、BridgeVPNService 无 binder 即
ErrUnavailable）在合并 APK 中不再可达：NewShell 的默认 starter
仍是 Unavailable——**生产 starter 由 libboxbind 的 session 装配
显式注入**（android.Options.Starter），binder 由
RegisterShellBridge 显式注册。不改 app/android 的默认值本身，
是因为 Gio 逻辑构建依赖那组诚实默认；两条构建线在装配点分岔，
不靠运行时判断。

## 5. CI 作业（.github/workflows/ci.yml，android + app 两处）

### 5.1 android 作业新序

check（交叉编译门，现含 libboxbind）→ 安装 gomobile+gobind
@v0.1.13 → **bind**（ANDROID_NDK_HOME 取 runner 镜像 ndk 最新
版，与 gio 步同法；scripts/build-android.sh bind）→ 上传 AAR
构件 `relavia-android-libbox-aar` → **shell**（Gradle
assembleDebug，此时即合并 APK）→ **静态验包**（unzip -l 断言
任一 ABI 的 lib/libgojni.so 在包；aapt2 dump permissions 断言
uses-permission 恰为 5 条，与壳声明集一致）→ 上传合并 APK
构件 `relavia-android-merged-debug`（原 shell 构件名随形态
升级更名，旧名 relavia-android-shell-debug 退役）→ gio 步
不变（逻辑 APK 构件名不变）。

scripts/build-android.sh 同步新增 bind 段与 all 序
（check→bind→shell→gio）；bind 段对缺 gomobile/缺 NDK 给出
精确安装提示并以退出码 3 失败，绝不跳过。

### 5.2 app 作业改动一处

Test 步加 `-ldflags=-checklinkname=0`（理由 §1.2，同文件注释）。
其余步（build/vet/windows vet/i18n/Windows 交叉构建）不动；
libboxbind 在 GOOS=windows 下 vet/build 本地已验通过。

### 5.3 预期 CI 证据形态（实跑后回填本节）

- android 作业全绿；`relavia-android-libbox-aar` 与
  `relavia-android-merged-debug` 两构件可下载，体积记入 §6 表；
- 验包步日志含 libgojni.so 至少一行（预期 arm64-v8a +
  armeabi-v7a + x86_64 三行，gomobile -target android 的默认
  ABI 集）与 5 条权限；
- 已知风险点（若红，先查这三处）：①gomobile 安装耗时/网络；
  ②runner 的 NDK 发现路径与 gio 步同源，gio 既已绿则 bind
  应同样成立；③AAR 自身 manifest 若带入权限，验包的「恰 5 条」
  会如实触发——那是检查在工作，届时以实际权限集复核壳声明后
  再调整断言，不预先放宽。

## 6. 许可证与体积

- 口径：主仓 GPL-3.0-or-later；sing-box（含 libbox）GPL-3.0-or-later
  + 名称/关联附加条款，Step 2 审计已覆盖，绑定不引入新的许可
  冲突；AAR 随合并 APK 分发时，sing-box 的授权声明与对应源码
  义务沿 THIRD_PARTY_NOTICES 第 1 条执行（公开仓库即对应源码）。
- 构建工具 sagernet/gomobile（BSD-3-Clause）仅构建期使用，
  不分发、不入产品依赖。
- 新编入依赖（app/go.mod 经 tidy 登记；`go list -deps
  ./libboxbind` 核实实际编入闭包）：filippo.io/age v1.3.1、
  filippo.io/hpke v0.4.0，均 BSD-3-Clause，系 libbox 自身的
  配置/档案加密依赖；已登记 THIRD_PARTY_NOTICES 第 9/10 项及
  义务条目。c2sp.org/CCTV/age 仅出现在模块图谱（age 自身
  go.mod 条目），不编入，已在登记中注明。
- 体积：AAR 与合并 APK 的字节数**只能由 CI 产物给出**（本机
  无 NDK 出不了 AAR，§7.3）——实跑后回填：AAR 〔待 CI〕、
  合并 APK 〔待 CI〕（对照基线：纯壳 APK 1,221,035 B，
  Step 10）。不在文档里预估冒充实测。

## 7. 本地实测与卡点

### 7.1 Go 侧（全绿）

- core：go build/vet/test ./... 全过；新增 TestCompileTunConfig*
  5 项（形态/IPv6/片段+防改断言/双门拒绝）与既有 TestCompile*
  同绿（compileConfig 重构后行为不变的回归证明）。
- app/libboxbind（9 项，go test -ldflags=-checklinkname=0）：
  no-drift 配置≡壳请求 + CheckConfig 全构造接受（v4/v6）；
  binder 委托（Prepare/Establish/句柄 Close 恰一次/Teardown）；
  无桥时 ErrUnavailable；待决 fd 消费一次 + 直连 fd 停止时
  CloseTun + 待决 fd **不**被平台侧关；include_package 诚实
  拒绝；protect 委托与拒绝报错；连接归属 uid+包名与未知报错；
  Localize 回退与未知键回空；**真实 libbox 生命周期**：
  Setup→非 TUN 配置 StartService 成功、ServiceRunning 真、
  CloseService 后假；随后 TUN 配置 + 管道 fd 启动——如期失败，
  错误原文：`start inbound/tun[tun-in]: configure tun interface:
  query tun name: failed to get name of TUN device: inappropriate
  ioctl for device`。这条负控证明启链完整抵达 OpenTun 且待决
  fd 被消费（失败点是「管道不是 TUN 设备」这一真机才不存在
  的条件），且失败后 pending 清空、服务不残留 running、平台
  侧未误关壳 fd。
- app 全量：vet 过；i18ncheck 过（133 键 ×3 包，缺失/多余/空
  均为 0，硬编码扫描 0 违规；**本项零新增词条**——Localize
  复用既有 android.* 键）；go test -ldflags=-checklinkname=0
  ./... 全过（含 service 的 Step 13 安全套件）；GOOS=windows
  CGO 关全量 build 过。
- plugins/vpngate：build/vet/test 全过（未触碰，仅回归确认）。
- build-android.sh check（扩展后）：本地通过（libboxbind 的
  GOOS=android CGO 关 build+vet 在门内）。

### 7.2 Kotlin 侧（手工等价流水线，复刻 Step 10 法）

- 以本机安装的 gobind v0.1.13 按 CI 同参数（-javapkg
  org.relavia）真实生成 Java 门面（Libboxbind/ShellBridge/
  TunParams），javac 编译通过；
- 四个壳 Kotlin 文件（GoBridge/MainActivity/RelaviaVpnService/
  ShellBridgeImpl）以 kotlinc 2.0.20 对〔生成门面 classes +
  android.jar(34) + androidx core/core-ktx 1.13.1 的 classes.jar
  （dl.google.com 官方 maven 直取）+ aapt2 生成的 R〕做类型
  检查：**零错误**。即壳与门面的每个方法签名、TunParams 的
  getter、ShellBridge 的 12 个 override 都与真实生成物逐一对
  得上——不是按预期手写的接口在自说自话。

### 7.3 沙箱卡点（如实）

- **NDK 缺失**：gomobile 本体可装可跑，bind 在本机止步于其
  原文报错 `gomobile: no usable NDK in ~/tools/android-sdk:
  open .../ndk: no such file or directory`；scripts 的 bind 段
  在更前面以自有提示同样拒绝（退出码 3）。AAR 与合并 APK 的
  产出只能等 CI（runner 镜像有 NDK）。
- Gradle 守护进程在沙箱自停（Step 10 已实测的既有结论），
  Gradle 构建本地不可验，以 §7.2 的等价类型检查 + CI 为据。
- 主机 `go build ./...`（app）链接 Gio 桌面二进制时缺
  libEGL/libxkbcommon-x11 等系统库——沙箱既有环境缺口（CI 的
  app 作业以 apt 安装这组依赖），与本项无关：失败的两个包
  均不依赖 libboxbind，且本项相关包已以 vet/Windows 交叉/
  测试链接三种方式分别验证。

## 8. 真机清单（承接 Step 15，不冒充）

在 Step 10 的 A 清单基础上，本项新增/具体化：

1. **A-2 真 TUN 贯通**：合并 APK 安装→授权→连接→libbox 日志
   出现 tun 入站启动且无 query-tun-name 类错误；浏览器经隧道
   出网，出口 IP 为所选节点；断开后设备网络恢复。
2. **protect 实证**：连接状态下持续出网 5 分钟无环路征象
   （流量计数单调、无自连风暴）；节点服务器地址本身经隧道
   可达（ Reality/WS 等依赖外层连接的节点各验一个）。
3. **DNS 实证**：隧道内解析走片段策略（远端经隧道），用
   Step 11 的 scripts/leak-check.sh 安卓段复核；WebRTC 浏览器
   项与 Step 11 清单合并执行。
4. A-4 后台保活、A-5 onRevoke（开另一 VPN 应用抢占→本应用
   状态如实回落且不误报已连接）、A-6 lockdown 与 Step 12 的
   killswitch-check 衔接，各按原清单。
5. 授权拒绝路径：首次连接在系统对话框点拒绝→Go 侧 typed
   permission 错误、界面回落未连接、无残留前景服务。
6. 桥授权路径：从非 Activity 入口发起 StartSession（开发者
   选项/后续 Gio 面）→ACTION_CONSENT 拉起对话框→授权后连接
   完成；后台状态下拉起失败时如实报拒绝（Android 后台启动
   限制），不假装成功。
7. Wi-Fi 规则降级注记：壳未持 ACCESS_WIFI_STATE/定位权限，
   ReadWIFIState 恒空，SSID 类规则不匹配——属已知降级，若
   产品要支持 SSID 规则，先做权限决策再改桥（桥已按真实
   形态实现，权限到位即生效）。
8. 口令锁定 store 的解锁 UI 未接线（Step 13 挂账）：设过口令
   的用户重启后会话报 no node selected，真机验收时与该项
   合并观察，不计本项缺陷。
9. 合并 APK 对纯壳 APK 的覆盖安装（同 applicationId；CI
   构建为调试签名，发行签名连续性属 Step 15 发布工程）。

## 9. 协调与提交说明

- 本项提交只含本项文件：core/singbox（tuncompile 新增 +
  compile.go 共用重构 + 测试）、app/libboxbind（新包）、
  app/go.mod、app/go.sum、Kotlin 四文件、android/.gitignore、
  android/app/build.gradle.kts 与 scripts/build-android.sh 中
  **仅本项的 hunk**、.github/workflows/ci.yml、
  THIRD_PARTY_NOTICES.md、本文件。
- build.gradle.kts 与 build-android.sh 在本项开工前已有
  Step 15 的未提交改动（VERSION 版本身份、gio 委托 release
  脚本）；本项以分片暂存（partial staging）只提交自己的
  hunk，未把 Step 15/16 的在途工作扫进本提交——两文件在
  工作树中的完整内容是两项工作的叠加，父会话提交 Step 15
  时自然收尾。推送前请确认这两文件的剩余 hunk 已有归属，
  因为 CI 的 bind 步与 Gradle 的 AAR 依赖是本项作业成立的
  前提（缺任一，android 作业会在 bind/shell 步如实变红）。
- docs/step10-Android客户端MVP.md 的「未完成项第 1 条」至此
  在代码层与 CI 层关闭，真机层转 §8；阶段 1 汇总验收的挂账
  第 2 条同此口径更新（验收文档本身不在本项改动范围，留待
  父会话在 CI 实跑后回填结论）。
