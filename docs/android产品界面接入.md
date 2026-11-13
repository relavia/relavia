# Android 产品界面接入（合并包 LAUNCHER 换 Gio 产品界面）

> 背景：2026-11-14 用户真机实测发现——合并 APK 的 LAUNCHER 是
> Step 10 的 Kotlin 壳页 MainActivity（只有状态文案＋连接/断开
> 两钮，类注释自述 "The product UI is the Go/Gio surface; this
> Activity is deliberately not it"）。产品界面（app/ui 的 Gio
> 界面：节点列表/导入/节点来源（含 VPN Gate 池）/日志/设置）
> 只存在于 gogio 单独打出的逻辑包里，从未被接为安卓入口：
> 用户装上后无节点可选、无从连接，点连接只走到 VPN 同意未
> 授予的报错。本步把产品界面接为合并包的 LAUNCHER，并把界面
> 的连接动作接到既有 ShellBridge 同意流与 libbox 会话编排上。
> 视觉实现按「效果图先行」定版规则只做到结构层：界面呈现的
> 是既有 app/ui 的朴素 material 形态，效果图在
> docs/ui-mockups/ 待用户评审，点头后另步按图做视觉。

## 0. 结论

路线 (a)：扩展现有 Gradle 工程，在**单一 Go 运行时**（gomobile
的 libgojni.so）内同时承载 libbox 数据面与 Gio 产品界面；
Gio 的 Java 类（org.gioui 三件）按 gogio 的做法 vendored 进
Gradle 工程并声明 GioActivity 为 LAUNCHER。会话侧新增
libboxbind 的 TUN 引擎，使 UI 的 svc.Connect 与壳门面的
StartSession 成为同一条编排路径。路线 (b)（gogio 打 UI 包再
合并）否决，理由见 §1。

## 1. 路线抉择与否决理由

评估口径：与现有壳桥（同意闩/establish/前台服务）兼容、CI
可复现构建、改动面最小。

### (b) gogio 构建 UI 再与 VpnService/libbox 合并清单与服务 —— 否决

1. **双 Go 运行时同进程不受支持。** gogio 的产物是 libgio.so
   （c-shared，内含一整份 Go runtime），gomobile AAR 是
   libgojni.so（同样内含一整份）。把两者装进同一 APK 同一
   进程，等于在一个进程里初始化两份 Go runtime——Go 官方
   明确不支持多份 c-shared 库同进程共存（runtime 抢占信号
   SIGURG、调度器与信号处理都是进程级全局状态），gomobile
   生态亦有同进程只许一份绑定库的既有结论。此路在根上不成立。
2. **多进程回避方案代价失控。** 让 GioActivity 与 VpnService
   分进程可绕开上条，但随之而来的是：Store 跨进程一致性
   （UI 进程编辑节点、会话进程读选择，需要 IPC 或每连接重读
   并处理并发写）、libbox 会话状态跨进程同步、gogio APK 的
   事后手术（拆包塞入 Kotlin dex、AAR 的 .so 与清单条目、再
   重签）——CI 里多出一条 apktool 级脆弱流水线，可复现性差，
   且与 Step 15 的可复现口径正面冲突。
3. **改动面与收益不成比例。** (b) 的每一步都在现有已验链路
   （AAR 绑定、Gradle 打包、五权限校验）之外另起炉灶；(a) 则
   全部落在已验链路之内（见 §2）。

### (a) 的子方案裁定

- **.so 双名双份**（libgio.so 与 libgojni.so 内容相同装两份）：
  否决。同一进程仍是两份 runtime，且包体翻倍。
- **改 gomobile 的 -libname 为 gio**：否决。生成门面类写死
  loadLibrary("gojni")，构建脚本与 CI 校验也以 libgojni.so
  为既定事实；改名的收益为零、波及面大。正解是 vendored 的
  Gio.java 一行补丁加载 "gojni"（§6）。
- **UI 循环的启动点**：Gio 的 Java 侧经 Gio.runGoMain 以
  linkname 调用程序的 main.main（gioui.org/app/runmain.go
  实读确认），而 gomobile 生成的 main 是空桩——调用无害但也
  带不起来 UI。故 UI 循环改由壳必调的 Setup 门面启动
  （§4），不依赖 main.main。

### (a) 可行性的关键事实（均实读源码）

- Gio 的全部 JNI 导出（Java_org_gioui_Gio_runGoMain、
  Java_org_gioui_GioView_* 等）位于 gioui.org/app 包内
  （os_android.go 的 //export）。gomobile bind 与 gogio 一样
  以 -buildmode=c-shared 构建：只要绑定库的导入图包含
  gioui.org/app，其导出符号即进入同一 .so——一份 runtime、
  两组 JNI 入口（门面 + Gio）在同一库内共存。
- GioActivity/GioView/Gio 三个 Java 类自包含（仅依赖
  android 框架），gogio 本就把它们复制进生成的工程
  （gioui.org/cmd/gogio 源码实读，其清单模板的 activity
  属性一并照抄，见 §6）。
- GioView 构造时调用 Gio.init（加载库 + runGoMain 空桩），
  与门面先行加载互不冲突：库只初始化一次。

## 2. 装配图（合并 APK，单进程）

```
┌─ org.gioui.GioActivity (LAUNCHER) ─┐   ┌─ Kotlin 壳（基础设施） ────────┐
│  GioView / Gio（vendored, §6)      │   │ RelaviaApp        进程引导     │
└──────────────┬─────────────────────┘   │ ConsentActivity   同意弹窗面   │
               │ JNI（Gio 导出）          │ RelaviaVpnService TUN/前台服务 │
┌──────────────▼─────────────────────┐   │ ShellBridgeImpl   桥实现       │
│ libgojni.so（单一 Go runtime)      │   └──────────────┬─────────────────┘
│  gioui.org/app 驱动                 │      ShellBridge│（gomobile 代理）
│  libboxbind:                        │◄────────────────┘
│    门面 Setup/StartSession/...      │
│    产品 UI 循环（ui_android.go)     │   同意/establish/protect/
│    ui.App ──► service.Service       │   通知/接口监控 回调
│    dispatch: TUN 引擎 │ probe │ 不可用槽 │
│    android.Shell 编排 ──► tunStarter│
│    libbox 数据面 (sing-box)         │
└─────────────────────────────────────┘
```

要点：进程内只有一个 service 实例（libboxbind 会话装配），
UI 与壳门面共用；Store 只有一个文件
（filesDir/Relavia/store.json），不存在双装配分歧。

## 3. 会话与引擎接线（libboxbind/engine.go）

UI 的连接动作只有 svc.Connect 一条路，故编排必须以
service.Engine 的形态出现。新增 tunEngine（分发引擎的
sing-box 槽位），职责切分：

| Engine 方法 | 走向 | 说明 |
|---|---|---|
| StartNode | Shell.ConnectNode | 同意→建立→libbox 启链的完整编排；自带 3 分钟界（脱离 UI 的 90 秒通用预算，含人阅读系统同意弹窗的时间），口径与门面旧路径一致 |
| Stop | Shell.StopTUN | 只拆 TUN 侧（starter→handle→壳 teardown）；**不经** Shell.Disconnect 的服务层回落，避免 引擎 Stop → Shell → Service → 引擎 Stop 的递归 |
| Status | Shell.Connected() | 与门面 SessionStatus 同源 |
| TestHandshakeNode / ValidateSpec | probe（进程内 sing-box 引擎） | 测活不需要 TUN（一次性本地盒，与桌面同路），且连接中也可测 |
| QueryTraffic | 显式失败（KindPlatformUnavailable） | 本绑定未接 libbox 计数面；能力自报 Features.TrafficStats=false，界面不显示伪造的 0 |
| Capabilities | probe 的协议矩阵 + 本路径平台事实 | TUN 可用（VpnService、需同意）、系统代理不可用、断网保护不可用（KI-08 未关）、IPv6 关闭（编排只建 v4 请求）、RequiresVPNPermission=true |
| MixedAddr | "" | TUN 模式无本地监听；UI 页脚随 svc.Mode() 显示「TUN 全局」，不再误标手动模式 |

随之收敛的：门面 StartSession/StopSession 改走
svc.Connect/svc.Disconnect——壳按钮、通知断开、handler 的
ServiceStop 与 UI 连接从此是同一条路径，lastErr 的记录点
不变。app/android 相应拆分：Connect 的编排主体抽为
ConnectNode（引擎按节点直调，不查 Store、不写选择——选择
持久化归 svc.Connect），Disconnect 的 TUN 分支抽为
StopTUN（Disconnect 保留原语义供逻辑构建/测试）。

OpenVPN 槽位维持 NewAndroidOpenVPNEngine（诚实不可用）：
池节点在安卓继续可导入可测活、连接按钮按既有口径禁用并
给原因（node.openvpn_connect_unavailable）。

## 4. UI 启动与窗口生命周期（libboxbind/ui_android.go）

- 文件以 `//go:build android && cgo` 约束：Gio 的安卓驱动是
  cgo/JNI 代码，宿主机与 CGO-off 交叉编译门
  （scripts/build-android.sh check）看 ui_stub.go 的空实现
  ——与 cmd/relavia-android 不进该门的既有格局一致。gomobile
  bind 构建（CGO 开）才编入真实现。
- 触发点：Setup 门面成功后调 maybeStartProductUI
  （sync.Once）。Application 与 VpnService 的 onCreate 都经
  ShellRuntime.ensureStarted 汇到这里，UI 循环必在任何界面
  出现之前就绪；仅为服务被拉起的进程里，循环阻塞在窗口
  事件上空转等待，成本可忽略。
- 装配复用会话：ensureBuiltLocked 拿到（svc, tr）后以桌面
  同款方式建 material 主题（ui.FontCollection 字体集）与
  ui.App，外加 1 秒刷新 ticker（与桌面/逻辑构建入口一致）。
- 窗口重建：DestroyEvent 只结束当前窗口不结束循环——安卓
  进程常比 Activity 活得久（前台服务保活），同进程内再次
  启动 LAUNCHER 必须有新窗口接应。故循环按「建窗→泵事件→
  销毁→（300ms 间隔）重建」无限往复，ui.App 状态跨窗口保留。

## 5. 同意流时序（产品界面路径）

```
用户在节点页点「连接」
  → ui.runAsync → svc.Connect(ctx, id)
  → DispatchEngine.StartNode → tunEngine.StartNode
  → Shell.ConnectNode
  → BridgeVPNService.Prepare → shellBinder.Prepare
  → ShellBridgeImpl.prepare()
      ├─ 已授予 → 直接返回 true
      └─ 未授予 → startActivity(ConsentActivity, FLAG_ACTIVITY_NEW_TASK)
                   → ConsentActivity 调 VpnService.prepare 的系统弹窗
                   → onActivityResult → ShellBridgeImpl.onConsentResult（闩，≤120s)
  → 授予：ShellBridgeImpl.establishTun → 拉起 RelaviaVpnService
          → Builder.establish → fd 回 Go（pending fd)
          → tunStarter.StartWithTUN → libbox OpenTun 取 fd → 已连接
    拒绝：ErrPermissionDenied 回滚到 UI
          → ui.ErrorKey 映射 android.vpn_permission_denied
          → 页脚红字显示「未获得 VPN 权限，无法建立连接。
             你可以在下次连接时再次授权。」（与壳页旧文案同串）
```

## 6. 清单与壳变更

- AndroidManifest：application 加 android:name=".RelaviaApp"；
  LAUNCHER 换 org.gioui.GioActivity（configChanges /
  windowSoftInputMode / launchMode=singleInstance 照 gogio
  模板；主题 @style/Theme.RelaviaGio 新增于
  res/values/styles.xml，作用等同 gogio 的 Theme.GioApp）；
  新增 .ConsentActivity（exported=false，
  Theme.Translucent.NoTitleBar，不可见同意面）；
  MainActivity 声明删除。权限集不变（仍恰 5 条，CI 校验
  原样通过）。
- MainActivity.kt 删除。其职责三分：引导 →
  RelaviaApp + Go 侧 Setup 钩子；同意面 → ConsentActivity
  （ACTION_CONSENT 字符串值不变）；POST_NOTIFICATIONS
  请求 → vendored GioActivity.onCreate 的 Relavia 补丁。
- vendored 文件（android/app/src/main/java/org/gioui/，
  源为 gioui.org v0.10.3 模块内同名文件，与 app/go.mod 所钉
  版本一致）：GioView.java 原样；Gio.java 一处补丁
  （loadLibrary("gio")→"gojni")；GioActivity.java 一处补丁
  （onCreate 末尾请求 POST_NOTIFICATIONS)。文件头均标注
  来源与补丁点，Gio 升级时整体重 vendored。
- RelaviaVpnService：通知的 openIntent 改指
  org.gioui.GioActivity（点通知回到产品界面）。
- ShellBridgeImpl.prepare：同意 Intent 改指 ConsentActivity。
- 资源：删除壳页专属的 main_status_idle / main_connect /
  main_disconnect（3 个 values 文件同步），其余 bootstrap
  兜底串保留。
- CI：合并包校验步新增 LAUNCHER 断言（aapt2 dump badging 的
  launchable-activity 必须为 org.gioui.GioActivity），把
  「壳页回潮」挡在产物层。
- gogio 逻辑包保留为构建/逻辑门（build-android.sh gio、
  CI android 作业的 logic 构件、Step 15 repro 的 gio 目标
  均不动），但不再是产品界面。

## 7. 验证证据（本地，2026-11-14）

- Go 宿主机：go build / vet 全绿；app 全量测试以仓库规范
  命令 `go test -ldflags=-checklinkname=0 ./...`（ci.yml
  既定口径：libbox 内部用 //go:linkname 引用 runtime 符号，
  无此标志 libboxbind 测试二进制链接必失败，与代码无关）
  除下述既有 flake 外全绿（service 包的
  TestDownloadCanceledLeavesNothing 在满负载全量跑时出过
  时序 flake：单独跑、整包重跑与基线 eaec038 对照均绿，
  失败形态为取消与 1KiB 本地下载的竞态翻转，与本步改动面
  无关，见 §8 登记）；i18ncheck 全绿（152 键 × 3 包 100%，本步未新增
  文案键——同意拒绝复用既有 android.vpn_permission_denied）；
  Windows 交叉编译 + vet 绿。
- build-android.sh check（CGO-off 安卓交叉门）绿。
- ui_android.go 在 GOOS=android + CGO_ENABLED=1 + 绑定标签集
  下以 go/packages 源码级类型检查零诊断（本机无 NDK，cgo
  编译本体由 CI 的 gomobile bind 步出证）。
- Kotlin/Java（手工等价流水线，本机 Gradle 守护进程无法
  启动——既有环境障碍）：门面 API 桩（按 libboxbind 导出面
  手写，仅本地校验用，已移除）+ android.jar + androidx
  core 1.13.1 等真实依赖下，kotlinc 2.0.20 编译全部壳
  Kotlin 源码 + vendored Java + aapt2 生成的 R.java，退出码
  0；vendored 三个 Java 文件另经 javac 独立编译通过。
- 清单/资源：aapt2 compile + link 全过（processed 清单注入
  package 属性，同 AGP 口径）；dump badging 实测
  launchable-activity = org.gioui.GioActivity，权限恰 5 条。

## 8. 未验与残余（不得宣称已过）

- **CI 全量**：本步提交推送后由主会话拾取七作业判决；
  gomobile bind（含 ui_android.go 的真实 cgo 编译）、Gradle
  合并包、新 LAUNCHER 校验均以该轮 CI 为最终证据。
- **真机端到端**：装新合并包 → 产品界面出现 → 选节点连接 →
  同意弹窗 → TUN 贯通 → 流量实走，仍须用户真机复测
  （KI-01 的 A 组清单与本步合并验收）。Gio 与 gomobile 在
  同一 .so 内共存的运行时行为（首帧渲染、视图重建、窗口
  销毁后同进程再启动）只有构建层与代码路径证据，真机首跑
  才是实证。
- **窗口生命周期语义**：§4 的窗口重建循环是对 Gio 安卓
  DestroyEvent 语义的防御式处理；若真机上活动销毁即进程
  终结，该循环自然不触发，无害但也未被实证走过。
- **视觉未实现**：界面视觉停留在既有朴素 material 呈现；
  docs/ui-mockups/ 的效果图经用户评审通过后，另步按图
  实现（届时 Gio 帧捕获眼验同为交付条件）。
- **既有 flake 登记**：app/service 的
  TestDownloadCanceledLeavesNothing 在高负载全量跑下偶发
  （取消竞态），基线同样可复现（低概率），非本步引入；
  建议在 Step 16 挂账里给该测试加竞态硬化（本步未动）。
- TalkBack 实操、锁屏/后台保活下的 UI 恢复、深色模式
  （当前主题为浅色单套）均不在本步范围。

## 9. 增补（2026-11-14）：视觉实现与流量卡裁定

本节记录效果图评审通过（2026-11-14，用户「方向通过，照图
实现视觉」）后的视觉实现步结论，取代 §8 中「视觉未实现」
一条。实现只动 app/ui 呈现层（新增 theme.go 令牌与自绘控件，
ui.go / views.go 重写布局），行为逻辑、服务装配与同意流
（§4–§6）未改。

### 9.1 流量卡裁定：安卓端整卡不渲染（证据）

已连接页的「本会话流量」卡只许接真实计数。经查 libbox
（sing-box v1.14.4）绑定面，安卓 TUN 路径**没有**进程内可用
的流量统计接口：

- libbox 唯一的流量面是 CommandClient 流式推送的
  StatusMessage（TrafficAvailable / UplinkTotal /
  DownlinkTotal），其前提是 CommandServer.Start() 在
  <basePath>/command.sock 打开 unix socket 监听；
  app/libboxbind/service.go 出于攻击面政策**刻意从不开**
  该 socket（代码内有明文注释）。CommandServer 本身没有
  同步的 GetStatus 类访问器；box 实例与其
  trafficcontrol.Manager 对绑定位私有，不像桌面端那样
  可达。
- 因此接计数 = 推翻绑定层既定的安全政策（新增常驻本地
  socket 服务），超出呈现层范围，不在本步做。若未来要接，
  需单独立项评估该 socket 的访问控制，并以 StatusMessage
  的 TrafficAvailable 标志为渲染前提。

界面侧的门是双重的，与引擎能力绑定：仅当
State==Running 且主引擎 Features.TrafficStats==true 且
svc.Traffic() 取样成功时才渲染该卡。安卓主引擎（TUN 引擎）
的 TrafficStats 恒为 false，故安卓端整卡不出现；桌面端
主引擎为 sing-box 适配器，Features.TrafficStats=true，
计数来自其自有 box 的 trafficcontrol.Manager.Total()
（core/singbox 适配器 QueryTraffic），刷新方式为每次布局
帧取样、卡上显示最近一次成功样本。严禁占位假数字。

### 9.2 设置页「软件更新」卡：本步不渲染（省略说明）

效果图 03 含软件更新卡，但当前 service.Updater 没有任何
入口点构造/挂接，UI 也没有版本信息来源——在本步接线等于
新增功能（超出呈现层范围），做装饰按钮则等于假 UI。故
设置页整卡省略，待 Step 16 挂账的更新 UI 接线一并实现
（Updater 装配 + 版本来源）后再按图补上。此为已知偏差，
非遗漏。

### 9.3 已知偏差清单（对效果图）

- 按钮高度 44dp：高于图中 ≥40dp 下限，仍低于 KI-14 的
  48dp 指南（既有登记项，不在本步关闭）。
- Gio 无现成投影原语：卡片以 1dp 边框 + 圆角呈现，不带
  图中阴影；色值、圆角、间距均按 README 令牌取值。
- 导入页「从文件导入」：功能需要路径输入，实现为卡内
  文字按钮展开路径输入行（图中未画该行，属呈现层增补，
  动作与语义不变）。
- 日志页无效果图：按同一令牌体系呈现（标题 + 清除 +
  等宽行距的次级色文本）。
- 连接中态：非目标节点卡的「变灰」以名称次级色 + 操作
  文字弱化呈现，未做整卡透明度处理。
- 已连接节点标识：引擎 Status 带 ActiveNodeID 时以其为
  准；安卓 TUN 引擎的 Status 只带 State，此时以当前选中
  节点为准（UI 与壳层的连接路径只会启动选中节点）。

## 10. 增补（2026-11-14 晚）：真机缺陷四件 + 设计裁定三/四落地与帧验

### 10.1 分组筛选行布局爆炸（缺陷 1）——根因与修复
根因：分组单选行是无界横向 Flex，长国家名（Australia、Croatia (LOCAL Name: Hrvatska)）之后的子项被测得近零宽度，CJK/拉丁标签逐字竖排撑高整行，把内容推到半屏以下。修复：分组改为横向 material.List（高度固定 = chip 高 + 4dp），chip 内标签单行截断；帧验以 98 节点、10 国分组（含上述两个长名）验证：行高有界、横滑可用、滚动条可见。

### 10.2 节点行滚动压字（缺陷 2）——根因与修复
帧验定位到真正的结构性根源（与行高/裁剪无关）：节点行右栏星标行内含 `Flexed(1, Spacer)`，在 Rigid 测量语境下（Gio Flex 对 Rigid 子项以整行最大宽测量）把右栏撑成整行宽度，文本列被挤为零宽——标签被裁没、右栏动作贴到旗帜旁。同类问题连带修三处：①右栏去掉 Flexed 垫片，改为纵向 Flex 尾对齐；②Gio Stack 对 Stacked 子级清零 Min 约束——`surface`/`editorBox`/`bigButton` 改为在 Stacked 闭包内按需重抬 Min.X（导入卡编辑框与按钮曾缩成文字宽；bigButton 仅在 Rigid 语境重抬，Flexed 槽位内强制会破坏页签等宽布局，帧验抓到并已分开处理）；③语言单选行标签改 Flexed（语言卡曾窄于其他卡）。行内所有标签单行截断（lbl1），行高由内容决定且一致。帧验：长列表滚动中段（定位至第 40 行）画面干净，无文字穿透/重叠。

### 10.3 页脚被挤成竖排（缺陷 3）
页脚改两行结构：错误文案独占一行（最多 2 行截断），模式行 Flexed(1) 单行截断，长错误不再挤压页脚。帧验页脚完整。

### 10.4 报错话术人话化（缺陷 4）
外泄源头是语言包条目本身：`err.platform_unavailable` 三语均为规格话术（「已如实拒绝，未做静默降级」类）。已改写为人话（说清什么不能用、为什么、还能做什么）；全量自查 err.*/mode.* 条目，另改 `err.unsupported`（软化）与 `mode.capability_note`（去掉「如实」话术）。risk.* 为法定披露原文，不动。三语 + 模板同步，i18ncheck 全绿（201 键）。

### 10.5 导入失败给原因（缺陷 5）
ImportReport 本就携带逐项 Failed{Index, Code, Detail}，只是界面没展示。现导入结果区在计数行下方展示首个失败的人话原因：解析错误码（unknown-scheme、bad-port、bad-uuid 等 14 个 + model-conversion）逐一映射 `import.fail.*` 本地化条目，未知码回落通用条目。

### 10.6 日志页为空（追加缺陷二）——根因与修复
根因有二：①服务层日志其实一直存在且有测试覆盖（导入汇总与逐项失败、连接失败、测活、来源刷新失败都经 logf 记录）；但**界面层产生的失败从未写入**——订阅拉取错误（ImportSubscriptionURL 绕过统一收尾直接返回）、文件读取错误、以及一切经 UI 异步通道上抛的错误（runAsync 只设置了横幅）。用户截图里的那次失败正是界面层上抛型，日志自然为空。②日志缓冲仅存进程内存，安卓进程重启即清——这是结构限制，本批未改存储介质（仍如实标注「仅保存在本地」的进程内日志）。修复：runAsync 统一在失败时调用新增的 `Service.LogFailure(环节, err)` 写日志；ImportSubscriptionURL 的拉取/状态码/读体失败在返回前先记日志；ImportText 空输入改走统一收尾（也记日志）。服务层测试覆盖：订阅 HTTP 500 必落日志、导入失败码必落日志、LogFailure 可用。帧验：日志页可见带时间/环节/原因的失败记录。

### 10.7 裸订阅地址贴错框（追加缺陷二之三）
选择「引导而非代拉」：文本导入框内容为裸 http(s) 网址时，不发任何网络请求（不做用户未明确发起的拉取），而是把地址预填进订阅框并显示提示条「这看起来是一个订阅地址…已帮你填到下面的订阅地址」，用户点「拉取订阅并导入」完成。效果图 02 v2 已呈现该状态。

### 10.8 设计裁定三：节点行改版 + 图标按钮 + 收藏
- 行 = 46×34dp 旗帜图（无国家信息时协议短码图兜底）+ 两行文字（名称 / 地址·延迟）+ 右侧收藏星标与测活/删除。国家解析顺序（不编造）：名称中的旗帜 emoji → 校验过的 〔XX〕 括号码 → 池节点按分组国家名匹配 → 名称中国家名子串匹配；国家名数据表以数据文件内嵌（186 条名→ISO、79 个合法码），避免污染 i18n 硬编码扫描。约 70 国旗帜以基础几何绘制（条纹/十字/圆盘/星/月），几何不足以忠实呈现的国家一律回落 ISO 码牌，**不画错旗**：已知近似——以色列旗星形为双三角近似、英国旗红色斜十字从略。
- 收藏落存：NodeRecord.Favorite + Store.SetFavorite，重启不丢，星标可点切换。
- 全部主要按钮 = 图标 + 文字：成套描边图标（24 网格、统一线宽；电源/靶心/仪表/脉搏/垃圾桶/链接/下载/文件/文件夹/刷新/盾牌/勾/叉/搜索/地球/列表/齿轮），深色参考的质感借鉴、色板仍用 v1 浅色令牌（未改深色主题，待用户看 v2 图裁定）。
- 搜索框（按名称/地址/分组过滤）+ 分组页签已落地；帧验搜索「kore」只剩 KR 节点。

### 10.9 设计裁定四：设置页「连接偏好」
- 协议偏好（自动/速度优先/兼容优先）持久化于 Settings.ProtocolPref，接入 AutoSelect 排序：**弱加密降级规则冻结不变、先行**；其后（非自动时）按 25ms 延迟桶 → 协议类别（快：WireGuard/Hysteria2/TUIC；传统：Shadowsocks/Trojan/VMess/OpenVPN/SOCKS5/HTTP）→ 精确延迟。服务层 9 个新测试证明同条件下偏好确实改变选择、弱加密永不被偏好抬升、无该类节点时自动回落；界面在「当前分组无该类节点」时显示回落注记。
- 运行模式单选接真实接线：Service.RunModeOptions 按平台能力给出可用性（TUN ← 平台 TUN 能力；系统代理 ← 平台系统代理能力；手动 ← 引擎有本地监听地址），不可用项禁用并给人话原因；选择经 SetMode 持久化并在下次连接时由引擎按模式启动，页脚「运行模式」读此设置。
- 帧验（Linux/Xvfb，720×1400）：设置页语言卡满宽、连接偏好（速度优先选中态）、运行模式（TUN 选中、其余禁用注原因）、能力卡、信任卡均与 03 v2 图一致。偏差一处：禁用模式行同时显示说明行（变灰）与原因行，效果图只画了原因行——信息更全，保留。

### 10.10 帧验总览（本批）
无头帧验完成 7 帧：节点列表（98 节点多国）、滚动中段、搜索过滤、导入、设置、已连接（含流量卡，数字为探针引擎真实计数样本）、日志（失败记录在册）。与 v2 效果图逐项对照通过；探针引擎协议矩阵不含 OpenVPN，故节点页连接位显示「此平台暂时无法连接 OpenVPN 节点」的人话注记（真实构建按 sing-box 能力矩阵决定，属设计行为非缺陷）。已连接页流量卡另修一处死锁：采样原只在卡片内部触发、而卡片以「已有采样」为门控——改为运行态每帧先触发采样再判门控（桌面真实计数路径，来源见 §9）。
仍未验：真机复测（本批全部修复以真机截图缺陷为据，需用户真机回归确认）；公网 L5 握手、真机 TUN 贯通不在本批。

## 11. 增补（2026-11-14 深夜）：v3 界面实现（照批准图施工）

用户 2026-11-14 04:21 批准 v3 图组（「方向通过，照图实现」）后本批落地。施工图 = docs/ui-mockups/ v3 图组 + 同目录 README 的 v3 令牌与已记录偏差 + 《竞品按钮与页面拆解》§1/§2/§3/§4 定稿话术。

### 11.1 落地清单
- 首屏层级：英雄卡按真实服务状态切换（新用户「一键连接免费节点」/ 回访未连「一键连接最快节点」或「继续连接上次节点」/ 已连 = 状态 + 断开）；一键连接走既有服务链（池同意 → 刷新 → 全组检查 → 自动选择 → 连接），链上失败停留在英雄卡并给出人话原因与「换一个节点重试」；风险确认改底部弹层不跳页，三条要点不弱化，法定风险全文（risk.vpngate.body）一字未改、只在弹层内经「查看完整风险说明」展开。
- 「为你选好」最多 3 行：仅收录有真实测活成功记录的节点（排序 = 上次连接 → 收藏按延迟 → 最快），未测活不入选、不编造数字；已连接节点不入选（钉在英雄卡）。
- 多背景四档（浅色 / 深蓝 / 墨色 / 跟随系统）：令牌整套切换、持久化（Settings.Theme）；设置页色板区 56×40 样块 + 选中外环 + 对勾；跟随系统在桌面读 Windows 注册表 AppsUseLightTheme、读不到时回落浅色并在设置页注明（帧验在 Linux 上验证了回落路径与注记）。
- 节点行两行制 72dp（警告行 84dp），删除 / 检查延迟收入 ⋯ 溢出菜单，分隔线 68dp 缩进，全部检查降为区头图标钮，自动选择不再有独立按钮（连接收敛到英雄卡与精选行箭头）。
- 设置页选项行组：说明同组、禁用原因紧贴同组、选中组浅底、未选组卡片边框；话术全量换拆解 §4 定稿（三语，i18ncheck 绿；risk.* 未动）。应用包 249 键 × 3 语言包对齐。
- 导入页：推荐卡（公共池）+ 帮助入口 + 方式行点开才展开（四方式永不同时展开）。
- 节点页与导入页、设置页各有「看图文教程」入口，打开 https://relavia.github.io/guide.html（桌面经系统浏览器、安卓经壳 Intent 打开，见 §11.4 接线补记；失败落日志并给人话提示）。

### 11.2 与图纸的偏差（有意保留，备案）
- 设置页保留 v2 的能力卡与信任卡：它们是 TUN / 系统代理 / 断网保护「不可用」状态的唯一诚实陈述面，图纸未画不等于可以撤下。
- 节点页由「固定头 + 内嵌列表」改为整页单一滚动流：原结构在 700dp 高窗口（及桌面最小尺寸）下把节点行挤到 0 高、不可达；图纸的长屏（800dp）下两者视觉一致。

### 11.3 WCAG AA 对比度（Step 18 方法，app/ui/palette_test.go 自动验）
三档调色板 × 27 组文字/表面配对全部 ≥ 4.5（Disabled 为非活动态豁免）。最低值：浅色 Hint/Bg = 4.52、浅色 Warn/WarnBg = 4.62、浅色 Secondary/PrimaryLite = 4.70；深蓝最低 Secondary/PrimaryLite = 5.41；墨色最低 Secondary/PrimaryLite = 6.06。按钮白字：White/Primary = 5.86（三档同值），White/DangerFill = 5.69（浅）/ 5.03（深蓝、墨）。完整数值由 `go test -run TestPaletteContrastAA -v ./ui/` 输出。

### 11.4 帧验（Linux/Xvfb，360×700dp 窗口，探针引擎 + 98 节点量级种子数据）
12 场景与 v3 图逐项对照：首屏新用户（浅/深蓝）、风险弹层、回访未连（浅）、最快（深蓝）、节点列表 + 溢出菜单展开、导入（浅/深蓝、方式行展开态）、设置（浅/深蓝/跟随系统回落）、已连接。对照中发现并修复的真实缺陷：Gio Stack 的 Expanded 填充只按 Stacked 子级尺寸绘制（外层 Min 只抬布局盒不抬漆面）——英雄按钮、普通按钮、分组 chip、分段页签曾普遍「盒高对、漆面矮」，统一改为由 Stacked 子级自带目标尺寸；断开按钮文字贴顶（Stacked 内容加 Center）；风险行链接被挤换行（短提醒改 Flexed 截断）；风险弹层被 Flexed 列表撑满高（改高度封顶、面板贴合内容）；已连接节点误入「为你选好」（排除）。
仍未验：真机复测（本批以帧验 + 既有真机缺陷为据，真机回归待用户）。
接线补记（2026-11-14）：安卓端教程入口的外链打开已接线——platform.OpenURL 在 Android 构建下经平台注册表（URLBinder，openurl_bridge.go）委托 ShellBridge.OpenURL，壳侧（ShellBridgeImpl）以 ACTION_VIEW Intent 打开；Go 侧先行校验（仅允许 https，空值/非 https 在过桥前拒绝，错误经既有失败链落日志并给人话提示），桥未注册或系统无浏览器时仍如实返回不支持、落日志、人话提示，不假装打开。验收点：Go 假桥三例（已注册转发 / 未注册降级 / 非 https 拒绝）与 libboxbind 桥接线测试全过；Kotlin 以手工等价流水线对 gobind 真实再生成门面编译零错误（生成门面 ShellBridge 新增 openURL(String)，与壳实现逐字对上）；真实 Gradle/APK 构建归 CI 的 android 作业，真机点击打开浏览器归用户真机复测——未验，不得宣称已通。
