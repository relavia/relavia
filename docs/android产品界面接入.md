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
