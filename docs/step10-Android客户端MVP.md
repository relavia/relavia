# Step 10 Android 客户端 MVP — 交付报告

状态：**Go 服务层/i18n/平台桥的 Android 接通、VpnService 薄壳（Kotlin）、连接编排与单测、手工流水线实出并验签的 debug APK 均已交付；Gradle 规范构建与 Gio 逻辑包由 CI 作业出包（本沙箱 Gradle 守护进程不可用，证据见 §2）；VpnService 真 TUN 数据面、后台保活、扫码、通知行为等真机项挂账（§8），未冒充通过。**

Governing source：方案书 §8.1（通用功能）、§8.2 平台差异 Android 列（系统代理模式「—」、TUN v1.0（VpnService）、断网保护 v1.0、扫码导入=相机扫码）、第 14 章 Step 10 原文——「交付 VpnService 版同等功能集。验收：主流机型真机测试通过，无 Root 依赖」。复用口径承 Step 9 文档（服务层/i18n 单一实现、双端共用），桥对接口径参 Step 12 文档 §5（`LockdownBridge` 提案）。

本步为**接续执行**：前任执行体被环境中断、无最终报告，留有未提交盘面。本报告 §1 为逐项审计处置，保留的每一项都经本步复验，不盲信盘面。

---

## 1. 盘面审计处置表

基线 HEAD=74a485a（Step 12），其下 cae6c19（Step 14）、1e7f795（Step 9）、df50b53（Step 11）。

| 盘面项 | 处置 | 依据 |
|---|---|---|
| `android/`（Gradle 工程：settings/build.gradle.kts、app/build.gradle.kts、Kotlin 壳三件、Manifest、三语 res/values） | **保留**，另修 1 处缺陷（见下「本步修复」） | Step 10 正当产物；Kotlin 源码经本步 kotlinc 实编译通过（§5） |
| `app/android/`（连接编排 Shell + TunnelStarter/QRScanner 接口 + 单测） | **保留** | 服务层复用与诚实占位的核心交付；单测 8 个全过 |
| `app/cmd/relavia-android/main.go`（Gio 逻辑构建入口） | **保留** | 见 §3 姿态说明：逻辑/UI 验证壳，非生产数据面 |
| `app/platform/vpn.go` + `vpn_test.go`（VPNBinder 桥 + Fake） | **保留** | Step 12 §5 提案所指的桥即此物；单测 4 个全过 |
| `app/platform/factory_android.go` | **保留** | Android 构造器：系统代理如实报不支持（8.2「—」）、TUN 可用性=桥是否注册、无托盘 |
| `app/platform/factory_other.go`（modified） | **保留** | 构建标签 `!windows` → `!windows && !android`：不改则 Android 目标下与 factory_android.go 构造器符号重复，交叉编译不可能通过。属必要修正 |
| `app/platform/platform.go`（modified） | **保留** | 仅包注释增补 Android 段落，无代码变更；注释内容与实现一致 |
| `app/tools/i18ncheck/whitelist.txt`（modified） | **保留** | 新增 2 条：`RELAVIA_STORE`、`RELAVIA_FAKE_VPN`，均为 `cmd/relavia-android/main.go` 中真实使用的环境变量名（构建/OS 常量非文案），各带理由注释，符合工具的白名单纪律；加后 i18ncheck 全绿（§6） |
| `core/singbox/step11_leak_test.go`（modified） | **回退到已提交状态** | diff 经逐字核验仅为一处注释对齐空格（`0, 1)  // CLASS IN` 的 gofmt 对齐），零语义。Step 11 已验收，按接续任务书口径：改已验收步骤文件须有充分理由，此项不构成，予以回退。如实登记其反面事实：HEAD 版本该文件本身存在这一处 gofmt 瑕疵（本步以 `gofmt -l` 对 HEAD 版本实测确认），属 Step 11 的既存表面瑕疵，不影响任何测试，建议由独立卫生提交处理，不夹带进 Step 10 |
| `app/tmp-android-check`（未跟踪，59,127,056 字节） | **删除** | `file` 实测为 Linux x86-64 ELF——前任某次本地 `go build -o` 的临时产物，非 Android 产物、非交付物；根 .gitignore 的模式（`*.exe`/`dist/` 等）覆盖不到无扩展名文件，故直接删除 |
| `scripts/build-android.sh` | **保留**，其声称的 CI 作业由本步补齐（见下） | 脚本三段（check/shell/gio）与本步实测口径一致 |
| CI 作业「android」 | **本步新增**（前任未落） | 脚本头注释声称 CI 以同入口运行，但盘面 `.github/workflows/ci.yml` 中并无该作业——引用悬空。本步在 ci.yml 中补齐 android 作业（交叉编译门 + Gradle 壳包 + gogio 逻辑包 + 构件上传），引用闭环 |
| `android/app/src/main/AndroidManifest.xml` | **本步修复 1 处真实缺陷** | 原稿声明 `foregroundServiceType="specialUse"` 却缺 API 34 起强制的 `FOREGROUND_SERVICE_SPECIAL_USE` 权限与 `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` 理由声明——缺失时 Android 14 上以该类型调 `startForeground` 会抛 SecurityException。本步补齐两项（验包证据见 §5：权限恰 5 条、property 已入包）。这是「编译可过、真机必炸」的一类缺陷，正是接续审计要拦的 |

Step 12 已交付的 `app/platform/killswitch*.go` 与 `core/killswitch/`：**未触碰**（`git status` 中无其改动；core 全量回归含 killswitch 包全过，见 §5）。

---

## 2. 工具链实情（本沙箱实测，2026-11-12）

| 工具 | 状态 | 证据 |
|---|---|---|
| Go | ✅ 1.23.12 + 本地缓存的 1.25.5 toolchain（GOTOOLCHAIN=auto 自动切换，与 go.mod 一致） | `go version` / toolchain 缓存目录 |
| JDK | ✅ Temurin 17.0.21（~/tools/jdk17），默认 PATH 上无 java，须显式 JAVA_HOME | `java -version` |
| Android SDK | ✅ ~/tools/android-sdk：platforms/android-34、build-tools 34.0.0（aapt2/apksigner/zipalign/d8 齐全）、platform-tools、cmdline-tools 12.0 | 目录实测 |
| 调试密钥库 | ✅ ~/tools/android-debug.keystore（标准 debug 别名/口令） | 本步 apksigner 实签通过 |
| Gradle 8.11.1 | ❌ **不可用** | 发行包已解压且 `gradle -version` 正常，但任何构建（含空目录 `gradle help`）均报 `Could not receive a message from the daemon`：守护进程日志显示其启动、写完问候后约 10 秒在注册表自检中认定自身条目丢失而自停。在 btrfs（~/tools/gradle-home）与 tmpfs（/tmp/gh）两种 GRADLE_USER_HOME、daemon 与 --no-daemon 两模式、机器忙/闲两状态下均可复现；sdkmanager 的 `--licenses` 亦因 Java HttpURLConnection 过不去本沙箱出口代理的 CONNECT 隧道而崩（`doTunneling0` NoSuchElementException）。curl 与 Gradle 所需的 dl.google.com 经同一代理可达（AGP POM 实测 HTTP 200）。结论：本沙箱的 Java 长驻进程/代理组合有环境级障碍，**不是工程文件的问题**；规范 Gradle 构建改由 CI 承担，本地改走 §5 的手工等价流水线 |
| NDK | ❌ 无 | android-sdk 下无 ndk 目录。gogio/gomobile 的 CGO 构建本地不可能，归 CI |
| gomobile / gogio | ❌ 未安装 | `command -v` 实测缺失；且无 NDK 时装了也无法出包 |
| kotlinc | ✅ 本步下载 Kotlin 编译器 2.0.20（与 Gradle 工程锁定版本一致）至 ~/tools/kotlinc | GitHub Release zip 86,110,157 字节，实编译见 §5 |

---

## 3. 架构裁定

沿 Step 9 已定的 Gio 选型与服务层单实现，本步 Android 形态定为 **libbox 式两层 + 桥**：

1. **Kotlin 薄壳**（仓库根 `android/`，applicationId `org.relavia.client` —— 仅为标识字符串，不主张任何域名所有权）：只拥有 Android 平台保留给应用进程的东西——`VpnService` 的授权流（`VpnService.prepare` 在 MainActivity）、`Builder().establish()` 的 TUN 生命周期、前台通知（连接中/已连接两态 + 断开动作）、`onRevoke` 撤销处理。只用公开 API，无 Root、无隐藏 API。壳内 TUN 参数（172.18.0.1/30、DNS 172.18.0.2、MTU 9000）是 Go 侧 `platform.DefaultTUNRequest`（即 sing-box TUN 默认值）的镜像，Go 侧为真源，壳注释已标注须同步。
2. **Go 侧**（`app/`，与桌面共用）：节点库、Step 8 解析导入、服务状态机、i18n、流量与测活原样复用；新增 `app/platform/vpn.go` 的桥抽象（`VPNBinder`/`BridgeVPNService`/`TUNRequest`/`TUNHandle`）与 `app/android` 的连接编排（授权→建立→fd 交给 TunnelStarter→失败全回滚；断开三步全执行并报首错）。
3. **数据面**：生产形态是 gomobile 构建的内核（libbox 模式）实现 `TunnelStarter`，消费壳交来的 fd。**该绑定尚不存在**，故默认实现为 `UnavailableTunnelStarter`：TUN 连接在当前构建中显式失败（`ErrUnavailable`），不存在「假装连上」。壳侧 `GoBridge` 同理：原生侧未绑定时 `tunEstablished` 返回 false，壳立即关闭刚建立的接口并收通知——宁可断开，不把设备流量黑洞进死 fd。诚实契约与 Step 7/9/12 一致。
4. **Gio 逻辑构建**（`app/cmd/relavia-android`，gogio 打包）：Step 9 的 UI 与服务层在 Android 上的验证壳。姿态在入口文件头写死：进程内内核按桌面方式运行，VpnService 桥未注册时 TUN 连接显式拒绝；`RELAVIA_FAKE_VPN=1` 的逻辑验证变体注册 Fake 桥以便在真机上演练授权→建立→fd 移交编排，该变体**不承载任何真实流量**，且启动即以 `android.fake_vpn_notice` 词条写入日志明示。

模式口径（8.2）：Android 无系统代理模式——`factory_android.go` 的 `NewSystemProxy` 直接返回不支持实现，不发明一个假的；`NewShell` 在全新设置下把默认模式置为 TUN（桌面仍保留其 manual 默认）。

与 Step 12 的对接：Step 12 §5 的 `LockdownBridge`（lockdown 状态读取/设置页拉起/撤销事件）与其 `VPNBinder` 正交，Step 12 文档已将整合列为跨步协调项（其 §10 未完成项 2）。本步确认对接点：整合期在 `app/platform` 与 `VPNBinder` 并列落地、由 Kotlin 壳同一注册点注入（壳已有 `onRevoke` 与 `SUPPORTS_ALWAYS_ON` 声明可承接）。本步不单方面实现该整合（Step 12 明确要求协调进行），列入 §9。

---

## 4. 方案书 §8.2 Android 列逐项状态

| §8.2 Android 列 | 状态 | 说明 |
|---|---|---|
| 系统代理模式：—（以 TUN 为主） | ✅ 落实 | 构造器如实报不支持，无假模式 |
| TUN 模式：v1.0（VpnService） | 🟡 壳与编排完成，数据面待 libbox 绑定 | 授权/建立/撤销/通知全链路代码就绪并经单测与实编译；真实数据面（fd→内核）是后续 libbox 绑定步的工作，本步构建中 TUN 连接显式失败而非假装（§3.3） |
| 断网保护：v1.0 | ⏳ 归 Step 12 + 整合项 | 策略层/状态机已由 Step 12 交付；Android lockdown 语义映射在其文档 §4.3，桥整合待协调（§3 末） |
| 扫码导入：相机扫码 | 🟡 接口落地，实现待组件选型 | `QRScanner` 接口 + 服务层 `ScanAndImport`（扫到即走 Step 8 导入）+ 诚实占位 `UnavailableQRScanner`（返回 `ErrScanUnavailable`，UI 有对应词条）；CameraX + 解码组件的选型与实现未做，列 §9 |

§8.1 通用功能在 Android 上的复用状态承 Step 9 机验结论（同一服务层，本步以 Android 目标交叉编译 + 单测复证）：节点/分组管理、导入（粘贴/文件）、批量握手测活、一键连接（manual 路径）、自动选择、实时流量、连接日志、三语切换均由同一代码提供；Android 特有差异仅在平台层（上表）。

---

## 5. 产物与验证证据

### 5.1 Go 侧（本机实测，全绿）

- `core/`：`go build ./...`、`go vet ./...`、`go test ./...` 全过（kernel、killswitch、parsers、routecfg、singbox、specnode 等全包，含 Step 12 在内无回归）。
- `plugins/vpngate`：build/vet/test 全过（Step 14 无回归）。
- `app/`：build/vet/test 全过——service、i18n、platform、android 四包有测试，其中本步新增/保留的 android 编排 8 个用例（默认 TUN 模式、编排高兴路、授权拒绝零建立、无桥如实不可用、starter 失败全回滚、占位 starter 不可用、扫码占位、三包词条解析）与 platform 桥 4 个用例全过。
- **Android 交叉编译门**：`scripts/build-android.sh check` 通过——`CGO_ENABLED=0 GOOS=android GOARCH=arm64` 下 i18n/locales/platform/service/android 五包 build + platform/android 两包 vet 全过；另以官方标签（with_quic/with_utls/with_wireguard/with_gvisor）对 service/android/platform 三包同目标构建通过；`ui` 包同目标单独构建通过。
- 边界如实标注：`GOOS=android go build ./...`（全包）会失败于 `cmd/relavia`（桌面入口）与 `cmd/relavia-android`——两者经 `gioui.org/app` 依赖 Gio 的 CGO/NDK Android 后端（`internal/vk` 在 CGO 关闭时无可用文件），属 Gio 的既定打包方式（gogio），不是代码缺陷；这正是 check 门按包列举而非 `./...` 的原因。Windows 目标 `go build ./...` 回归通过（Step 9 无回归）。

### 5.2 Kotlin 壳 + APK（本机手工等价流水线实出）

因 §2 的 Gradle 环境障碍，本步以 Android 官方工具链手工执行了与 Gradle 等价的各阶段，**每一步都是真工具真输入**：

1. 依赖经 dl.google.com 实下载：androidx core/core-ktx 1.13.1 AAR、lifecycle-runtime 2.6.2 AAR、lifecycle-common/annotation 1.7.1（Gradle 工程锁定的 core-ktx 1.13.1 及其传递依赖）。
2. `aapt2 compile` 三语 res 全部通过；`aapt2 link` 生成 R 类与基础包（说明：独立调用 aapt2 须给清单副本注入 `package` 属性——AGP 在规范构建中以 namespace 注入同一信息，仓库清单文件本身无需也不应带该属性；手工流水线用的是 /tmp 副本，仓库文件未因此改动）。
3. `kotlinc` 2.0.20 对壳三件源码（MainActivity / RelaviaVpnService / GoBridge）以 android-34 的 android.jar + 上述依赖编译：**零错误**。
4. `d8` 转 dex（min-api 24 与工程 minSdk 一致；有一条 R8 对 Kotlin 2.0 Metadata 的重写警告——build-tools 34 自带 R8 早于 Kotlin 2.0 元数据格式，属工具链代差提示，CI 的 AGP 8.5.2 携带更新的 R8，不影响 dex 生成与验签结论）。
5. 注入 dex → `zipalign` → `apksigner` 以调试密钥库签名 → `apksigner verify` **通过**。
6. `aapt2 dump badging/permissions` 静态验包：包名 `org.relavia.client`、compileSdk 34、启动 Activity 为 MainActivity、specialUse 理由 property 在包内；**权限恰为声明的 5 条**（INTERNET、ACCESS_NETWORK_STATE、FOREGROUND_SERVICE、FOREGROUND_SERVICE_SPECIAL_USE、POST_NOTIFICATIONS），无多余权限。

产物：`app/dist/relavia-shell-debug.apk`（dist/ 为 gitignore 区，不入库）——**1,221,035 字节，sha256 `d98b8b3ba13ee035ee7743f71d0db54530779adbf39d6c1590f89ba506b8c198`**。

与规范 Gradle 产物的已知差异（如实）：手工包未做 androidx 库清单/资源合并（壳自身资源完整，通知图标暂用系统图）；badging 中 versionCode/versionName 为空、targetSdk 未写入（由 AGP 在规范构建注入，工程文件里是 34 / 1 / 0.1.0-dev）；不含 Go 原生库（libbox 未绑定，见 §3.3）。**定位：壳源码与清单的实编译/实打包证据，不是可分发产品包。** 规范出包以 CI 的 Gradle 作业为准（§5.3），CI 首跑结果不在本报告预称。

### 5.3 CI 作业（本步补齐，待主会话推送后实跑）

`.github/workflows/ci.yml` 新增 `android` 作业（ubuntu-latest：Go 1.25 + Temurin 17 + Gradle 8.11.1），与本地脚本同入口：
`build-android.sh check`（交叉编译门）→ `build-android.sh shell`（Gradle assembleDebug，上传 app-debug.apk 构件）→ 装 gogio +  runner 自带 NDK → `build-android.sh gio`（上传 relavia-logic.apk 构件）。GitHub runner 的守护进程/网络环境正常，§2 的沙箱障碍不适用；作业实跑结论以 Actions 为准。

Gradle Wrapper 未入库：生成 wrapper 需一次成功的 Gradle 运行（本沙箱不可得，见 §2），故 CI 以 setup-gradle 按锁定版本 8.11.1 供给 Gradle，与工程的版本锁定一致；wrapper 待任一正常环境首次构建时补生成，列 §9 小项。

---

## 6. 多语言（§8.1 锁定要求）

- 壳系统侧字符串的**真源是三语词条包**：`android.*` 共 10 个键（通知渠道/标题/正文、断开动作、权限说明标题/正文/被拒提示、扫码不可用、假桥提示）已在 zh-Hans/zh-Hant/en 三包中齐备，`TestShellStringsResolveInAllPacks` 逐包逐键断言可解析；壳在 Go 绑定后经 `GoBridge.text(key, fallback)` 优先取包内文案，语言切换语义与桌面同一 Translator。
- `res/values`、`values-b+zh+Hans`、`values-b+zh+Hant` 三套资源是**绑定前引导回退**（启动器标签、首帧通知等 Go 未就绪的表面），三语齐备、从不是单语言；文件头注释已写明其与词条包的主从关系，包胜出。
- `i18ncheck` 本步实跑：三包各 **103** 词条（Step 9 的 87 + Step 14 的 6 + 本步 10），缺失/多余/空值全 0，渲染层硬编码扫描违规 0（白名单新增 2 条见 §1）。RTL：Manifest 已声明 `supportsRtl=true`，架构预留承 Step 9。

---

## 7. 无 Root 依赖核对

全步只用公开 API：`android.net.VpnService`（含 prepare 授权流）、前台服务、通知、POST_NOTIFICATIONS 运行时权限。清单权限 5 条全部为普通/运行时权限，无签名级、无隐藏 API、无 root 调用（`su` 等）——已以验包权限清单与源码双向核对。

---

## 8. 真机挂账清单（未验，不得宣称通过）

Step 10 验收原文含「主流机型真机测试通过」——本沙箱无真机，以下逐项挂账，建议并入 Step 15 真机清单：

| 编号 | 项目 |
|---|---|
| A-1 | 主流机型（至少 Pixel + 一家国产 ROM）上壳 APK 安装、授权流弹出与拒绝/同意两分支行为 |
| A-2 | libbox 绑定后：真 TUN 建立→真实节点流量贯通→断开清理，及 fd 移交的稳定性 |
| A-3 | 前台通知两态呈现、断开动作、语言切换后通知文案（经桥取包） |
| A-4 | 后台保活与系统回收：长时间后台、Doze、厂商电池优化下的连接存续与重连 |
| A-5 | onRevoke 贯通：另一 VPN 接管/设置中撤销时壳的拆除与 Go 侧状态同步 |
| A-6 | always-on / lockdown 与 Step 12 的贯通（同其 A-1~A-3，桥整合后一并验） |
| A-7 | 相机扫码导入真机链路（组件实现后） |
| A-8 | Gio 逻辑构建在真机上的渲染与三语界面肉眼确认（承 Step 9 的 W-5 同类项） |

## 9. 未完成项

1. **libbox 数据面绑定**：gomobile 构建内核 AAR + GoBridge 三个原生入口（localize/onTunEstablished/onTunClosed）的实现 + Kotlin 壳与 Go 运行时的装配。这是 Android 真 TUN 的最后一公里，独立成步为宜（涉及 NDK 构建链与 fd 所有权细节），完成后 A-2 才可验。
2. **扫码实现**：CameraX + 解码库选型（许可证需过 Step 2 同口径审计）后实现 `QRScanner`。
3. **Step 12 `LockdownBridge` 整合**：按 §3 末的对接点与 Step 12 协调落地（其 §10 项 2）。
4. **Gradle Wrapper 补生成**：任一正常 Gradle 环境执行 `gradle wrapper --gradle-version 8.11.1` 后入库。
5. 壳的通知小图标为系统占位图，产品图标随品牌资产步替换；壳 Activity 的极简启停界面仅供壳自验，产品 UI 是 Gio 表面（§3.4）。

## 10. 提交

本地提交（未推送）：Step 10 全部文件（android/ 工程、app/android、app/cmd/relavia-android、app/platform 的 vpn/factory_android/factory_other/platform 改动、i18ncheck 白名单、scripts/build-android.sh、ci.yml 的 android 作业、本报告）。`app/tmp-android-check` 已删除且不入库；Step 11 测试文件已回退至 HEAD，工作树中不再有其改动。
