# Step 18 本地化与无障碍基线（交付说明）

口径注记：方案书第 14 章 Step 18 原文为「中英双语完整界面」，
但第 3 章多语言锁定口径（2026-11-12 用户定版）已升级为
**v1.0 简中 / 繁中 / 英文三语 100%**。本步按三语执行，原文
「双语走查」按三语走查验收；原文「其余语言的社区翻译入口」
照原文交付。

## 1. 三语走查（核心验收：无缺项）

### 1.1 方法

1. **界面盘点**：从 `app/ui`、`app/cmd`、`app/android`、
   `app/libboxbind` 代码与 `android/` Kotlin 壳盘点全部用户
   可见面与状态（见 1.2 表），逐面列出其消费的语言键。
2. **键对账**：静态引用扫描（Go + Kotlin 源码中的键字面量）
   与三包键集对账：包内键 134 个，其中 92 个被代码静态引用，
   其余 42 个为已入包待接线的预置键（1.4），无一为孤儿
   误入；代码引用而包内不存在的键为 0（`update.*` 的
   `update.hash_mismatch` 等 10 个同名字符串是服务层**机器
   错误码**，与展示键是两套命名，映射见 1.4）。
3. **逐条审读**：134 键逐键三语对照审读（非空、非占位、
   语义对应）；`risk.*`、`security.*`、`risk.vpngate.*`
   （含于 risk 组）、`update.*` 四组风险相关文案逐条人工
   审读；占位符集合逐键校验：三包 134 键占位符不一致
   **0** 处。
4. **自动门复跑**：`tools/i18ncheck` 三包各 134 键、
   missing/extra/empty/untranslated 全 0、渲染层硬编码扫描
   违规 0。

### 1.2 走查表（面 × 键 × 消费状态 × 三包结论）

| 面 | 键组（数） | 消费状态 | 三包结论 |
|---|---|---|---|
| 全局框架（页眉/页签/页脚/状态行） | app.*（2）、nav.*（4）、status.*（5）、mode.label/manual/manual_addr、traffic.upload/download | 已接线渲染 | 三语齐全，语义对应 |
| 系统托盘（桌面） | tray.show/connect/disconnect/quit/tooltip | 已接线（语言切换即时重建菜单） | 齐全 |
| 节点页（列表/空态/选中/行状态） | group.*（2）、conn.*（5）、node.*（9） | 已接线；行状态含未测活/失败/延迟/弱加密/跳过校验徽标 | 齐全 |
| 节点页风险横幅 | risk.weak_encryption、risk.insecure_skip_verify | 已接线（选中风险节点时全文展示） | 齐全，人工审读通过（见 1.3 修复 2） |
| 导入页（文本/订阅 URL/文件） | import.*（11）、warn.weak_auto_note、import.result | 已接线 | 齐全（import.fetching 为预置，见 1.4） |
| 日志页 | log.*（3） | 已接线 | 齐全 |
| 设置页（语言/能力/模式说明） | settings.*（3）、cap.*（8）、mode.capability_note、risk.node_trust、lang.name ×3 | 已接线 | 齐全（见 1.3 修复 3） |
| 错误提示（页脚错误行） | err.*（10），经 ui.ErrorKey 映射 | 已接线 | 齐全（见 1.3 修复 4） |
| Android 授权与通知 | android.vpn_permission_*（3）、android.notif_*（5）、android.scan_unavailable、android.fake_vpn_notice | Kotlin 壳经 GoBridge Localize 消费 5 键 + Go 侧编排/日志消费其余 | 齐全 |
| VPN Gate 风险确认 | risk.vpngate.title/body/confirm/decline/revoke/node_line（6） | 插件同意状态机 + 壳侧接缝（Step 14 口径） | 齐全，逐条人工审读 |
| 本地安全（口令/锁定/备份导出） | security.*（7） | **预置待接线**（数据层语义与文案已备，锁屏/口令界面未接线，Step 13 挂账） | 文案三语齐全且已审读 |
| 软件更新（检查/下载/验签/安装） | update.*（24） | **预置待接线**（服务层与文案已备，设置页更新区未接线，Step 16 §10 挂账） | 文案三语齐全且已审读（见 1.3 修复 1） |
| 通用对话框键 | common.*（4） | 部分预置（ok 已用；cancel/close/delete 为对话框预置） | 齐全 |

### 1.3 走查发现与当场修复（4 项）

1. **真实缺项 1 处**：服务层更新错误码 `update.download_failed`
   没有对应展示文案（其余 9 个错误码均有 `update.err_*`
   对应键）。三包新增 `update.err_download`（「下载更新
   失败，请检查网络后重试。」/「下載更新失敗，請檢查網路
   後重試。」/ "The update download failed. Check your
   connection and try again."），三包键数 133 → **134**。
   另：`update.download_canceled` 是用户主动取消，按设计
   不弹错误文案（回到就绪态），不算缺项，记录在此。
2. **繁中风险文案地域用词 4 处**（`risk.vpngate.body`，
   机器转换痕迹，仅改繁中 orthography、语义零变动，简中
   §7.3 固定句未动）：網絡→網路、數據包→封包、賬號口令
   →帳號密碼、財務信息→財務資訊。
3. **过期文案 1 处 × 三包**：`mode.capability_note` 仍是
   Step 9 时代的冻结表述（「系统代理与 TUN 模式尚未
   落地…后续步骤实现」），与设置页上方实时能力状态脱节。
   三包统一改写为与实时检测挂钩的表述（「能力状态以实时
   检测结果为准：显示『不可用』者为当前平台/构建尚未
   提供，界面如实标注、不提供无效开关」）。
4. **英文润色 1 处**：`err.platform_unavailable` 的
   "instead of silently degrading" 改为
   "rather than silently falling back"，语义不变、表达
   自然。

### 1.4 预置未接线键（42 个，非缺项）

`security.*`（7）与 `update.*` 展示键（24）为 Step 13/16
按「文案先行」口径入包、界面接线挂账中的键；另有
`common.cancel/close/delete`、`mode.system_proxy`、
`mode.tun`、`node.selected`、`status.stopped`、
`traffic.title`、`traffic.bytes`、`tray.hide`、
`import.fetching` 共 11 个通用/未来面预置键。三类均已在
上表标注归属，接线随对应步骤落地时直接取用，不需再补
翻译。服务层更新错误码 → 展示键映射：
manifest_fetch→err_fetch、manifest_invalid→err_invalid、
no_artifact→err_no_artifact、hash_mismatch→err_hash、
signature_invalid→err_signature、
rollback_detected→err_rollback、
install_unavailable→err_install_unavailable、
install_failed→err_install、download_failed→err_download
（本步新增）、download_canceled→（无，见 1.3-1）。

## 2. 术语表（核心术语三语对照，已沉淀至 app/locales/README.md）

| 简中 | 繁中 | 英文 | 备注 |
|---|---|---|---|
| 节点 | 節點 | node | |
| 分组 | 分組 | group | |
| 订阅 | 訂閱 | subscription | |
| 导入 | 匯入 | import | |
| 连接 | 連線 | connect / connection | 繁中用連線 |
| 断开 | 中斷連線 | disconnect | |
| 测活 | 測活 | test (connectivity test) | 真实握手测活 |
| 弱加密 | 弱加密 | weak encryption | 非 AEAD 老式加密 |
| 断网保护 | 斷網保護 | kill switch | |
| 系统代理 | 系統代理 | system proxy | |
| 分流（路由） | 分流（路由） | routing / split routing | 预留术语，尚无上屏文案 |
| 口令 | 密碼 | passphrase | 两岸惯例不同，各包保留自有用法 |
| 内核 | 核心 | kernel | 繁中用核心 |
| 日志 | 日誌 | log | |
| 凭据 | 憑證 | credentials | |
| 校验 | 校驗 | verification | 哈希/签名校验 |
| 流量 | 流量 | traffic | |
| 更新渠道 | 更新渠道 | update channel | |

英文/繁中译文质量抽查结论：除 1.3 所列外，未发现明显
机翻味或术语漂移；测活、断网保护等自造术语在三包内
用法一致。

## 3. 社区翻译入口

交付物（均在 `app/locales/`）：

- **README.md**：新增语言全流程（复制模板 → 逐条翻译 →
  校验 → PR → 母语者复核 → 维护者提升）、翻译纪律
  （风险组 `risk.*`/`security.*`/`update.err_*` 与
  `android.vpn_permission_*` 必须人工译、禁止机翻上岗；
  术语表必遵；占位符原样保留）、术语表（第 2 节）、
  成熟度规则（见下）、RTL 说明。
- **_template/**：模板包（134 键，值为英文原文 +
  `[UNTRANSLATED]` 前缀）与说明文件。模板**不在**
  `locales.Supported`、且 `locales.go` 的 embed 已改为
  显式三包清单（不再用通配），模板与进行中的社区包
  永远不会被打进二进制、不会被运行时加载。
- **校验工具扩展**：`i18n.CheckPacks` 新增未翻译标记
  检测（`UntranslatedKey`）与完整度百分比
  （`Completeness`）；`tools/i18ncheck` 新增
  `-extra lang,…`（报告任意进行中包的
  missing/extra/empty/untranslated 与完整度）与
  `-strict-extra`（不完整即失败退出）。**既有三包门
  不变且不回退**：默认运行（CI 口径）仍对三包全量
  硬失败，新增能力只作用于 -extra 指定的包。新增单元
  测试 `TestCheckPacksFlagsUntranslated` 钉住标记检测
  与完整度计算，并断言三包无任何标记残留。

**成熟度规则**：语言包未达 100%（missing=0、empty=0、
untranslated=0、完整度 100.0%）不得进入
`locales.Supported` 可加载集合；未达标的包只存在于
PR 中，校验工具如实报告其完整度。

### 3.1 演练留证（模板 → 空壳语言 → 校验如实报告）

在 /tmp 演练目录放入三包原件 + `ja`（模板原样复制）
+ `ko`（仅 3 键空壳），实跑
`go run ./tools/i18ncheck -locales /tmp/drill-locales
-scan ui,cmd -extra ja,ko -strict-extra`，摘要行：

```
pack zh-Hans  keys=134 missing=0 extra=0 empty=0 untranslated=0 completeness=100.0%
pack zh-Hant  keys=134 missing=0 extra=0 empty=0 untranslated=0 completeness=100.0%
pack en       keys=134 missing=0 extra=0 empty=0 untranslated=0 completeness=100.0%
pack ja       keys=134 missing=0 extra=0 empty=0 untranslated=134 completeness=0.0%
pack ko       keys=3   missing=131 extra=0 empty=0 untranslated=1 completeness=1.5%
```

退出码：`-strict-extra` 时为 **1**（不完整即拦截）；
不带 `-strict-extra` 时为 0（仅报告，维护者人工把关）。
模板包 134 个未翻译键逐条列出（UNTRANSLATED 行），
空壳包 131 个缺失键逐条列出（MISSING 行）——工具对
空壳语言如实报告，不存在「键齐即完成」的假象。

## 4. 无障碍基线（Gio v0.10.3 框架内如实分级）

### 4.1 对比度审计（全数达标，无配色改动）

UI 实际配色全部来自 Gio material 默认调色板（本壳未
自定义主题色）与一处错误文字色，按 WCAG 相对亮度公式
实算（正文 AA 门槛 4.5:1）：

| 文字/背景对 | 比值 | 结论 |
|---|---|---|
| 正文 #000000 on #FFFFFF（Fg on Bg） | 21.00:1 | 达标（AAA） |
| 按钮文字 #FFFFFF on #3F51B5（ContrastFg on ContrastBg） | 6.87:1 | 达标（AA） |
| 错误文字 #B02020 on #FFFFFF（ui.go 页脚错误行） | 6.83:1 | 达标（AA） |
| 输入框提示文字（Fg 以 0xBB alpha 混合，等效 #444444）on #FFFFFF | 9.74:1 | 达标（AA） |
| 文本选区底（ContrastBg 以 0x60 alpha 混合，等效 #B7BDE3）上正文 #000000 | 11.40:1 | 达标（AA） |

不达标项：**0**。本步未做任何配色调整。

### 4.2 键盘与焦点（框架具备 / 应用未验）

Gio 控件（Clickable/Button、Enum/RadioButton、Editor）
在框架层注册焦点过滤器并支持获得焦点后以
Return/Space 激活、Tab 在控件间移动焦点（已核
gioui.org v0.10.3 widget 源码）。本壳未做任何自定义
焦点处理、无快捷键与助记键，也未按 Tab 顺序做过
真键盘走查——**结论：主要流程具备键盘到达的框架
基础，应用级键盘走查未做，列真机/桌面验收项**
（见第 5 节），不宣称已无障碍。

### 4.3 触控目标尺寸盘点

高度为无头布局实测值（Metric 1.0、英文包，量法与
4.5 的布局测试同源）：

| 控件 | 实测高度 | 对照 48dp（Material 指南） | 对照 24dp（WCAG 2.2 AA 2.5.8 下限） |
|---|---|---|---|
| material.Button（页签/连接/导入等主按钮） | 37dp（14sp 文字 + 上下 10dp 内距，框架默认） | 不达 | 达 |
| 节点行（整行 Clickable） | 50dp（双行文字 + 上下 6dp 内距） | 达 | 达 |
| RadioButton 行（分组/语言单选） | 34dp（框架默认） | 不达 | 达 |

整改结论：按钮与单选行未达 48dp 指南值（达 WCAG AA
下限）。给主按钮与单选行统一加 48dp 最小高度约束是
**布局视觉变更**，需配合帧验证，不在本步（文案步）
内盲改；登记为待办（第 6 节），与后续 UI 帧验收批
一并处理。

### 4.4 屏幕阅读器语义（分平台如实说明）

Gio 框架会构建语义树：本壳使用的控件均发出语义标注
（Label 文本、Button/Editor 类、Selected/Enabled
状态，已核 v0.10.3 源码）。平台桥接分化明显：

- **Android**：Gio 驱动把语义树桥接到
  AccessibilityNodeInfo（os_android.go），TalkBack
  理论上可感知基本结构——**未在真机验证**，列真机项。
- **Windows（桌面主平台）**：所钉 Gio v0.10.3 的
  Windows 驱动**没有** UI Automation 无障碍桥接
  （已核 os_windows.go 无相关实现），即 Narrator/NVDA
  目前读不到本界面。这是**框架限制**，不是本壳的
  标注缺失；待 Gio 上游补齐或更换框架时再评估。
  **本产品不宣称 Windows 屏幕阅读器支持。**

### 4.5 字体缩放 / 系统大字体

无头布局演练（新增 `app/ui/a11y_layout_test.go`）：
三语 × 四页签 × 系统字号 1.0/1.3/2.0 × 三种窗口
（640×420 桌面最小、420×760、360×640）共 108 种组合，
含弱加密风险横幅的最长文案路径，全部完成布局、无
panic、返回尺寸不超约束。**视觉层面的溢出/截断/
重叠在无头环境无法判定，列真机项**（第 5 节）。

## 5. 真机待验项（并入 Step 15 真机清单口径）

1. Windows 真机：系统大字体（150%/200%）下四页签
   逐页眼验有无截断/重叠；键盘 Tab 全流程走查
   （节点选择→连接→导入→设置切换语言）。
2. Android 真机：TalkBack 朗读节点列表与设置页的
   实际效果；系统字体放大下布局眼验。
3. RTL 语言包落地时（如 ar/fa 社区包提升前）：布局
   翻转真机眼验（运行时方向报告已就绪，见 README）。

## 6. 待办（本步登记，非本步范围）

- 主按钮与单选行 48dp 最小触控高度统一整改
  （需帧验证配合，见 4.3）。
- Windows 屏幕阅读器：跟踪 Gio 上游 UIA 桥接进展
  （框架限制，见 4.4）。
- security.*/update.* 界面接线时直接消费 1.4 的
  预置键（归 Step 13/16 挂账的接线步）。

## 7. 回归

- `go run ./tools/i18ncheck`：三包 134 键全对齐，
  scan_violations=0，OK。
- app 全量测试通过：i18n（含新增标记检测测试）、ui
  （含新增字体缩放布局测试）、service、platform、
  android；libboxbind 需其文档记载的
  `-ldflags=-checklinkname=0` 旗标（libbox 步既有
  要求，与本步无关）加旗标后通过；plugins/vpngate
  通过。
- 交叉编译门：`GOOS=windows go build ./...`、
  `GOOS=android/arm64` 库包构建均通过。沙箱内两个
  cmd 入口的本机 cgo 链接缺 X11/EGL 系统库，为既有
  环境边界（CI 与交叉编译不受影响）。
