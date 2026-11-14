# Step 9：Windows 客户端 MVP（含多语言验收）

- 项目：Relavia（开源全协议代理客户端）
- 日期：2026-11-12
- 依据：方案书 3.6（多语言原生）、5.1/5.4、8.1/8.2（Windows 列）、第 14 章 Step 9 原文。
- 交付物：`app/` 新 Go 模块（`openproxy/app`，replace 指向 `../core`）：服务层 `service/`、i18n 引擎 `i18n/` + 语言包 `locales/`、平台抽象 `platform/`、Gio 壳 `ui/`、入口 `cmd/relavia/`、多语言检查工具 `tools/i18ncheck/`；CI 新增 `app` 作业。
- 总口径（先说清）：沙箱为 Linux、无 Windows 真机、无显示器。本步验收分两层——(a) 机器可验项已实测（见第 3、4 节）；(b) 真机项全部挂账（第 5 节），**一项都没有声称通过**。

## 1. UI 框架选型裁定：Gio

| 候选 | 结论 | 理由 |
|---|---|---|
| **Gio（gioui.org v0.10.3）** | **采用** | 纯 Go、CGO_ENABLED=0 即可从 Linux 交叉编译出 Windows.exe（本步硬要求，实测通过）；自带 Android 后端，Step 10 可复用服务层与大部分 UI 逻辑；不依赖系统 WebView。代价：即时模式 UI 需手写布局、控件集比 Fyne 薄、系统托盘无内置（本步托盘本来就走平台抽象，代价可控）。 |
| Fyne v2.8 | 不采用 | 桌面驱动依赖 cgo/GLFW：从 Linux 交叉编译 Windows 需要 mingw-w64 工具链或 fyne-cross/Docker，沙箱与当前 CI 均不具备，为一个工具链问题引入整套构建复杂度不划算。其余方面（控件丰富度、Android 路径）与 Gio 相当或略优，若将来构建环境变化可再议——UI 与服务层之间只有 `ui/` 一层，换框架不触及服务层与内核。 |
| Wails/网页壳 | 不采用 | 引入 WebView 与前端工具链，与 Go 单栈、离线可复现构建的口径冲突。 |

已知代价（如实记录）：Gio 无系统字体发现，内置 Go 字体**无中文字形**。本步对策：启动时按平台标准路径加载系统 CJK 字体（Windows 微软雅黑/繁中微软正黑、Linux Noto Sans CJK、macOS 苹方），加载不到则回退 Go 字体并在日志中明示（中文将显示为方框）。Windows 真机上的字形渲染列入真机清单 W-3。

> 增补（2026-11-14）：上段的「按平台路径加载系统 CJK 字体」对策已被取代——该路径表不含 Android，正是 KI-21（安卓中文全豆腐）的根因之一。现行口径为全平台内嵌 Noto Sans CJK + `ui.NewShaper()`（禁系统字体参与渲染），见 docs/android产品界面接入.md §11.5。本段保留为 Step 9 当时的历史记录。

## 2. 功能对照（8.1 通用功能 / 8.2 Windows 列）

状态口径：**机验** = 本机/CI 自动化实测通过；**待真机** = 已实现、仅编译验证，须 Windows 真机签收；**未实现** = 本步未做，写明归属步骤。

| 条目 | 状态 | 说明 |
|---|---|---|
| 节点增删改、排序 | 机验（服务层） | Store CRUD + MoveNode 排序，单测覆盖；UI 有删除与点选，拖拽排序未做（按钮式排序 API 已备，拖拽交互列后续 UI 打磨） |
| 分组管理 | 机验（服务层） | 分组随订阅导入自动登记，UI 单选切换；分组增删 API 已备，UI 按钮未做（同上打磨项） |
| 批量测活 | 机验（服务层） | TestGroup 全组真实握手（经适配器 TestHandshakeNode，非 ping），单测以 fake 引擎覆盖流程；真实节点握手由 Step 7 回环测试在 core CI 中持续验证 |
| 按国家/协议/延迟筛选 | 部分 | 分组维度可筛；国家维度依赖节点地理数据（模型无此字段，须来源侧补充），协议/延迟未做 UI 筛选——列为未实现（本步范围外打磨项） |
| 一键连接/断开 | 机验（服务层）+ 待真机（端到端） | Connect/Disconnect 全链路单测通过（fake 引擎）；与 sing-box 真适配器的连接在 Linux 开发构建上走 manual 模式本地监听，真机端到端列 W-4 |
| 自动选择（组内最低延迟） | 机验 | 见第 3 节弱加密裁定的选择侧实现与单测 |
| 故障自动切换（可关） | 未实现 | 归 Step 11/12 与连接策略一并落地（本步未在任务书内） |
| 系统代理模式（8.2 Windows v1.0） | 已实现**待真机**（设置层）/ 内核侧未接通 | platform 层 WinINet 代理设置（注册表 + InternetSetOption 刷新）为真实实现、仅编译验证（W-1）；但 sing-box 适配器当前 Platform.SystemProxy 自报 false、Start 拒绝 system-proxy 模式——UI 如实呈现「不可用」，模式接通归 Step 11 平台网络层 |
| TUN 模式（8.2 Windows v1.0，Wintun） | 未接通（检测骨架） | winTUN 仅探测 wintun.dll 在位与导出函数；建设备与接内核归 Step 11/12。适配器 Platform.TUN 自报 false，UI 如实呈现 |
| 路由分流（全局/规则/直连名单） | 未实现 | 归 Step 11（路由与 DNS），Config 结构按 Step 7 口径未提前扩字段 |
| 测活历史（仅本地） | 机验 | LastTest 落盘到节点记录（模型 5.2 字段），重启后仍在 |
| 断网保护（8.2 Windows v1.0） | 未实现 | 归 Step 12（双平台 kill switch）；适配器自报 false，UI 如实呈现 |
| DNS 防泄露策略、IPv6 开关与泄露检查入口 | 未实现 | 归 Step 11 |
| 配置加密备份与恢复、二维码分享 | 未实现 | 加密存储归 Step 13（本步 Store 为明文 JSON 替换点，见第 6 节）；二维码未排期至本步 |
| 实时流量 | 机验（服务层）+ 待真机显示 | QueryTraffic 采样与格式化有单测链路（fake 引擎）；UI 页脚每秒刷新，真机显示列 W-4 |
| 连接日志视图（本地、可清空） | 机验 | LogBuffer 环形缓冲 + UI 列表 + 清空按钮；日志只进本地，不外发 |
| 无障碍（高对比/屏幕阅读器） | 未实现 | Gio 无障碍支持有限，本步未做；如实登记为缺口，后续评估 |
| 多语言（三语完整、切换免重启、RTL 预留） | 机验 | 见第 4 节三项验收实测 |
| 系统托盘图标与菜单（Step 9 任务书） | 已实现**待真机** | Shell_NotifyIcon 真实实现（图标/提示/右键菜单/双击显示），菜单文案随语言切换重建；仅编译验证（W-2） |
| 导入入口（粘贴链接/订阅 URL/文件） | 机验 | ImportText / ImportSubscriptionURL / ImportFile（.ovpn、WireGuard.conf、订阅文件）全走 Step 8 解析器，单测覆盖链接导入与失败分流 |
| 扫码导入（8.2 Windows：文件/截图识别） | 未实现 | 本步导入为粘贴/文件路径形态；截图识别未做，登记缺口 |

## 3. 弱加密裁定的 UI 执行点（Step 5 冻结裁定落地）

冻结裁定要求：老式 SS 方法保留导入、必须警示、**不得默认推荐**。本步三处落地，全部有单测：

1. **分类**：`service.WeakEncryption` 按与解析器 `weakSSMethods` 镜像的方法集（cfb 系、chacha20/chacha20-ietf/xchacha20、rc4-md5、none）对任何来源的节点重新分类，不信任存储标记；导入时解析器警示码 `weak-encryption` 随节点落盘（`TestImportLinksAndWeakWarningFlow` 验证 legacy/modern 两节点分类与警示码）。
2. **呈现**：节点行对弱加密节点显示「弱加密」徽标（`node.weak_badge`）；节点被选中时，界面展示 `risk.weak_encryption` 全文风险告知（三语人工翻译，见第 4 节）；跳过证书校验的节点同理（徽标 + `risk.insecure_skip_verify` 全文）。
3. **选择**：`service.AutoSelect` 先按「非弱加密」分层、再按延迟排序——弱节点仅当分组内无其他测活成功节点时才会被选中。单测 `TestAutoSelectDeprioritizesWeak` 覆盖三场景：弱节点最快也不得当选（有 AEAD 节点时）、仅弱节点可用时可作兜底、无成功节点时返回空；端到端 `TestConnectTestAndAutoSelectFlow` 验证自动选择实际连接的是 AEAD 节点而非更快的弱节点。

## 4. 多语言验收（三项，实测结果）

语言包：`locales/<lang>/messages.json`，zh-Hans 为源语言全量撰写，zh-Hant 与 en 完整翻译，`risk.*` 风险告知词条逐条人工翻译（非机翻）。

| 验收项 | 方法 | 实测结果 |
|---|---|---|
| 三语文案完整性自动检查 | `tools/i18ncheck` + i18n 包单测 `TestShippedPacksAligned` / `TestRiskStringsPresentEverywhere` | 三包各 **87** 词条，键集合完全一致，缺失 0、多余 0、空值 0；risk.* 三条在每个包均存在且非空 |
| 语言切换免重启 | Translator 原子换包 + UI 语言单选即时重渲染 + 托盘菜单重建；i18n 单测 `TestRuntimeSwitchAndFallback` | 单测通过：切换后立即以新语言解析、缺失键回退英文、未加载语言切换被拒绝且不改变当前语言。真机界面肉眼确认列 W-5 |
| 无硬编码文案抽查 | i18ncheck 渲染层扫描（ui/、cmd/）：AST 提取全部字符串字面量，含汉字或 3+ 字母词形者即判违规，除非为词条键引用、路径类字面量或白名单（每条白名单须附理由注释，工具强制） | 违规 **0**。白名单共 15 条，全部为内部常量（托盘菜单 ID、GOOS/环境变量/字体文件名、SI 单位符号表、枚举状态值、诊断日志行），逐条理由在 `app/tools/i18ncheck/whitelist.txt` |
| RTL 架构预留 | i18n.DirectionOf 对 ar/fa/he/ur 返回 RTL，单测固化 | 架构预留完成（布局不写死方向）；本步不做阿语包（按任务书口径） |

候选批次顺序定版（8.1 要求 Step 9 开工前定版）：第二批（社区翻译就绪即上）日语、韩语；第三批西班牙语、俄语、葡萄牙语；第四批法语、德语、土耳其语、越南语、印尼语；RTL 批阿拉伯语、波斯语（随 RTL 布局实装一并上）。此顺序为工程建议，社区译者可得性可调整先后，不构成发版承诺。

## 5. 真机验收挂账清单（Windows 实机，全部未验）

| 编号 | 项目 | 通过标准 |
|---|---|---|
| W-1 | 系统代理设置层 | 在 Windows 10/11 实机 Set 后系统代理指向给定地址、浏览器流量走代理，Clear 后恢复直连；与 platform/sysproxy_windows.go 对照 |
| W-2 | 系统托盘 | 图标出现、提示正确、右键菜单（三语各验一遍）可点、双击唤起主窗口、退出项生效 |
| W-3 | CJK 字体渲染 | 简中/繁中界面无方框字，雅黑/正黑被正确加载 |
| W-4 | 端到端连接 | 实机导入真实订阅 → 测活 → 连接（manual 模式）→ 浏览器经本地监听地址出网 → 流量计数增长 → 断开恢复 |
| W-5 | 语言切换肉眼确认 | 三语逐项过界面：无截断、无未译键名裸露、托盘菜单同步切换 |
| W-6 | Windows 安装/分发形态 |.exe 在干净 Windows 环境直接运行（无 VC 运行时依赖问题）、杀软误报情况记录 |
| W-7 | 高 DPI 与窗口缩放 | 150%/200% 缩放下布局可用 |

## 6. 工程事实与遗留

- 构建实测：Linux `go build/vet/test./...` 全绿（app 模块单测 15 个：service 7、i18n 4、platform 4）；`GOOS=windows go vet` 通过（Windows 平台文件类型检查）；Windows 交叉编译产物见文末数据。
- CI 新增 `app` 作业：Linux 构建（含 Gio 系统头安装）、双目标 vet、单测、i18ncheck 门禁、Windows 交叉编译并上传 exe 构件。本步提交后由 CI 首跑验证（本地已按相同命令序列复现核心项；CI 实跑结果以仓库 Actions 为准，不在此预称）。
- Store 明文 JSON：`service/store.go` 文件头已标注——Step 13 加密存储的替换点就是该文件的 Document 编解码，调用方无感。文件权限 0600、目录 0700。
- 适配器能力如实呈现：设置页直接渲染适配器自报（TUN/系统代理/断网保护均为「不可用」+ `mode.capability_note` 说明），与 Step 7 的能力实情一致，无假装可用项。
- 未改动：spec/ 冻结文件、core/kernel 接口、core 既有代码均零修改（app 为独立模块，仅以 replace 引用 core）。

## 7. 交叉编译产物

- 命令：`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags "with_quic with_utls with_wireguard with_gvisor" -o dist/relavia.exe./cmd/relavia`（官方构建标签，与 Step 7 口径一致）
- 产物：`app/dist/relavia.exe`（dist/ 在.gitignore 内，不入库；CI 构件同名上传）
- 大小：**70,485,504 字节（约 67.2 MiB）**，PE32+ x86-64 Windows 可执行文件，sha256 前 16 位 `1db57ab3315b2436`（本地构建值，CI 构件以其运行为准）。
- 无标签构建对照：57,733,632 字节（约 55.1 MiB）——差异即 QUIC/uTLS/WireGuard/gVisor 特性集，与 Step 7 的能力自报口径一致：无标签构建能力矩阵更小且如实自报。

（完）
