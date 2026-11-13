# Relavia v0.1.0-beta.1 已知问题清单

> 状态：内部测试包已组装（CI run 43380743997 构件），公开发布待真机
> 测试与发布批准，本清单随包同行。日期：2026-11-13。
> 严重级定义：P0 = 阻断（数据丢失 / 安全失效 / 核心功能不可用）；
> P1 = 重要（核心功能未在目标环境验证，或重大使用限制）；
> P2 = 一般（功能降级或未接通，界面如实标注、有替代路径）；
> P3 = 轻微（体验项与工程债，无功能影响）。
> 每项标注来源文档与归属步骤，口径与各步文档原文一致，不缩水。

**P0：无已知 P0。** 以下 P1 共 6 项、P2 共 7 项、P3 共 6 项。

## P1

### KI-01 Android 真 TUN 未在真实设备验证
libbox 数据面绑定已达代码层完成、CI 合并 APK 已实出（原生库在包、
权限恰 5 条），TUN 启链在本机走通至 libbox 的 OpenTun；但 A-2 真
TUN 贯通、A-3 DNS 实证、A-4 后台保活、A-5 onRevoke、A-6 lockdown
衔接等真机项一项未验。来源：docs/libbox绑定.md §8；归属：真机清单。

### KI-02 Windows 真机全项未验
W-1 系统代理实际生效、W-2 托盘行为、W-3 CJK 字体渲染、W-4 端到端
连接、W-5 语言切换肉眼确认、W-6 分发形态、W-7 高 DPI，全部仅编译
或服务层验证，无一在 Windows 实机签收。来源：docs/step9-Windows
客户端MVP.md §5、docs/阶段1-汇总验收.md §4；归属：真机清单。

### KI-03 VPN Gate 节点在应用内尚不可连接
桌面 OpenVPN 独立进程适配器已就绪（本地自起服务端真实握手通过、
错证书被准确分类），但 app 服务层按协议分发的接线未完成（设计见
docs/openvpn进程适配.md §7）；且连接真实 VPN Gate 服务器的公网
握手（L5）未验。当前准入等级维持 parse + tcp-connect，界面标注
「可导入 / 可测活 / 不可连接」不变。来源：docs/step14-VPNGate
来源插件.md、docs/openvpn进程适配.md §7；归属：OpenVPN 接线后续步。

### KI-04 本地存储口令界面未接线（默认无口令模式）
加密存储数据层已就绪（Argon2id 派生 + XChaCha20-Poly1305，备份
强制加密），但口令设置 / 解锁屏 UI 未接线：当前构建默认以无口令
模式运行（节点与凭据存于权限 0600 的明文 JSON，文件与界面均带
降级标注，不得视为与加密模式等效）；经其他途径设过口令的存储，
在当前界面重启后无法解锁（会话表现为无节点可选）。来源：
docs/step13-本地安全存储与备份.md；归属：Step 13 挂账接线步。

### KI-05 Beta 更新渠道签名钥为过渡钥（TEST-ONLY）
本包的 update-beta.json 以客户端当前内嵌的 TEST-ONLY 测试钥签署：
客户端与清单同钥、验签链真实有效且已全链复核，但该钥的私钥存在
于仓库测试夹具中，不具备正式发行钥的保管等级，只认证「内容与本
Beta 构建同源」。v1.0 前由发行负责人生成正式钥、回填
app/service/releasekey.go 并随版本换钥；换钥后测试钥签出的清单
将被正式版客户端拒绝。来源：app/service/releasekey.go 横幅、
docs/step15-签名与可复现构建.md §9；归属：Step 20。

### KI-06 Android Beta 包为 debug 签名
合并 APK 的签名证书为 CN=Android Debug（证书 SHA-256
f1850fb259fbc7ff9bda9348a01fe6966c3eaa8241dd5f4f9591219c35126aa9），
可直接安装测试；v1.0 正式签名与之不同，届时必须先卸载 Beta 再装
正式版，应用数据不保留。来源：本步 apksigner 实查；归属：Step 20
发行签名。

## P2

### KI-07 Windows 客户端未做 Authenticode 签名
exe 首次运行会触发 SmartScreen「未知发布者」，需手动选择「仍要
运行」。这是既定发行口径（免费签名类别不收本项目、付费证书需
实名）：真伪验证走官网公布的 SHA-256 与更新清单 Ed25519 验签，
教程见官网 verify 页。来源：docs/step15-签名与可复现构建.md §8。

### KI-08 断网保护（kill switch）平台接线未完成
策略层与状态机已就绪（docs/step12-断网保护.md），但 Windows
防火墙 / Android lockdown 的实机阻断未验，适配器能力如实自报
不可用，界面不会宣称已启用。归属：Step 12 真机项。

### KI-09 应用内更新的安装环节未接通
更新的检查、下载与验签链完整可用，但：Windows 安装入口为诚实
占位（已验签的包保留在下载目录供手动安装）、Android 壳侧
InstallBinder 未接线、设置页更新区 UI 未接线。Beta 期间升级请到
GitHub Releases 手动下载新版本。来源：docs/step16-更新机制.md
§10；归属：Step 16 挂账。

### KI-10 公网 / DNS 泄露面未做公网实测
真实浏览器 WebRTC、公网解析器身份、UDP 传输 DNS、TUN 模式 DNS
劫持四项，待公网环境按 scripts/leak-check.sh 执行；沙箱内等价
证据（双假 DNS 日志 + 双 echo 令牌）已通过，不等同于公网结论。
来源：docs/step11-路由与DNS.md、docs/阶段1-汇总验收.md §4。

### KI-11 平台密钥库真实绑定未做
Windows DPAPI / Android Keystore 只交付 KeyWrapper 接口与全路径
fake 验证。口令派生加密路径本身可用（见 KI-04），本项影响的是
系统级密钥托管与自动解锁。来源：docs/step13-本地安全存储与
备份.md；归属：Step 13 挂账。

### KI-12 Windows 屏幕阅读器不支持
所钉 Gio 版本在 Windows 无 UIA 桥接（框架限制），不宣称支持；
Android 侧有 AccessibilityNodeInfo 桥接但 TalkBack 未真机验。
来源：docs/step18-本地化与无障碍基线.md §4/§5。

### KI-13 扫码导入未实现
接口与导入链路就绪，CameraX 集成与解码组件选型 / 许可证审计
未做；链接粘贴、订阅 URL、文件导入三种方式可用，界面对扫码
如实标注不可用。来源：docs/step10-Android客户端MVP.md。

## P3

### KI-14 触控目标高度未达 48dp 指南
主按钮 37dp、单选行 34dp（达 WCAG AA 的 24dp 下限）；统一整改
需帧验证配合。来源：docs/step18-本地化与无障碍基线.md §6。

### KI-15 Android SSID 类规则不匹配
壳未持 ACCESS_WIFI_STATE / 定位权限，ReadWIFIState 恒空，SSID
规则不匹配；桥已按真实形态实现，待权限决策。来源：
docs/libbox绑定.md §8 第 7 条。

### KI-16 双 spec 镜像未收敛
parsers 内部节点表示与 core/specnode 两份镜像并存（行为一致、
有测试钉住），属工程债，无用户影响。来源：docs/阶段1-汇总
验收.md §2；归属：后续集成步。

### KI-17 spec/ 独立许可证文本未补
方案书 §10.1 定 specs 适用独立宽松许可证，spec/ 目录下尚无
独立 LICENSE 文件。来源：阶段 0 验收遗留；归属：仓库治理项。

### KI-18 Android 合并 APK 体积较大
234,980,461 字节：gomobile AAR 含 arm64-v8a / armeabi-v7a /
x86 / x86_64 四 ABI 原生库，未做 ABI 拆分。功能无影响，下载
耗时较长。来源：本步组装实测。

### KI-19 更新清单默认 URL 真链路未验
客户端默认 beta 清单 URL 指向 GitHub Releases 的 latest 资产，
真实拉取待 Beta 正式发布后验证；本次发布前复核以本地等价全链
（客户端 Check → Download 验签）替代通过，不等同于公网链路
结论。来源：docs/step16-更新机制.md §10；发布后自然关闭。

## 状态说明

- 本清单全部条目均为「已登记、未关闭」，关闭以对应归属步的
  验收证据为准，不以本清单的措辞为准。
- 真实用户反馈闭环（Step 19 验收项）在公开发布后进行：反馈
  通道的仓库侧模板与指引已在本地备好，标签、Discussions 与
  通道开启待发布批准后执行。
