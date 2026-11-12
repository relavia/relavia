# Step 2 许可证审计报告（阶段 0 · 硬门禁）

- 审计对象：《开源全协议代理客户端》方案书 v0.1 第 10.1 节与附录 B 登记的拟集成组件
- 审计基准：主仓库以 GPLv3 对外分发（方案书 10.1 裁定）；兼容性判断以「组件代码/二进制与本项目代码组合后，能否合法地以 GPLv3 整体分发」为准
- 审计方法：逐个打开各组件官方 GitHub 仓库的 LICENSE / COPYING 原文核对（2026-11-12），不以二手汇总为准；原文链接见各项末尾
- 审计范围：任务书指定的 8 个组件。sing-box 等组件的完整传递依赖树（go.mod 传递依赖）不在本次范围内，建议在 Step 7 集成时用 SBOM 工具（如 go-licenses）补做全量扫描，列为后续义务而非本次门禁未决项
- 免责：本报告为工程合规审计，不构成法律意见；重大分发决策建议按方案书附录 C 第 5 项做专业法律咨询

---

## 1. 逐项结论一览

| # | 组件 | LICENSE 原文确认的许可证 | 与 GPLv3 分发兼容性 | 关键条件 |
|---|---|---|---|---|
| 1 | sing-box | GPL-3.0-or-later ＋ 一条名称/关联附加条款 | 兼容（有条件） | 保留附加条款原文；不得用 sing-box/SagerNet 名称暗示关联 |
| 2 | SoftEther VPN | Apache-2.0 | 兼容 | 附许可证、保留署名/NOTICE、标注修改；另查其 THIRD_PARTY.TXT |
| 3 | OpenVPN（openvpn 2.x） | GPL-2.0-only ＋ OpenSSL 例外 ＋ Apache2 链接例外 ＋ LZO 例外 | **有条件兼容（不得同二进制链接）** | 只能以独立进程二进制形式随附分发；进程内实现改用 OpenVPN 3（见 3.3） |
| 4 | wireguard-go | MIT | 兼容 | 保留版权与许可声明 |
| 5 | Wintun | 源码 GPL-2.0；官方预编译 wintun.dll 为专有 Prebuilt Binaries License；Go 绑定为 MIT | **有条件兼容（仅预编译 DLL 路径）** | 只分发 wintun.net 官方未修改 DLL、仅经 wintun.h 接口使用、随附其许可证、明示该组件非开源 |
| 6 | quic-go | MIT（Logo/品牌资产除外） | 兼容 | 保留声明；不得使用其 Logo |
| 7 | uTLS | BSD-3-Clause | 兼容 | 保留版权声明与免责条款；不得以版权方名义背书 |
| 8 | Xray-core（备选内核） | MPL-2.0 | 兼容 | MPL 文件保持 MPL-2.0、公开其源码；组合体按 GPLv3 分发（Secondary License 机制） |

**总结论：硬门禁可通过（有条件通过）**——不存在无解的不兼容项；OpenVPN 与 Wintun 两项存在「按原设想集成即违规」的路径，已有明确替代/隔离方案（第 4 节），其余六项直接兼容。通过条件清单见第 5 节，须回写方案书（第 6 节）。

---

## 2. 逐项审计

### 2.1 sing-box（SagerNet/sing-box）— 一期主挂接内核

- 官方仓库：https://github.com/SagerNet/sing-box
- 原文确认：仓库 LICENSE 文件**不是 GPL 全文，而是一页授权声明**：版权方 nekohasekai，声明以 GNU GPL「version 3 of the License, or (at your option) any later version」授权，即 **GPL-3.0-or-later**；声明末尾另有一句附加条款（原文）："In addition, no derivative work may use the name or imply association with this application without prior consent."
- 兼容性结论：**兼容（有条件）**。GPL-3.0-or-later 允许将组合体按 GPLv3 分发，与方案书路线一致。附加条款属 GPLv3 第 7 条框架下的附加条款（名称/关联限制，与商标法不授予权利一脉相承），下游项目普遍将其作为须保留的 §7 条款处理。
- 分发义务：随附该授权声明原文与 GPLv3 全文；提供组合体完整对应源码；保留版权声明。
- 风险/注意：
  - **不得使用 sing-box、SagerNet 名称或标识暗示官方关联/背书**；确需在产品名、宣传中使用其名称须事先取得同意。描述性提及（「兼容 sing-box 订阅格式」）与暗示关联须严格区分——此条与方案书 10.2 的商标政策方向一致，执行时并入品牌规范。
  - 本项目主许可证措辞建议明确为 **GPL-3.0-or-later**（见发现 F-5），以便与 sing-box 的 or-later 授权及未来组件衔接无歧义。
- 原文：https://raw.githubusercontent.com/SagerNet/sing-box/25a600db24f7680ad9806ce5427bd0ab8afe1114/LICENSE

### 2.2 SoftEther VPN（SoftEtherVPN/SoftEtherVPN）

- 官方仓库：https://github.com/SoftEtherVPN/SoftEtherVPN （稳定版仓库 SoftEtherVPN_Stable 的 LICENSE 与主仓库一致）
- 原文确认：LICENSE 文件为 **Apache License 2.0** 全文，附录版权行为 SoftEther VPN 项目贡献者、筑波大学 SoftEther 项目与 SoftEther Corporation；文件后半附 DISCLAIMER 段落，其中含日本法管辖与「仅限日本使用」等声明，但原文明确标注 "NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A STATEMENT FOR WARNING AND DISCLAIMER"（该段自述为警告/免责声明而非许可证限制）。
- 兼容性结论：**兼容**。Apache-2.0 与 GPLv3 单向兼容（Apache-2.0 代码可并入 GPLv3 组合体分发），与方案书 10.1 的判断一致；Apache-2.0 的专利授权与专利诉讼终止条款在 GPLv3 下无冲突。
- 分发义务：随附 Apache-2.0 全文；保留源码中的版权、专利、商标与署名声明及 NOTICE（如有）；修改过的文件须带显著修改标注；不使用其商标背书。
- 风险/注意：
  - SoftEther 发行物内含第三方组件，其条件登记于仓库 `src/THIRD_PARTY.TXT`（含 OpenSSL 等）。**集成 SoftEther 二进制时必须逐项复核该文件**，本次审计未展开，列为 Step 30（SoftEther 编排步）的交付前置项，不构成本次门禁未决项的原因是：SoftEther 属第二梯队（v1.x），且该文件为上游官方登记、路径明确。
  - LICENSE 后附的日本法/地域声明虽自述非许可证限制，仍建议在法律咨询时一并请律师确认其对分发者的实际效力，避免只按工程口径理解。
- 原文：https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/blob/master/LICENSE

### 2.3 OpenVPN（OpenVPN/openvpn，2.x 社区版守护进程）

- 官方仓库：https://github.com/OpenVPN/openvpn
- 原文确认：COPYING 文件载明 "OpenVPN is distributed under the GPL license version 2"，**全文无 or-later 授权语言，按 GPL-2.0-only 处理**。COPYING 同时载有三项链接例外（均为 OpenVPN 官方授予）：
  1. **OpenSSL 例外**：允许将 OpenVPN 与 OpenSSL 库（或同许可证的修改版）链接并分发组合体——解决旧版 OpenSSL 许可证与 GPLv2 的经典冲突；注意 OpenSSL 3.0 起已改用 Apache-2.0，该例外的实际必要性下降；
  2. **Apache2 链接例外**：允许 OpenVPN 链接 Apache-2.0 库并分发组合体，无须把该库置于 GPLv2 之下——解决 GPLv2 与 Apache-2.0 的不兼容；但组合体其余部分仍须履行 GPLv2，且该库自身若禁止此种链接则例外不覆盖；
  3. **LZO 例外**：LZO 作者授予 OpenVPN 项目同时链接 LZO 与 OpenSSL 的特别例外。
  另：COPYING 开头注明 "OpenVPN" 为 OpenVPN Inc 商标，且发行物含多组件、各有其许可证。
- 兼容性结论：**有条件兼容**。GPL-2.0-only 与 GPLv3 在同一程序内链接组合属经典不兼容（GPLv2 不接受 GPLv3 的附加条件，GPLv3 亦然），**不得将 OpenVPN 2.x 代码静态/动态链接进本项目 GPLv3 二进制，也不得改其源码并入主仓库**。但以**独立可执行文件**形式随安装包分发、由本项目以命令行参数/配置文件/标准输入输出与其交互（独立进程、臂长协作），属两个独立程序的聚合分发，不构成组合体，是业界通行做法（如主流 GUI 客户端捆绑 openvpn.exe 的模式），在此形态下兼容。
- 分发义务（独立进程形态）：随附 OpenVPN 的 COPYING 与 GPLv2 全文；提供其对应源码或有效的源码获取途径；保留商标归属说明，不得暗示 OpenVPN Inc 背书。
- 替代方案（进程内实现的场合）：**OpenVPN 3 核心库**（OpenVPN/openvpn3）为客户端库形态，官方 LICENSE 页载明其以 **AGPL-3.0 或 MPL-2.0 双许可证**分发（并附 AGPLv3 下链接 OpenSSL 的 §7 附加许可）——任选其一均与 GPLv3 路线兼容，可作进程内集成候选。若一期确定需要进程内 OpenVPN，改走此路线；代价：OpenVPN 3 为纯客户端库（无服务端/守护进程功能）、接入工作量与行为对齐需重新评估，且采用前须对其仓库 LICENSE 原文再做一次专项复核（本次仅核到其官方文档站的 LICENSE 页）。
- 原文：https://raw.githubusercontent.com/OpenVPN/openvpn/master/COPYING ；替代项：https://openvpn.github.io/openvpn3/md_LICENSE.html

### 2.4 wireguard-go（WireGuard/wireguard-go）

- 官方仓库：https://github.com/WireGuard/wireguard-go （GitHub 为镜像，官方仓库在 git.zx2c4.com，内容一致）
- 原文确认：LICENSE 为标准 **MIT** 文本，版权方 WireGuard LLC（2017–2025）。
- 兼容性结论：**兼容**。MIT 为宽松许可证，可并入 GPLv3 组合体。
- 分发义务：所有副本/实质部分保留版权声明与许可声明。
- 风险/注意："WireGuard" 为注册商标，许可证不授予商标权；产品文案中只能描述性使用，不得暗示 WireGuard LLC 背书（与 2.5 的 Wintun §3(e)、2.1 的 sing-box 条款同属「名称克制」义务族，建议合并执行）。
- 原文：https://github.com/WireGuard/wireguard-go （仓库 LICENSE 文件，README License 节同文）

### 2.5 Wintun（WireGuard/wintun）— 本次审计最特殊的组件

- 官方仓库：https://github.com/WireGuard/wintun （镜像；官方源在 git.zx2c4.com/wintun）
- 原文确认：Wintun 是**三层许可结构**，必须分开看：
  1. **驱动源码**：仓库 COPYING 为 GPLv2 全文，README 明示 "Source code is licensed under the GPLv2"（原文未见 or-later 授权语言）。即自研构建 wintun.dll 走 GPL-2.0 路径；
  2. **官方预编译 wintun.dll**：**不是开源许可**，适用单独的 **Prebuilt Binaries License**（专有许可，WireGuard LLC 所有）。其官方站明示：预编译签名 DLL 是「唯一受支持的分发方式」，且其许可「比 GPL 2.0 更宽松」（指分发场景）。该许可核心条款（原文 §3）：不得逆向/反编译/修改（§3a）；不得基于其创作衍生作品，但仅通过随附 `wintun.h` 定义的 Permitted API 使用不在此限（§3b）；不得移除专有声明/版权（§3c）；**不得转售、再分发、转让，但「随同仅经 Permitted API 使用它的其他软件一同分发」除外**（§3d）；不得用 WireGuard LLC / WireGuard / Wintun 名称背书（§3e）。违约即自动终止，须删除并停止分发（§6）；
  3. **Go 绑定**（golang.zx2c4.com/wintun，即 sing-tun 等实际调用的封装层）：MIT（据上游与下游项目的声明登记；本次未单独打开该子仓库 LICENSE，分发前以其仓库原文复核一次即可，风险低）。
- 兼容性结论：**有条件兼容（仅预编译 DLL 路径）**。GPLv3 项目随附该 DLL 属「GPL 程序 + 独立专有组件的聚合分发」：DLL 不链接进 GPL 二进制的源码组合体、仅以独立文件形式随包、且其许可 §3d 明确授权此种随同分发，故不违反 GPLv3；项目**必须**满足的条件是：只用 wintun.net 官方 zip 中的未修改签名 DLL；仅经 wintun.h 接口调用；随包附 Prebuilt Binaries License 全文；不在任何文案中暗示背书。
- **禁止路径**：自行编译 GPL-2.0 源码版 wintun.dll 并分发——除 GPL-2.0-only 与 GPLv3 的组合问题外，自行构建的驱动不带微软签名将无法在默认配置的 Windows 上加载，且官方明确表示预编译 DLL 是唯一受支持分发方式。此路径直接排除，不作为备选。
- 风险/注意：
  - **Windows 安装包将含一个非开源组件**。项目对外表述须诚实标注（官网/包内 THIRD_PARTY 说明），不得宣称「Windows 版 100% 开源」；可复现构建的口径须把 wintun.dll 列为外部二进制例外并记录其官方校验值（此点须回写方案书 9.2/Step 15 的可复现构建条目，见第 6 节）。
  - sing-box 的 sing-tun 在 Windows 构建中内嵌同一 wintun.dll，这是上游已在采用的同一合规路径，但**分发责任在本项目**，不能以上游做了为由免除本项目的随附许可证与标注义务。
- 原文：https://github.com/WireGuard/wintun/blob/master/COPYING ；https://git.zx2c4.com/wintun/plain/prebuilt-binaries-license.txt ；https://www.wintun.net/

### 2.6 quic-go（quic-go/quic-go）— sing-box 的 QUIC 依赖代表

- 官方仓库：https://github.com/quic-go/quic-go
- 原文确认：LICENSE 为标准 **MIT** 文本。项目 README 补充：代码为 MIT，**Logo 与品牌资产不包含在 MIT 授权内**，另有 assets/LICENSE.md 约束。
- 兼容性结论：**兼容**。
- 分发义务：保留版权与许可声明；不得使用 quic-go 的 Logo/品牌资产。
- 风险/注意：个别源文件可能带其他宽松许可头（如 BSD 风格），均为 GPL 兼容的宽松条款，Step 7 做 SBOM 全量扫描时一并登记即可。
- 原文：https://github.com/quic-go/quic-go/blob/v0.59.0/LICENSE

### 2.7 uTLS（refraction-networking/utls）— 指纹层依赖代表

- 官方仓库：https://github.com/refraction-networking/utls
- 原文确认：LICENSE 为 **BSD-3-Clause**（仓库许可证标识与源文件头「BSD-style license」一致；其代码源自 Go 标准库 crypto/tls 的 fork，Go 本体亦为 BSD-3-Clause）。
- 兼容性结论：**兼容**。BSD-3-Clause 可并入 GPLv3 组合体。
- 分发义务：源码与二进制分发均须保留版权声明、许可条款与免责声明；不得以版权方/贡献者名义为衍生产品背书（BSD 第三条）。
- 风险/注意：无实质风险；注意其最小 Go 版本要求随上游滚动（如 README 所示的 Go 版本下限），属工程事项非许可事项。
- 原文：https://github.com/refraction-networking/utls （仓库 LICENSE 文件）

### 2.8 Xray-core（XTLS/Xray-core）— 备选内核

- 官方仓库：https://github.com/XTLS/Xray-core
- 原文确认：LICENSE 为未改动的 **Mozilla Public License Version 2.0** 全文（含 Exhibit A/B 模板文本，此为 MPL 标准模板组成部分，不构成对本软件附加的 Incompatible With Secondary Licenses 声明）。
- 兼容性结论：**兼容**。MPL-2.0 为文件级弱 copyleft：其 §1.12 将 GPLv2、LGPLv2.1、AGPLv3「及上述许可证的任何后续版本」定义为 Secondary License，GPLv3 在此列；§3.3 明确允许在 Larger Work 中将 Covered Software 与 Secondary License 作品组合并按 Secondary License 分发组合体（前提是 Covered Software 未被标为与 Secondary License 不兼容——Xray-core 未作此标注）。故 Xray-core 可作为备选内核与本项目 GPLv3 代码组合分发，**不存在与 GPLv3 路线的冲突**。
- 分发义务：Xray-core 的源文件保持 MPL-2.0（修改其文件后分发须以 MPL-2.0 提供该等文件的源码并告知获取方式）；不得移除或篡改其许可声明；执行体分发须告知接收者如何获取 MPL 部分源码；MPL 不授予商标权。
- 风险/注意：义务以「文件」为单位而非整体，混排目录时须在仓库层面把 MPL 文件与 GPL 文件的边界标清（文件头即边界），避免后续贡献者误改授权。
- 原文：https://github.com/XTLS/Xray-core/blob/main/LICENSE

---

## 3. 跨组件关键问题：GPL-2.0-only 孤岛

本次审计唯一的结构性不兼容来自 **GPL-2.0-only 阵营**（OpenVPN 2.x、Wintun 源码）：GPL-2.0-only 与 GPLv3 代码在同一程序内链接组合不被任一许可证接受。两项均已有不触碰该红线的集成形态（独立进程 / 官方预编译聚合分发），故定为「有条件兼容」而非「不兼容」。任何后续设计变更若触及以下红线，须回到本审计复核：

- 把 OpenVPN 2.x 代码（或改其源码）编进主程序；
- 自行构建或修改 wintun.dll 后分发；
- 把 Wintun 源码编进 GPLv3 二进制。

## 4. 总结论

**Step 2 硬门禁：可通过（有条件通过）。**

- 无未决不兼容项：8 个组件中 5 个直接兼容（SoftEther、wireguard-go、quic-go、uTLS、Xray-core），1 个兼容附名称条款（sing-box），2 个有明确合规集成形态（OpenVPN 独立进程、Wintun 官方预编译 DLL）。
- 通过条件即第 5 节义务清单，须在 Step 7（内核集成）与 Step 15（发布工程）验收时逐项核对。
- 两个条件项的替代方案与代价：
  - OpenVPN：默认方案为独立进程捆绑（代价：安装包体积增加、进程管理与跨平台路径适配工作量）；备选为 OpenVPN 3 库进程内集成（代价：接入与行为对齐重估、采用前补一次其仓库 LICENSE 原文专项复核）。
  - Wintun：默认方案为官方预编译 DLL（代价：Windows 包非 100% 开源，须对外标注；可复现构建留例外项）。不存在可接受的自建替代（签名与官方支持双重原因），故此项为长期固定形态而非临时妥协。

## 5. 通过条件 / 分发义务总清单（供 Step 7、Step 15 验收引用）

1. 主仓库 LICENSE 明确采用 GPL-3.0-or-later（见 F-5），随附 GPLv3 全文与 sing-box 授权声明原文。
2. 全产品不使用 sing-box/SagerNet、WireGuard/Wintun、OpenVPN、quic-go 的名称与标识暗示官方关联或背书；描述性提及与暗示性使用分开评审。
3. OpenVPN 2.x 只以独立进程二进制随附分发，随附其 COPYING 与 GPLv2 全文及源码获取途径；禁止链接进主二进制。
4. Wintun 只分发 wintun.net 官方未修改签名 DLL（记录版本与校验值），仅经 wintun.h 调用，随附 Prebuilt Binaries License 全文，并在官网与包内明示其为非开源组件、可复现构建例外。
5. SoftEther 集成步（Step 30）交付前，逐项复核其 `src/THIRD_PARTY.TXT` 并登记结论。
6. Xray-core 若启用：其文件保持 MPL-2.0，仓库内标清 MPL/GPL 文件边界，提供 MPL 部分源码获取途径。
7. 建立 THIRD_PARTY_NOTICES 文件汇总全部组件的版权与许可证文本，随每个正式包发布；Step 7 集成时补做传递依赖全量 SBOM 扫描并回填本清单。

## 6. 与方案书附录 B 初步口径不一致之处（发现清单，须回写方案书）

- **F-1（OpenVPN，重要）**：附录 B 仅记「GPL 系」，过于含糊。原文为 **GPL-2.0-only ＋ 三项链接例外**，与 GPLv3 同二进制链接不兼容。方案书 5.1 将 OpenVPN 与 sing-box 并列在「内核层（可插拔）」同一格，未区分集成形态。**须回写**：在 5.1/5.4 注明 OpenVPN 走独立进程适配（或 OpenVPN 3 路线），不得与主内核同二进制链接。
- **F-2（Wintun，重要）**：附录 B 仅记「逐项登记其分发条款」。原文结构为：源码 GPL-2.0、**预编译 DLL 为专有许可且非开源**、仅授权随同经 wintun.h 使用的软件分发。**须回写**：方案书 9.2「可复现构建」与 Step 15 条目须为 wintun.dll 留外部二进制例外并记录校验值；对外口径不得宣称 Windows 版整体开源。
- **F-3（sing-box，补充）**：附录 B 的 GPL-3.0-or-later 与原文一致，但**漏记 LICENSE 末尾的名称/关联附加条款**。须回写附录 B 并纳入品牌规范（义务清单第 2 条）。
- **F-4（SoftEther，补充）**：Apache-2.0 与原文一致；但 LICENSE 后附日本法管辖与地域使用声明（原文自述非许可证限制）及 `src/THIRD_PARTY.TXT` 的内含第三方组件两项，附录 B 未提及。须回写为 Step 30 前置复核项，法律咨询时一并确认声明效力。
- **F-5（主许可证措辞，建议）**：方案书 10.1 与总表第 8 条只写「GPLv3」，未区分 GPL-3.0-only 与 GPL-3.0-or-later。结合 sing-box 的 or-later 授权与 Xray-core 的 Secondary License 路径，建议主仓库在 Step 4 落地时明确采用 **GPL-3.0-or-later**，消除后续解释空间。此项为措辞澄清，不改变已裁定的 GPLv3 路线。
- **F-6（登记表补全）**：附录 B 中「QUIC / TLS / uTLS 相关库：逐项登记」一项，本次已落实两项代表：quic-go 为 MIT（Logo 除外）、uTLS 为 BSD-3-Clause，均兼容；余下传递依赖以 Step 7 的 SBOM 扫描补全，不留空项过关。

（完）
