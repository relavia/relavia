# OpenVPN 3 核心库许可证专项审查（安卓进程内集成）

- 审查对象：OpenVPN/openvpn3 核心库（下称 openvpn3），拟用于 Relavia 安卓端在同一 APK、同一进程内承载 OpenVPN 会话（主要供 VPN Gate 池节点连接）。
- 审查时点与版本锚：2026-11-14 实查官方仓库 master，HEAD `0c1ce172fe918b05463d71e682a0c2f2d8fe7899`；`vcpkg.json` 的 version-string 为 3.12。后续构建尖峰与集成以此提交（或届时复核过的等价 tag）为钉死版本，升级版本须重过本审查的原文核对项。
- 本项目许可基线：Relavia 主许可证 GPL-3.0-or-later（Step 4 定版）；分发形态为单一 APK 同进程组合。项目既有红线（Step 2 审计）：GPL-2.0-only 代码不得同进程链接进 GPLv3 组合体（ics-openvpn 因此出局）。
- 性质声明：本审查为工程口径的许可证兼容性判断，逐字依据下列官方原文；不构成法律意见。正式发布前如做付费法律咨询，本文件所列条款点应一并提交律师复核（与 Step 2 审计既有口径一致）。

## 1. 结论

**可接** —— 条件是：**取 MPL-2.0 一侧**集成 openvpn3，并履行第 4 节义务清单。AGPL-3.0-only 一侧不取（理由见第 3 节）。

## 2. 原文证据（逐字核对）

### 2.1 仓库 LICENSE.md（master 根目录，原文）

> OpenVPN 3 is distributed under
> [GNU Affero General Public License version 3](LICENSES/AGPL-3.0-only.txt)
> or [Mozilla Public License Version 2.0](LICENSES/MPL-2.0.txt).
>
> with a special permission to link against OpenSSL when using AGPLv3:
> "Additional permission under GNU AGPL version 3 section 7 — If you modify this Program, or any covered work, by linking or combining it with OpenSSL (or a modified version of that library), containing parts covered by the terms of the OpenSSL License or the Original SSLeay License, the licensors of this Program grant you additional permission to convey the resulting work. …"
>
> Note that this special permission is only needed for OpenSSL versions older than OpenSSL 3.0 as OpenSSL 3.0 uses the Apache 2.0 license instead.

- 官方文档站的 LICENSE 页（openvpn.github.io/openvpn3/md_LICENSE.html）与仓库 LICENSE.md 同文，互为印证（Step 2 审计 §2.3 当时只核到文档站，本次已补核仓库原文，结论一致）。
- 出处：https://raw.githubusercontent.com/OpenVPN/openvpn3/master/LICENSE.md ；https://openvpn.github.io/openvpn3/md_LICENSE.html

### 2.2 源文件头 SPDX（抽查 client/ovpncli.hpp）

> SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
> Copyright (C) 2012- OpenVPN Inc.

文件级标记与 LICENSE.md 的双许可一致，且**未出现 MPL-2.0 Exhibit B 的「Incompatible With Secondary Licenses」声明**（该声明只有被实际写入文件通知时才生效；仓库 LICENSE.md 与抽查文件头均无）。这意味着即便走 MPL 的「次级许可证」机制，openvpn3 也未自我排除与 GPL 的组合——本项目取 MPL 一侧的路径不受此限。

### 2.3 依赖清单（vcpkg.json，version-string 3.12，原文枚举）

运行时依赖：asio、fmt、jsoncpp、lz4、openssl、xxhash；`tap-windows6` 仅 Windows（安卓不涉及）；`gtest` 为 host/测试依赖（不入 APK）。TLS 后端二选一：OpenSSL 3（Apache-2.0）或 mbedTLS（构建开关 `USE_MBEDTLS`）。可选 lzo（上游 README 列为 optional）——**本项目禁用**（见 3.3）。

## 3. 兼容性分析

### 3.1 取 MPL-2.0 一侧：与 GPL-3.0-or-later 同进程组合 —— 兼容

- MPL-2.0 是文件级弱 copyleft。其 §3.3 允许将 MPL 覆盖文件置于一个「Larger Work」中并以其他条款分发该整体，条件是 MPL 文件本身持续满足 MPL（源码可得、保留通知、修改过的文件仍以 MPL 提供）。GPLv3 组合体属于此类 Larger Work，条款间无互斥点：MPL 不对整体施加与 GPLv3 冲突的条件，GPLv3 也不禁止与满足其自身条款的 MPL 文件共存（FSF 将 MPL-2.0（无 Exhibit B 排除时）列为与 GPL 兼容）。
- 组合结果：Relavia 自有代码与整体分发继续按 GPL-3.0-or-later；openvpn3 的文件仍属 MPL-2.0 覆盖软件，须按第 4 节提供其源码与通知。**不得**把 openvpn3 文件改头换面并入本项目源码树冒充自有代码；集成形态为「钉死上游版本、经其构建系统编译、胶水代码（Kotlin/Java/Go）放在我方独立文件里调用其公开 API」。

### 3.2 AGPL-3.0-only 一侧：不取

- AGPL-3.0-only 与 GPL-3.0-or-later 的组合在 GPLv3 §13 的明示许可下并非绝对不可行，但组合体将背上 AGPL §13 的网络交互源码提供义务解释负担，且「-only」与本项目「-or-later」代际口径的衔接存在解释空间。既有 MPL 路径干净可用，无理由走 AGPL 侧。此项记为已评估的否决备选。

### 3.3 依赖逐项（均与 GPLv3 组合兼容）

| 依赖 | 许可证 | 备注 |
|---|---|---|
| asio | BSL-1.0 | 宽松，可并入 GPLv3 组合体 |
| fmt | MIT | 同上 |
| jsoncpp | MIT（上游另有 public domain 选项，取 MIT 口径登记） | 同上 |
| lz4（库部分） | BSD-2-Clause | 同上；lz4 仓库中 CLI 工具的 GPLv2 部分不引入、不分发 |
| xxhash（库） | BSD-2-Clause | 同上 |
| OpenSSL 3.x | Apache-2.0 | 与 GPLv3 兼容；与 openvpn3 的 AGPL 侧例外无关（我们取 MPL 侧亦无冲突） |
| mbedTLS（备选 TLS 后端） | Apache-2.0（3.x 起）/ 双许可中取 Apache-2.0 | 若构建尖峰改用 mbedTLS 按此登记，二选一最终以尖峰结论为准 |
| lzo | GPL-2.0-only | **禁用**：openvpn3 中为可选压缩依赖，构建时不启用（配置不带 LZO），从根上避开项目红线；VPN Gate 常见配置不依赖 lzo |

- OpenVPN 商标：许可证不授予商标权；产品文案仅作描述性使用（「支持 OpenVPN 协议」），不得暗示 OpenVPN Inc 背书——与 Step 2 审计对 WireGuard/Wintun 的「名称克制」义务同族，沿用既有执行方式。

### 3.4 备选路线对照（均不作候选，仅存档）

- **ics-openvpn**：OpenVPN 2.x 的 JNI 同进程形态，整体 GPLv2（且其内嵌的 OpenVPN 2.x 为 GPL-2.0-only）——触碰红线，排除（Step 2 审计与 docs/openvpn进程适配.md §6 既有结论，本次复核维持）。
- **OpenVPN 2.x 独立进程**（桌面已落地形态）：安卓上外部进程路线不可行（应用沙箱无法随包携带并 exec 独立守护进程的现实约束），排除——此为本项目立项背景，不赘述。
- 其他可嵌入实现：未发现有维护状态可接受的第三方 OpenVPN 协议进程内实现（协议复杂、主流实现只有 openvpn3 与 2.x 两支）。如未来出现，须另行专项审查后方可替换本结论。

## 4. 采用义务清单（取 MPL-2.0 侧，集成与发布时逐项执行）

1. THIRD_PARTY_NOTICES 增补 openvpn3 条目：MPL-2.0、版权归 OpenVPN Inc、钉死版本与上游仓库地址、许可证全文随附（应用内/仓库内）。
2. MPL 覆盖源码可得性：分发 APK 时须能提供 openvpn3 对应源码——本项目整体开源，直接在本仓库登记钉死版本与获取路径即可满足；**若将来对 openvpn3 源码有任何修改，修改过的文件必须继续以 MPL-2.0 提供源码**（原则上不改上游文件；确需补丁时，补丁文件独立存放并显著标注）。
3. 保留上游版权与 SPDX 通知（不剥离、不改写）。
4. 构建配置红线：不启用 LZO；不混入 lz4/xxhash 仓库中的 GPLv2 工具部分（只用库目标）。
5. 版本钉死与升级复核：openvpn3 或其依赖版本变动时，复核 LICENSE.md 与 vcpkg.json 是否变化，变化则更新本文件与 THIRD_PARTY_NOTICES。
6. 商标克制：仅描述性使用「OpenVPN」字样，不暗示官方背书。

## 5. 审查边界

- 已核：仓库 LICENSE.md 原文、官方文档站 LICENSE 页、client/ovpncli.hpp 文件头 SPDX、vcpkg.json 依赖枚举。
- 未逐一核：openvpn3 全部源文件的 SPDX 头（抽查制）；javacli（Java/SWIG 绑定）子目录的个别文件头。其与核心同仓同 LICENSE.md 覆盖，风险低；构建尖峰阶段若实际引入 javacli 产物，再补一次该子目录抽查并回填本节。
