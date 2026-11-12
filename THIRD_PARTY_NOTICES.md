# 第三方组件声明（Third-Party Notices）

本文件汇总 Relavia 拟集成 / 已集成第三方组件的版权与许可证义务，依项目方案书 10.1 与 Step 2 许可证审计（docs/step2-许可证审计.md，硬门禁有条件通过）建立。

- 当前状态（阶段 0）：下列组件均来自 Step 2 审计登记，**尚未实际集成进产品代码**；集成状态列随 Step 7 起逐步更新。
- 每个正式发布包必须随附本文件（审计义务清单第 7 条）。
- 传递依赖的全量 SBOM 扫描于 Step 7 集成时补做并回填本文件（义务清单第 7 条后半）。
- 通用义务（义务清单第 2 条）：全产品不使用 sing-box/SagerNet、WireGuard/Wintun、OpenVPN、quic-go 的名称与标识暗示官方关联或背书；描述性提及与暗示性使用分开评审。

## 组件清单

| # | 组件 | 官方仓库 | 许可证（原文确认） | 集成形态 | 当前状态 |
|---|---|---|---|---|---|
| 1 | sing-box | SagerNet/sing-box | GPL-3.0-or-later ＋ 名称/关联附加条款 | 一期主挂接内核 | 已审计，未集成 |
| 2 | SoftEther VPN | SoftEtherVPN/SoftEtherVPN | Apache-2.0 | 第二梯队（VPN 类编排） | 已审计，未集成 |
| 3 | OpenVPN（2.x） | OpenVPN/openvpn | GPL-2.0-only ＋ OpenSSL / Apache2 / LZO 链接例外 | 仅独立进程随附分发 | 已审计，未集成 |
| 4 | wireguard-go | WireGuard/wireguard-go | MIT | WireGuard 隧道实现 | 已审计，未集成 |
| 5 | Wintun | WireGuard/wintun | 源码 GPL-2.0；官方预编译 DLL 为专有 Prebuilt Binaries License；Go 绑定 MIT | 仅官方预编译签名 DLL | 已审计，未集成 |
| 6 | quic-go | quic-go/quic-go | MIT（Logo/品牌资产除外） | QUIC 依赖（经 sing-box 传递） | 已审计，未集成 |
| 7 | uTLS | refraction-networking/utls | BSD-3-Clause | TLS 指纹层依赖 | 已审计，未集成 |
| 8 | Xray-core | XTLS/Xray-core | MPL-2.0 | 备选内核 | 已审计，未集成 |

## 逐项分发义务（依审计报告第 5 节）

1. **sing-box**：随附其授权声明原文与 GPLv3 全文；提供组合体完整对应源码；保留版权声明。不得使用 sing-box、SagerNet 名称或标识暗示官方关联/背书，宣传性使用须事先取得同意；描述性提及（如「兼容 sing-box 订阅格式」）与暗示关联严格区分。
2. **SoftEther VPN**：随附 Apache-2.0 全文；保留源码中的版权、专利、商标与署名声明及 NOTICE（如有）；修改过的文件带显著修改标注；不使用其商标背书。集成其二进制前（Step 30 交付前置项，义务清单第 5 条），逐项复核其 `src/THIRD_PARTY.TXT` 并登记结论。另：其 LICENSE 后附的日本法/地域声明（原文自述非许可证限制）于法律咨询时一并确认效力。
3. **OpenVPN 2.x**：只以独立进程二进制随附分发，随附其 COPYING 与 GPLv2 全文及对应源码获取途径；保留商标归属说明，不暗示 OpenVPN Inc 背书。**禁止**将其代码静态/动态链接进本项目 GPLv3 二进制，禁止改其源码并入主仓库。进程内需求改走 OpenVPN 3 核心库（AGPL-3.0 / MPL-2.0 双许可，采用前须对其仓库 LICENSE 原文做专项复核）。
4. **wireguard-go**：所有副本/实质部分保留版权声明与许可声明。"WireGuard" 为注册商标，只能描述性使用，不暗示 WireGuard LLC 背书。
5. **Wintun**：只分发 wintun.net 官方未修改签名 DLL（记录版本与校验值），仅经 `wintun.h`（Permitted API）调用，随附 Prebuilt Binaries License 全文，并在官网与包内明示其为**非开源组件**、属可复现构建例外（义务清单第 4 条）。不得用 WireGuard LLC / WireGuard / Wintun 名称背书。**禁止**自行编译或修改 wintun.dll 后分发。Go 绑定（MIT）在分发前以其仓库原文复核一次。
6. **quic-go**：保留版权与许可声明；不得使用其 Logo/品牌资产。个别源文件可能带其他宽松许可头，于 Step 7 SBOM 扫描时一并登记。
7. **uTLS**：源码与二进制分发均保留版权声明、许可条款与免责声明；不得以版权方/贡献者名义为衍生产品背书。
8. **Xray-core**：若启用，其源文件保持 MPL-2.0（义务清单第 6 条）：修改其文件后分发须以 MPL-2.0 提供该等文件源码并告知获取方式；不移除或篡改许可声明；执行体分发须告知接收者如何获取 MPL 部分源码；仓库内标清 MPL/GPL 文件边界；MPL 不授予商标权。
