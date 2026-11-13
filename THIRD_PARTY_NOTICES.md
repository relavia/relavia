# 第三方组件声明（Third-Party Notices）

本文件汇总 Relavia 拟集成 / 已集成第三方组件的版权与许可证义务，依项目方案书 10.1 与 Step 2 许可证审计（docs/step2-许可证审计.md，硬门禁有条件通过）建立。

- 当前状态（Step 7 后）：sing-box 已实际集成进产品代码（见下表第 1 行），其传递依赖随之进入构建；其余组件仍为审计登记、未集成。
- 每个正式发布包必须随附本文件（审计义务清单第 7 条）。
- 传递依赖的全量 SBOM 扫描已于 Step 7 补做：`go list -m all` 共 **403 个模块**，底稿存 `docs/step7-sbom-modules.txt`（义务清单第 7 条后半已回填）。注：quic-go / wireguard-go / uTLS 实际以 sing-box 的 SagerNet/metacubex 分支形态传递进入（模块路径见 SBOM），其许可证分别为上游 MIT / MIT / BSD-3-Clause，分发义务与上游行相同。
- 通用义务（义务清单第 2 条）：全产品不使用 sing-box/SagerNet、WireGuard/Wintun、OpenVPN、quic-go 的名称与标识暗示官方关联或背书；描述性提及与暗示性使用分开评审。

## 组件清单

| # | 组件 | 官方仓库 | 许可证（原文确认） | 集成形态 | 当前状态 |
|---|---|---|---|---|---|
| 1 | sing-box | SagerNet/sing-box | GPL-3.0-or-later ＋ 名称/关联附加条款 | 一期主挂接内核 | **已集成（Step 7，v1.14.4，进程内库形态，构建标签 with_quic/with_utls/with_wireguard/with_gvisor；授权声明原文存 docs/licenses/sing-box-授权声明.txt）** |
| 2 | SoftEther VPN | SoftEtherVPN/SoftEtherVPN | Apache-2.0 | 第二梯队（VPN 类编排） | 已审计，未集成 |
| 3 | OpenVPN（2.x） | OpenVPN/openvpn | GPL-2.0-only ＋ OpenSSL / Apache2 / LZO 链接例外 | 仅独立进程随附分发 | **进程适配器已集成（core/openvpn，独立进程驱动 + management 接口；二进制本身不入仓、不链接）**；随包捆绑的版本与校验和在打包时按下方 OpenVPN 捆绑登记表回填 |
| 4 | wireguard-go | WireGuard/wireguard-go | MIT | WireGuard 隧道实现 | 已集成（Step 7 经 sing-box 传递，实际模块为 SagerNet 分支 github.com/sagernet/wireguard-go） |
| 5 | Wintun | WireGuard/wintun | 源码 GPL-2.0；官方预编译 DLL 为专有 Prebuilt Binaries License；Go 绑定 MIT | 仅官方预编译签名 DLL | 已审计，未集成 |
| 6 | quic-go | quic-go/quic-go | MIT（Logo/品牌资产除外） | QUIC 依赖（经 sing-box 传递） | 已集成（Step 7 经 sing-box 传递，实际模块为 SagerNet 分支 github.com/sagernet/quic-go） |
| 7 | uTLS | refraction-networking/utls | BSD-3-Clause | TLS 指纹层依赖 | 已集成（Step 7 经 sing-box 传递，实际模块为 metacubex 分支 github.com/metacubex/utls） |
| 8 | Xray-core | XTLS/Xray-core | MPL-2.0 | 备选内核 | 已审计，未集成 |
| 9 | filippo.io/age | FiloSottile/age | BSD-3-Clause | libbox 依赖（经 sing-box experimental/libbox 传递：其配置/档案加密） | 已集成（libbox 绑定，v1.3.1；实际编入 AAR 的依赖闭包经 `go list -deps` 核实；同图谱的 c2sp.org/CCTV/age 仅为 age 自身 go.mod 的图谱条目，不编入） |
| 10 | filippo.io/hpke | FiloSottile/hpke（filippo.io/hpke） | BSD-3-Clause | age 的 HPKE 依赖（经 libbox 传递） | 已集成（libbox 绑定，v0.4.0，随 age 编入） |
| 11 | OpenVPN 3 core | OpenVPN/openvpn3 | **MPL-2.0**（AGPL-3.0-only / MPL-2.0 双许可中取 MPL-2.0 一侧；专项审查 docs/openvpn3许可证审查.md，MPL 全文存 docs/licenses/MPL-2.0.txt） | 安卓进程内原生库 libovpn3android.so（静态编入核心 + SWIG Java 绑定 net.openvpn.ovpn3） | 已集成（安卓 OpenVPN 会话承载，槽位 app/libboxbind ovpn3Engine + 原生桥；钉死提交 0c1ce172fe918b05463d71e682a0c2f2d8fe7899，version-string 3.12；.so 与绑定为 git 忽略的构建产物，由 CI 作业 openvpn3-android 构建并注入 APK，构建证据口径见 docs/openvpn3构建尖峰.md） |
| 12 | asio | chriskohlhoff/asio（经 vcpkg arm64-android 引入） | BSL-1.0 | openvpn3 的头文件网络层依赖，编入 libovpn3android.so | 已集成（随 openvpn3） |
| 13 | fmt | fmtlib/fmt（经 vcpkg 引入） | MIT | openvpn3 的格式化依赖，编入 .so | 已集成（随 openvpn3） |
| 14 | jsoncpp | open-source-parsers/jsoncpp（经 vcpkg 引入） | MIT（或公有领域双选，取 MIT） | openvpn3 的配置/JSON 依赖，编入 .so | 已集成（随 openvpn3） |
| 15 | lz4（仅库） | lz4/lz4（经 vcpkg 引入） | BSD-2-Clause（仅库部分；其 GPLv2 的 CLI 工具部分不引入） | openvpn3 的压缩依赖，编入 .so | 已集成（随 openvpn3） |
| 16 | xxHash（仅库） | Cyan4973/xxHash（经 vcpkg 引入） | BSD-2-Clause（仅库部分） | openvpn3 的哈希依赖，编入 .so | 已集成（随 openvpn3） |
| 17 | OpenSSL | openssl/openssl（经 vcpkg 引入，3.x） | Apache-2.0 | openvpn3 的 TLS 后端，编入 .so（取 OpenSSL 而非 mbedTLS，与桌面端口径一致） | 已集成（随 openvpn3） |

## 逐项分发义务（依审计报告第 5 节）

1. **sing-box**：随附其授权声明原文与 GPLv3 全文；提供组合体完整对应源码；保留版权声明。不得使用 sing-box、SagerNet 名称或标识暗示官方关联/背书，宣传性使用须事先取得同意；描述性提及（如「兼容 sing-box 订阅格式」）与暗示关联严格区分。
2. **SoftEther VPN**：随附 Apache-2.0 全文；保留源码中的版权、专利、商标与署名声明及 NOTICE（如有）；修改过的文件带显著修改标注；不使用其商标背书。集成其二进制前（Step 30 交付前置项，义务清单第 5 条），逐项复核其 `src/THIRD_PARTY.TXT` 并登记结论。另：其 LICENSE 后附的日本法/地域声明（原文自述非许可证限制）于法律咨询时一并确认效力。
3. **OpenVPN 2.x**：只以独立进程二进制随附分发，随附其 COPYING 与 GPLv2 全文及对应源码获取途径；保留商标归属说明，不暗示 OpenVPN Inc 背书。**禁止**将其代码静态/动态链接进本项目 GPLv3 二进制，禁止改其源码并入主仓库。进程内需求改走 OpenVPN 3 核心库（AGPL-3.0 / MPL-2.0 双许可，采用前须对其仓库 LICENSE 原文做专项复核）。
4. **wireguard-go**：所有副本/实质部分保留版权声明与许可声明。"WireGuard" 为注册商标，只能描述性使用，不暗示 WireGuard LLC 背书。
5. **Wintun**：只分发 wintun.net 官方未修改签名 DLL（记录版本与校验值），仅经 `wintun.h`（Permitted API）调用，随附 Prebuilt Binaries License 全文，并在官网与包内明示其为**非开源组件**、属可复现构建例外（义务清单第 4 条）。不得用 WireGuard LLC / WireGuard / Wintun 名称背书。**禁止**自行编译或修改 wintun.dll 后分发。Go 绑定（MIT）在分发前以其仓库原文复核一次。
6. **quic-go**：保留版权与许可声明；不得使用其 Logo/品牌资产。个别源文件可能带其他宽松许可头，于 Step 7 SBOM 扫描时一并登记。
7. **uTLS**：源码与二进制分发均保留版权声明、许可条款与免责声明；不得以版权方/贡献者名义为衍生产品背书。
8. **Xray-core**：若启用，其源文件保持 MPL-2.0（义务清单第 6 条）：修改其文件后分发须以 MPL-2.0 提供该等文件源码并告知获取方式；不移除或篡改许可声明；执行体分发须告知接收者如何获取 MPL 部分源码；仓库内标清 MPL/GPL 文件边界；MPL 不授予商标权。
9. **filippo.io/age / filippo.io/hpke**：BSD-3-Clause 义务：源码与二进制分发均保留版权声明、许可条款与免责声明；不得以版权方/贡献者名义为衍生产品背书。随 libbox AAR 分发时其声明随 sing-box 的 GPL 对应源码义务一并提供（本仓库公开即满足）。构建工具 sagernet/gomobile（BSD-3-Clause）仅为构建期工具，不分发、不构成产品依赖，故不入逐项义务。
10. **OpenVPN 3 core 及 libovpn3android.so 内依赖**：取 MPL-2.0 一侧分发——随附 MPL-2.0 全文（docs/licenses/MPL-2.0.txt）；保留上游版权与 SPDX 通知，不剥离不改写；本项目不修改 openvpn3 源码（构建胶水在本仓独立目录 android/openvpn3/，上游以钉死提交 0c1ce172fe918b05463d71e682a0c2f2d8fe7899 获取），钉死版本与上游仓库地址已在本文件与 docs/openvpn3许可证审查.md 登记，本仓库公开即满足 MPL 覆盖文件的源码可得性；将来若确需修改其文件，修改过的文件必须继续以 MPL-2.0 提供源码、独立存放并显著标注。**红线：永不引入 LZO**（GPL-2.0-only）；lz4 / xxHash 只用库目标，不混入其 GPLv2 工具部分。asio（BSL-1.0）、fmt（MIT）、jsoncpp（MIT）、lz4 库 / xxHash 库（BSD-2-Clause）、OpenSSL（Apache-2.0）的版权与许可声明随包保留。构建工具 SWIG 4.2.0 仅构建期使用、不分发，与 gomobile 同口径不入逐项义务；openvpn3 或其依赖版本变动时须复核上游 LICENSE.md 与 vcpkg.json 并更新本文件（审查文档义务 5）。

## OpenVPN / Wintun 捆绑登记（Windows 发行包，打包时逐项回填）

进程适配器（core/openvpn）只驱动官方 OpenVPN 二进制，仓库内不含该二进制。Windows 发行包捆绑时必须逐项登记并随附下列材料（Step 2 审计义务清单第 3、4 条）；任一栏为空即不得出包：

| 字段 | OpenVPN | Wintun |
|---|---|---|
| 版本 | 〔打包时回填，须 ≥ 2.5.0 且经适配器版本校验〕 | 〔打包时回填〕 |
| 官方来源 URL | https://swupdate.openvpn.org/community/releases/（官方社区版安装包） | https://www.wintun.net/（官方分发包） |
| 官方签名校验 | 〔安装包 GPG/签名校验结果〕 | DLL 为官方 Authenticode 签名，未修改（签名者 WireGuard LLC） |
| SHA-256 | 〔openvpn.exe 校验和回填〕 | 〔wintun.dll 校验和回填〕 |
| 随附许可材料 | OpenVPN 的 COPYING 与 GPLv2 全文；对应源码获取途径说明 | Prebuilt Binaries License 全文；**非开源组件**明示 |
| 包内标注 | 不暗示 OpenVPN Inc 背书；因含 Wintun 专有预编译 DLL 与 OpenVPN 二进制，**发行包不得宣称「100% 开源」** | 同左 |

macOS/Linux 发行形态：不捆绑，依赖系统包管理器安装的 OpenVPN（适配器定位逻辑含 PATH 兜底），故无本登记义务；官网下载页须注明该依赖。
