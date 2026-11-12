# Step 7 交付报告：挂接内核集成（sing-box）

对应方案书第 14 章 Step 7。交付物：Step 6 适配层接口之下的真实 sing-box 实现（`core/singbox/`）、统一模型对接层（`core/specnode/`）、能力矩阵自报、逐协议本地回环真握手测试记录、SBOM 与许可证义务核对。

## 1. 版本锁定与选择理由

| 项 | 值 |
|---|---|
| sing-box | **v1.14.4**（2026-10-23 发布，集成当日模块代理可得的最新稳定版；非预发布） |
| 集成形态 | 进程内 Go 库链接（方案书 5.1 主挂接形态；OpenVPN 例外见 §5） |
| 官方构建标签 | `with_quic with_utls with_wireguard with_gvisor` |
| Go 工具链下限 | sing-box v1.14.4 要求 go 1.25.5 —— `core/go.mod` 的 go 指令由 1.23 升至 1.25.5，CI 的 setup-go 同步升至 1.25 并新增官方标签测试步（`.github/workflows/ci.yml`） |
| 版本防漂移 | 适配器自报版本常量与二进制构建信息中的模块版本有自动交叉校验测试（TestCapabilitiesConsistency） |

标签取舍（对照 v1.14.4 源码核实，非凭文档印象）：`with_utls` 同时门控 Reality 客户端与服务端（旧的 with_reality_server 已并入）；`with_quic` / `with_wireguard` 门控协议注册；1.14.4 **没有 xhttp 传输**（见 §6 不支持项）。

## 2. 统一模型对接方式（任务 1 的裁定）

**裁定：映射层，不替换。** Step 6 的 `core/kernel` 包保持字节级不变（其占位 Node、接口签名、22 条测试全部原样通过）；新增 `core/specnode` 包承载 Step 5 冻结统一模型的完整保真 Go 结构（按 spec schema 逐字段对照，含按协议区分的凭据联合体与 schema 对齐校验）。适配器原生入口（StartNode / ValidateSpec / TestHandshakeNode）直接消费 specnode；接口方法则经双向投影对接：

- `ProjectKernel()`（spec → 占位）：**有损投影**，逐项在代码注释中登记（如 raw 传输对 trojan/vmess/vless 投影为 tcp；http 传输投影为 http2；占位模型装不下的 WireGuard 密钥、端口跳跃、SpiderX 等字段在投影中丢失）。
- `FromKernel()`（占位 → spec）：供只持有占位 Node 的调用方使用。
- 占位模型**装不下必填数据**的协议（WireGuard 密钥对、OpenVPN 配置体）在占位路径上以精确的 invalid_config 错误拒绝并指明缺失项，绝不静默生成错误配置；完整路径（specnode）不受此限。

既有测试：kernel + mock 共 22 条全过，未改一字。另注：Step 8 解析器包（并行交付）自带一份 spec 镜像结构 `parsers.Node`，与 `specnode.Node` 并存——两者均经 schema 校验（解析器输出 46/46、specnode 用例 11/11），后续集成步应收敛为单一结构，本步不越界合并。

## 3. 适配器实现要点

- **配置编译**（`compile.go`）：统一模型节点 → sing-box JSON 配置（log + 本地 mixed 入站（仅回环）+ 节点出站或 WireGuard 端点 + direct 出站 + route.final=out）。逐协议出站构造器覆盖第一梯队全部进程内协议及传输/安全组合（见 §4）；Hysteria2 端口跳跃做 "20000-30000" → sing-box "20000:30000" 格式转换；证书 SHA-256 pin 映射 sing-box 的 certificate_public_key_sha256。
- **生命周期**：与 Step 6 mock 同语义（重复 Start 报 wrong_state、Stop 幂等、失败进 failed 态并留 LastError、Stop 后可重启）。实例上下文由适配器持有（不随调用方请求上下文销毁）。
- **平台门**：TUN / 系统代理 / 非手动模式 / KillSwitch 在本步一律以 platform_unavailable **显式拒绝**（能力矩阵如实报 false），绝不静默降级；平台网络属 Steps 9–12。
- **流量统计**：来源为 sing-box 的 trafficcontrol 管理器（经 box 的 PlatformLogWriter 机制取得，不开 Clash API、不暴露任何监听）。运行中读实时累计值，Stop 时冻结，首跑前返回零值。实测每条回环用例均读到非零上/下行（见 §5）。
- **TestHandshake**：起一次性实例（仅含被测节点出站），经其 mixed 入站做真实 SOCKS5 CONNECT + HTTP 探测；成功必须拿到格式完好的 HTTP 响应并计延迟；握手失败进结果（Go error 为 nil），节点非法/不支持/上下文取消才返回 Go error。
- **集成发现（已修复并写入代码注释）**：sing-box 1.14 在传入 PlatformLogWriter 时会强制启用其 bbolt cache-file（box.go 的 needCacheFile），默认路径为工作目录下 cache.db —— 多实例并发时文件锁争用导致实例启动超时（首轮回环测试全灭于此）。修复：每个实例分配独立临时目录中的 cache 文件，实例关闭后清除。

## 4. 能力矩阵实测表（官方标签构建，适配器自报）

协议（spec 坐标，✓=支持并经编译校验；握手列见 §5）：

| 协议 | 支持的传输 | 安全层 | 回环握手 |
|---|---|---|---|
| Shadowsocks | raw | aead（方法含 2022 系列与传统 AEAD） | ✓ 过（2 方法） |
| Trojan | raw / ws / http / httpupgrade / grpc | tls | ✓ 过（raw、ws） |
| VMess | raw / ws / http / httpupgrade / grpc | none / tls | ✓ 过（raw、grpc+tls） |
| VLESS | raw / ws / http / httpupgrade / grpc | none / tls / **reality** | ✓ 过（裸 tcp、Reality+Vision） |
| Hysteria2 | quic | tls | 环境阻断（§5） |
| TUIC | quic | tls | 环境阻断（§5） |
| WireGuard | raw（端点形态） | none | 环境阻断（§5） |
| SOCKS5 | raw | none / tls | ✓ 过（用户密码） |
| HTTP | raw | none / tls | ✓ 过（用户密码） |
| OpenVPN | —— | —— | **不在进程内矩阵**：按 Step 2 裁定 F-1 为独立进程形态，本步仅标注，未集成 |
| AnyTLS | —— | —— | 第二梯队（4.1），未经互通验证，**不进矩阵、不虚报** |

不支持项（如实拒绝，unsupported 错误）：xhttp / kcp / quic 传输（sing-box 1.14.4 无此三种传输实现）、SS 老式方法（cfb/rc4-md5 等，sing-box 已移除；spec 侧按 Step 5 裁定仍可无损导入，运行侧拒绝）、无 with_utls 构建时的 uTLS 指纹/Reality（未标记构建自动缩减矩阵并有门控测试）。

平台能力（本步）：TUN ✗、系统代理 ✗、KillSwitch ✗、IPv6 声明 ✗（均如实 false）；特性：握手测试 ✓、流量统计 ✓、节点 UDP ✓（协议侧）。

字段级缺口（如实登记）：VLESS 非 "none" 的 encryption 字符串 sing-box 无对应实现 → 拒绝；Trojan/VMess 的 grpcMode、Reality 的 SpiderX 在 spec 中保留，sing-box 无对应配置项 → 编译时不落地（不影响互通主路径）。

## 5. 逐协议回环握手测试记录（2026-11-12，本沙箱实测）

方法：服务端为本机另起的真实 sing-box 入站，客户端为被测适配器；通过标准 = TestHandshakeNode 报 OK 且有实测延迟 **且** StartNode 后经 mixed 入站取回显服务响应体含约定令牌 **且** 流量计数非零。测试代码：`core/singbox/loopback_test.go`（官方标签）。

| 用例 | 结果 | 延迟 | 证据要点 |
|---|---|---|---|
| shadowsocks-2022（blake3-aes-256-gcm） | **过** | 2.42ms | 流量 up=64 down=163 |
| shadowsocks-aes128-gcm | **过** | 1.47ms | 同上 |
| trojan-tls | **过** | 3.73ms | 自签证书 + allowInsecure |
| trojan-ws-tls | **过** | 3.32ms | ws 传输 |
| vmess-tcp（AEAD） | **过** | 1.53ms | —— |
| vmess-grpc-tls | **过** | 3.84ms | grpc 传输 + TLS |
| vless-tcp-plain | **过** | 1.32ms | —— |
| vless-reality-vision | **过** | 7.23ms | 本地 X25519 密钥对生成测试凭据；伪装目标为本机 httptest TLS 服务；flow=xtls-rprx-vision |
| socks5-userpass | **过** | 1.67ms | —— |
| http-proxy-userpass | **过** | 1.23ms | —— |
| 负控：SS-2022 错误密钥 | **过（应失败且失败）** | —— | 服务端日志实证 "cipher: message authentication failed"；结果为 handshake_failed 而非 Go error，证明握手为真 |
| hysteria2-salamander | **环境阻断，未过** | —— | 见下 |
| tuic-v5 | **环境阻断，未过** | —— | 见下 |
| wireguard | **环境阻断，未过** | —— | 见下 |

**UDP 三协议环境阻断的证据链（非协议实现问题）**：

1. 原始 syscall 探针（Python ctypes 直调）：`sendmmsg`(307) → EPERM；普通 UDP `sendto` 对 127.0.0.1、1.1.1.1、8.8.8.8 **全部** EPERM；TCP 回环正常。结论：本沙箱在 syscall 层封锁一切 UDP 发送。
2. sing-box 侧日志实证：WireGuard 端点反复报 "failed to send handshake initiation: write udp …: sendmmsg: operation not permitted"；Hysteria2 出站 "context deadline exceeded"（服务端零响应）；TUIC "no recent network activity"。
3. 已尝试的绕行：`QUIC_GO_DISABLE_GSO=1`（quic-go 分支提供的关 GSO 开关）无效 —— 因为连普通 sendmsg 路径同样被封锁。
4. 处置：三条用例**不删除、不改 mock**；测试内置环境探针（probeUDPSend / probeSendmmsg），在受阻环境以 SKIP 并附证据原因，在不受限环境（本步新增的 CI 步，GitHub 托管 runner）全量执行。**残留风险如实标注**：WireGuard 服务端「端点入站流量 → 路由 → direct 出站」的转发路径、以及 QUIC 两协议的完整握手，在 CI 首跑前未在任何环境实证过；CI 首跑结果即为其验收证据，若 WireGuard 需要补 route 规则，首跑失败日志会直接指明。

其余测试：未标记构建 `go test ./...` 全绿（kernel/mock/parsers/specnode/singbox）；官方标签下 singbox 包全套通过（3 条环境 SKIP 除外）；`go vet ./...` 干净；新代码均经 gofmt。

## 6. 依赖清单（SBOM）与许可证义务核对

- SBOM 底稿：`docs/step7-sbom-modules.txt`（`go list -m all`，共 **403 个模块**）。要点：sing-box v1.14.4 本体（GPL-3.0-or-later＋名称条款）；quic-go / wireguard-go / sing-tun / gvisor 实际以 SagerNet 分支模块进入，uTLS 以 metacubex 分支进入（许可证分别为上游 MIT / MIT / BSD-3-Clause 等宽松许可）。
- Step 2 审计 §5 义务清单逐项核对：

| # | 义务 | 本步落实 |
|---|---|---|
| 1 | 主 LICENSE 为 GPL-3.0-or-later，随附 GPLv3 全文与 sing-box 授权声明原文 | ✓ Step 4 已定版主 LICENSE（即 GPLv3 全文）；sing-box 授权声明原文已存 `docs/licenses/sing-box-授权声明.txt`（v1.14.4 LICENSE 卷首，含名称/关联条款） |
| 2 | 不以 sing-box/SagerNet 等名称标识暗示官方关联/背书 | ✓ 适配器对外标识为中性 kernel id，代码与文档中仅描述性提及；未使用任何上游 Logo/品牌资产 |
| 3 | OpenVPN 仅独立进程随附 + COPYING/GPLv2 + 源码途径，禁止链接 | ✓ 本步未进程内集成、未随附（能力矩阵标注形态）；义务在打包步继续生效 |
| 4 | Wintun 仅官方未修改签名 DLL + 专有许可全文 + 明示非开源 | 本步未随附（无 TUN）；义务在 Steps 9–12 Windows 平台步生效，届时发布物不得宣称「100% 开源」 |
| 5 | SoftEther 集成前复核其 THIRD_PARTY.TXT | Step 30 义务，本步不适用 |
| 6 | Xray-core 启用时 MPL-2.0 边界 | 未启用，不适用 |
| 7 | THIRD_PARTY_NOTICES 汇总随包发布；Step 7 补做传递依赖全量 SBOM 并回填 | ✓ 本文件与 THIRD_PARTY_NOTICES 已回填（sing-box 行转「已集成」、传递分支形态、SBOM 403 模块）；随包发布为发行步职责 |

## 7. 未完成项与原因

1. **Hysteria2 / TUIC / WireGuard 回环握手未在沙箱内实证** —— 沙箱 syscall 层封锁 UDP 发送（证据见 §5），非实现缺失；验收改由本步新增的 CI 步在不受限 runner 上完成，首跑结果待回填本文件。
2. **TUN / 系统代理 / KillSwitch 未实现** —— 按方案书属 Steps 9–12 平台步；本步能力矩阵如实报 false 并显式拒绝。
3. **AnyTLS 未进矩阵** —— 第二梯队，未做互通验证前不虚报（4.1）。
4. **两种 spec 镜像结构并存**（parsers.Node 与 specnode.Node）—— 收敛属后续集成步，本步已登记。
5. **模块路径仍为占位** `openproxy/core` —— 迁移至 relavia 组织路径为 Step 4 已登记 TODO，非本步范围。
