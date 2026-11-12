# 统一节点模型 v1 · 说明

- 状态：**v1 已评审冻结**（Step 5 交付物，2026-11-12 交付并于同日评审冻结；后续变更走 VERSIONING.md 的版本规则）
- 依据：方案书 5.2（模型定版于 spec/）、4.1（第一梯队矩阵）、4.2（订阅与链接格式）、7.2（来源插件输出与 authorization 标识）、10.3（版本化走 RFC）
- 本目录与文档按方案书 10.1 采用宽松条款单独授权（与代码 GPLv3 分开），以便其他项目兼容实现。

## 文件清单

| 文件 | 内容 |
|---|---|
| `unified-node-model.schema.json` | JSON Schema（draft 2020-12），含 Node、Group、Source、Subscription 四个模型与全部协议分支定义，共 21 个 `$defs` |
| `examples/nodes/*.json` | 11 个示例节点（第一梯队 10 个协议，其中 OpenVPN 两种承载各一） |
| `examples/group.json` / `source.json` / `subscription.json` | Group、Source、Subscription 示例各一 |
| `tests/validate.py` | 校验脚本（正例须全过、反例须全拒） |
| `tests/invalid/*.json` + `tests/invalid-manifest.json` | 9 个反例及其预期被拒理由 |
| `VERSIONING.md` | 版本化规则 |

## 模型结构总览

- **Node**：公共字段沿用方案书 5.2（`id`、`name`、`protocol`、`server`、`port`、`credential`、`transport`、`security`、`udp`、`source`、`group`、`lastTest`），另加 `schemaVersion`、`extraPorts`、`tags`、`remarks`（出入见下文专节）。`credential` / `transport.type` 的允许形态由 `protocol` 判别联合收窄：每个协议分支有独立的凭据 schema 且 `additionalProperties: false`，串用其他协议字段会被拒。
- **Group**：`id`、`name`、`nodeIds`（顺序即组内排序，对应 8.1 拖拽排序）、可选 `description`、`sourceId`。
- **Source**：来源登记，对应 7.2 插件 manifest 的模型化：`kind`、`operator`、`authorization{status, basis, termsUrl}`、`dataFormat` 等。`status` 即 7.1 分级 A/B/C，D 级禁止登记故模型不设 D；插件类 Source 强制 `status` 为 A。Node 内的 `source.authorization` 字符串应与登记的 `authorization.basis` 一致以便溯源。
- **Subscription**：`url`、`format`（含 `plugin-csv`）、`userAgent`、刷新间隔、`traffic{upload, download, total, expireAt}`（7.4）、`groupName` 等。

## 每协议字段对照表

记法：链接/订阅参数 → 模型字段。未列的参数即该协议分享形态中不存在或已由公共字段承载。

### Shadowsocks（含 SS2022）
- 链接 userinfo（method:password）/ SIP002 → `credential.method` / `credential.password`；SS2022 的 Base64 密钥仍为单一 `password` 字符串（多用户冒号拼接与主流实现一致）
- `plugin` 参数（如 `obfs-local`、`v2ray-plugin` 及其 `;` 选项串）→ `credential.plugin` / `credential.pluginOpts`
- UDP 支持 → 公共字段 `udp`；无 transport/security 层（分支强制 transport 仅 `raw`）

### Trojan
- 链接密码 → `credential.password`
- `type`（ws/grpc 等）→ `transport.type`；`path`、`host` → `transport.path` / `transport.host`；`serviceName` → `transport.serviceName`
- `sni`、`alpn`、`fp`、`allowInsecure` → `security.serverName` / `alpn` / `fingerprint` / `allowInsecure`；`security.type` 一般为 `tls`

### VMess
- 链接 JSON：`id` → `credential.uuid`；`aid` → `credential.alterId`；`scy`/配置 `security` → `credential.cipher`（改名理由见出入第 3 条）
- `net` → `transport.type`；`type`（伪装头）→ `transport.headerType`；`host`、`path` → `transport.host` / `transport.path`；gRPC 的 serviceName → `transport.serviceName`
- `tls` → `security.type=tls`；`sni`、`alpn`、`fp` 同 Trojan 映射

### VLESS（含 Reality / Vision）
- `encryption` → `credential.encryption`；`flow`（xtls-rprx-vision 等）→ `credential.flow`（位置与 5.2 示意一致，在 credential 内）
- `security=tls` → `security.type=tls`；`security=reality` → `security.type=reality`，且 `pbk` → `security.publicKey`（必填，缺失被拒）、`sid` → `security.shortId`、`spx` → `security.spiderX`、`sni` → `security.serverName`、`fp` → `security.fingerprint`
- `type` 及 ws/grpc/xhttp 参数 → transport 同名字段（`serviceName`、`grpcMode`、xhttp 的 `mode` 等）

### Hysteria2
- 认证串（`auth` 或 userpass 形态）→ `credential.auth`
- `obfs=salamander` / `obfs-password` → `credential.obfsType` / `credential.obfsPassword`（有 obfsType 时 obfsPassword 必填）
- `mport`（端口跳跃）→ `Node.extraPorts`（如 `"20000-30000"`）
- `sni`、`alpn`、`insecure`、`pinSHA256` → security 同义字段（`certificatePinSha256`）

### TUIC
- `uuid`、`password` → credential 同名字段
- `congestion_control` → `transport.congestionControl`；`udp_relay_mode` → `transport.udpRelayMode`（transport.type 取 `quic` 或省略）
- `sni`、`alpn`、`allow_insecure` → security 同义字段；`disable_sni` 以省略 `security.serverName` 表达

### WireGuard
- 承载决策：**结构化**（不采用 .conf 全文）。理由：WireGuard 配置是规整的键值结构，字段有限且稳定，结构化后可校验、可编辑、可与测活/分组体系打通；且 4.2 的「WireGuard 配置文件」是导入格式，由解析器（Step 8）映射到结构化字段，不要求模型层存全文。与 OpenVPN 的决策差异正在于 .ovpn 含任意指令、无规整结构（见下）。
- .conf `PrivateKey` → `credential.privateKey`；`Address` → `credential.addresses`；`DNS` → `credential.dns`；`MTU` → `credential.mtu`
- Peer `PublicKey` → `credential.peerPublicKey`；`PresharedKey` → `credential.preSharedKey`；`AllowedIPs` → `credential.allowedIPs`；`Endpoint` → `Node.server` / `Node.port`；`PersistentKeepalive` → `credential.persistentKeepalive`；服务商配置中的 reserved 三字节 → `credential.reserved`
- 三类密钥均以 44 字符 Base64 模式强校验

### OpenVPN
- 承载决策：**双模式二选一**（schema 以 oneOf 强制恰居其一）。理由：.ovpn 是含内嵌证书与任意指令（route、script-security、厂商私有指令等）的复合文本，纯结构化必丢字段、无法满足验收的「无损」；而 VPN Gate CSV 映射与手动录入又需要结构化字段。故：任意 .ovpn 文件走 `credential.configContent` 全文模式（无损兜底，此时 remote 在全文内，Node 的 server/port 可省略）；来源映射与手动录入走结构化模式（`proto`、`cipher`、`authDigest`、证书 PEM 文本、`tlsAuthKey`/`tlsCryptKey`、`keyDirection` 等，此时 server/port 必填）。两种模式都允许独立的 `username` / `password`（auth-user-pass）。
- 方案书 5.1 的 Step 2 审计回写（OpenVPN 独立进程适配）影响的是内核集成形态，不影响本模型。

### SOCKS5
- 地址与可选账号密码 → `server` / `port` / `credential.username` / `credential.password`（username 出现则 password 必填）；UDP → `udp`

### HTTP(S)
- 与 SOCKS5 共用 `CredUserPass`；HTTP 与 HTTPS 的区分由 `security.type` 表达（`none` 为明文 HTTP 代理，`tls` 为 HTTPS 代理），协议值统一为 `http`（出入第 9 条）

## 无损性自查结论

按验收口径逐协议核对「主流分享链接 / 订阅中的参数」与模型字段，结果如下：

- 第一梯队 10 个协议的分享链接与主流订阅参数均有对应字段，示例集逐协议覆盖并通过校验（实测见下节）。
- 已知取舍（如实登记，不算无损的部分）：
  1. **OpenVPN 结构化模式**只能表达常用指令子集，任意指令靠全文模式兜底才无损；解析器遇到结构化无法表达的指令必须转全文模式，不得静默丢弃。
  2. **Hysteria2 的带宽参数**（客户端配置中的上/下行 Mbps、Brutal 拥塞相关）不在分享链接中出现，未建模；如未来要支持，属拨号选项，走小版本新增可选字段。
  3. **TUIC 的 heartbeat / requestTimeout 等客户端调参**不在分享链接中出现，未建模，理由同上。
  4. **VLESS 的 packetEncoding**（xray 服务端侧配置）不在分享链接中出现，未建模。
  5. **Trojan 多密码数组**（服务端配置形态）未建模，分享形态为单密码，模型从分享形态。
  6. **跨文档约束**（Group.name 唯一、Node.group 与 Group.name 的引用完整性、nodeIds 指向存在的节点）JSON Schema 无法表达，由应用层校验负责，已在 schema 描述中注明。

## 校验实测记录（如实）

- 环境：Python 3.12.3，jsonschema 4.10.3（本机已有，未安装新包）
- 命令：在项目根目录执行 `python3 spec/tests/validate.py`
- 结果（2026-11-12 实测，退出码 0）：
  - schema 本身 `Draft202012Validator.check_schema`：OK
  - 正例：**14/14 通过**（11 个节点 + Group + Source + Subscription）
  - 反例：**9/9 被拒**（缺必填 server、port 类型错、VLESS 凭据混入 SS 的 method、Reality 缺 publicKey、WireGuard 缺 peerPublicKey、未知协议值、plugin 来源缺 authorization、udp 类型错、security.type=none 携带 serverName）
- 复跑方式：任何人可在装有 jsonschema 4.x 的环境运行同一脚本复核，脚本在任一用例不符时以非 0 退出码失败。

## 与方案书 5.2 示意字段的出入（发现清单）

示意字段全部保留（字段名与层级未改），出入均为新增或解释性处理，逐条列明理由，待评审冻结时一并裁定：

1. **新增 `schemaVersion`**（四模型共有）：5.2 示意无版本字段，但 Step 5 验收本身要求「版本化规则」，无版本字段则规则无从落地（规则见 VERSIONING.md）。
2. **新增 `Node.extraPorts`**：Hysteria2 分享链接的 `mport`（端口跳跃）在 5.2 字段中无处安放，不新增即不无损。
3. **新增 `Node.tags` / `Node.remarks`**：8.1 的按条件筛选与节点管理需要，均为可选字段，不影响既有解析。
4. **VMess 凭据的加密字段改名 `cipher`**：VMess 原字段名 `security` 与 Node 顶层 `security` 对象同名，置于 credential 内虽可共存但极易误读与写错映射，故改名并在对照表注明来源字段。
5. **OpenVPN 的 server/port 改为条件必填**：5.2 示意默认两字段恒在，但 .ovpn 全文模式下 remote 已在内容中，强制必填会迫使解析器伪造字段、破坏无损，故仅全文模式可省略。
6. **Node.group 沿用 5.2 的「分组名字符串」而非 Group 的 id 引用**：与 5.2 原文及订阅导入的 groupName 形态一致；代价是改名需级联更新，由应用层负责（已在取舍第 6 条登记）。
7. **Source.authorization 在 Node 内是字符串标识、在 Source 模型内是对象**：前者是 5.2/7.2 的节点内嵌形态（标识值），后者是登记全貌（含分级与条款链接），两者以 basis 值对应，非冲突。
8. **Shadowsocks method 枚举超出 4.1「AEAD 全系」范围**：为无损导入存量旧订阅，纳入了 cfb 系与 rc4-md5 等老式方法，仅供导入识别，建议解析器对老式方法给出弱加密警示；是否收紧枚举请评审裁定。
9. **HTTP(S) 合并为单一协议值 `http`**：4.1 表述为「SOCKS5 / HTTP(S) 代理」一项，模型以 `security.type` 区分明文与 TLS，不单设 `https` 协议值。
10. **5.2 示意中 VLESS 的 flow 在 credential 内、Reality 参数在 security 内**，本模型逐字沿用该层级（含示意中 security 的 fingerprint 字段），未按某些实现的「全部塞入链接参数」习惯重排。

## 状态与下一步

本模型为 **v1 候选**：已完成自洽性与示例/反例实测，但未经评审冻结。冻结动作（评审通过并在本文件与 schema 描述中改注状态）不在 Step 5 本子任务权限内，须由项目评审环节完成；冻结后任何字段级变更走 VERSIONING.md 的 RFC 规则。

## 评审裁定（2026-11-12，冻结记录）

- 第 7 项出入（Shadowsocks 方法枚举纳入 cfb/rc4-md5 等老式方法）：**裁定保留**。理由：统一模型的职责是无损导入存量订阅，拒绝老式方法等于让一批存量节点无法导入，与模型定位冲突。配套义务转 Step 8（解析器）：导入含老式方法的节点时必须给出弱加密警示，且不得在 UI 中默认推荐此类节点。
- 其余出入（1-6、8 项）与两项已知取舍：评审认可，按本文件登记口径执行。
- 校验复核：评审环节独立复跑 tests/validate.py，结果正例 14/14 通过、反例 9/9 被拒，与交付报告一致。据此冻结为 v1 定版。
