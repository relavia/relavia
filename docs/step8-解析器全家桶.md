# Step 8 解析器全家桶 · 交付报告

- 步骤：阶段 1 Step 8（交付 4.2 全部链接与订阅格式解析器；验收：样本集含异常样本解析测试全过，异常输入不崩溃且有明确报错）
- 日期：2026-11-12
- 落点：`core/parsers/`（模块 `openproxy/core` 内新建包，未改 `spec/` 与 `core/kernel` 既有文件；`core/go.mod`/`go.sum` 新增 `gopkg.in/yaml.v3` 依赖，供 Clash YAML 解析）
- 产出物：统一节点模型对象（spec v1 冻结版），解析产出经 spec schema 复验（见第 5 节）

## 1. 格式覆盖对照表（对照方案书 4.2 原文清单逐项）

### 1.1 分享链接

| 4.2 清单项 | 实现 | 形态/变体覆盖 |
|---|---|---|
| `vless://` | ✅ `ParseLink` | security=tls/reality/none；Reality 全参数（pbk/sid/spx/sni/fp）；flow=xtls-rprx-vision(-udp443) 校验；传输 tcp/ws/grpc/http/httpupgrade/xhttp/kcp/quic + headerType/serviceName/mode/seed |
| `vmess://` | ✅ | base64 JSON 形态（v2 字段全集：net 各值、type 伪装头、host/path、tls/sni/alpn/fp、scy、aid）；新式 query 形态（uuid@host + query） |
| `trojan://` | ✅ | 密码 userinfo；type=ws/grpc 等传输 + path/host/serviceName；sni/peer、alpn、fp、allowInsecure；缺省端口 443、缺省 TLS |
| `ss://` | ✅ | SIP002（base64 userinfo 与明文 userinfo 两种变体）、旧式整体 base64（带 deprecated-format 警示）；plugin/pluginOpts；SS2022 方法 |
| `hysteria2://`（含 `hy2://`） | ✅ | auth 串与 user:pass 双形态、query auth；obfs=salamander + obfs-password（缺失报错）；mport 端口跳跃 → extraPorts；sni/alpn/insecure/pinSHA256 |
| `tuic://` | ✅ | uuid:password userinfo；congestion_control、udp_relay_mode（枚举校验）；sni/disable_sni、alpn、allow_insecure |
| `wg://` / WireGuard 配置文件 | ✅ | wg:// 与 wireguard:// 链接（publickey/address/dns/mtu/allowedips/keepalive/reserved/psk）；.conf 文件结构化映射，多 [Peer] 逐个成节点 |
| OpenVPN `.ovpn` 文件 | ✅ | 全文无损映射 configContent 模式（spec README 承载决策）；提取首个 remote 填充 server/port 供展示；auth-user-pass 无参形态发 credentials-required 警示 |
| SOCKS5 / HTTP(S) 链接（4.2 未单列，依 4.1 第一梯队与 spec README 对照表补齐） | ✅ | socks5://（含 udp 开关）、http:// / https://（security.type 区分明文与 TLS） |

### 1.2 订阅格式

| 4.2 清单项 | 实现 | 说明 |
|---|---|---|
| sing-box JSON | ✅ `ParseSubscription` 自动识别 | outbounds 逐个映射：shadowsocks/trojan/vmess/vless/hysteria2/tuic/socks/http/wireguard 九类节点型出站；selector/urltest/direct/block/dns 非节点出站跳过并在结果级警示中逐项说明；单出站失败不拖垮整批 |
| Clash YAML | ✅（含 mihomo 字段习惯） | proxies 逐个映射十类（含 wireguard、http 的 tls/sni）；ws-opts/grpc-opts/h2-opts、reality-opts、plugin-opts 展平、skip-cert-verify → allowInsecure + 警示；模型外类型（如 ssr）逐条结构化报错 |
| V2Ray 订阅（base64） | ✅ | 整体 base64 解码后按链接列表解析，format 标注 v2ray-base64 |
| 原始链接列表（base64 与明文） | ✅ | 明文逐行解析（空行与 # 注释跳过）；整段 base64 且解码后含链接时同 V2Ray 路径；逐条标注成功/失败与序号 |
| 公共源格式：VPN Gate CSV（经来源插件，见 7.3） | ✅ 格式解析部分 | 逐行解码 OpenVPN_ConfigData_Base64 → configContent 节点（source.kind=plugin、authorization=vpngate-official-csv），并产出 Source 登记（status=A、basis=vpngate-official-csv、dataFormat=csv、operator=VPN Gate (University of Tsukuba)）；坏行逐条报错。**边界**：7.3 的强制风险提示页、镜像轮换等插件行为属 Step 14，不在本步 |

### 1.3 导入方式（4.2 末行）

粘贴、扫码、文件导入、订阅 URL 定时更新、剪贴板识别属客户端外壳（Step 9/10）的交互层：本步提供与之对应的解析入口（链接/列表/文件全文/订阅内容 + `BuildSubscriptionRecord` 构造订阅登记），外壳接线不在本步范围。

## 2. 字段映射要点

映射逐项遵循 spec/README 的每协议字段对照表，此处只记易错点：

- VLESS Reality：pbk → security.publicKey（缺失直接报错，不产出半成品节点）；flow 在 credential 内（沿用 5.2 示意层级）。
- VMess：链接 JSON 的 `security`/配置 `security` 一律改名映射到 credential.cipher；`aid` 非 0 发 legacy-parameter 警示；grpc 的 serviceName 在旧 JSON 中常借道 path 字段，已兼容。
- Shadowsocks：plugin 参数第一段为插件名、其余以 `;` 拼回 pluginOpts；Clash 的 obfs plugin-opts 特殊展平为 `obfs=<mode>;obfs-host=<host>` 与链接形态对齐。
- Hysteria2：mport/ports/server_ports 三种来源统一落 Node.extraPorts；auth 的 user:pass 形态以冒号拼为单一 auth 串（与模型口径一致）。
- TUIC：congestion_control/udp_relay_mode 枚举非法值直接报错（不静默降级）；disable_sni 以省略 security.serverName 表达。
- WireGuard：三类密钥按 schema 的 44 字符 Base64 模式强校验；.conf 的 Endpoint 落 Node.server/port，Address/DNS/MTU 落凭据；sing-box wireguard 出站 peers 多于一个时仅取第一个并发 param-not-modeled 警示（模型为单 Peer，spec README 已登记的取舍）。
- OpenVPN：结构化无法表达的任意指令一律走全文模式，不丢字段（spec README 取舍 1 的解析器义务）；remote 端口缺失时以 1194 填充展示并发 missing-field-defaulted 警示，全文为准。

## 3. 警示与错误码设计

警示（Warning{Code, Field, Message}，随产出携带）：

| 码 | 触发 |
|---|---|
| `weak-encryption` | SS 老式方法（aes-*-cfb、chacha20、chacha20-ietf、xchacha20、rc4-md5、none）——Step 5 冻结裁定义务 |
| `insecure-skip-verify` | allowInsecure/insecure/skip-cert-verify 被置 true |
| `deprecated-format` | ss 旧式整体 base64 形态 |
| `missing-field-defaulted` | 参数缺失按约定默认值补齐（vmess scy、wg allowedips、ovpn remote 端口等） |
| `unknown-param-ignored` | 无法识别的参数（逐个点名） |
| `param-not-modeled` | 模型未建模的参数（vless packet_encoding、tuic heartbeat 等，spec README 取舍已登记） |
| `credentials-required` | .ovpn 含无参 auth-user-pass，需另行索取凭据 |
| `legacy-parameter` | 存量旧参数（vmess alterId 非 0） |

错误（ParseError{Code, Index, Segment, Detail}，批量时带条目序号与原始条目截断文本）：
`empty-input`、`input-too-large`（单链 64KB / 整批 16MB / 1 万条上限）、`unknown-scheme`、`unsupported-protocol`、`bad-base64`、`bad-json`、`bad-uri`、`missing-field`、`bad-port`、`bad-uuid`、`bad-key-format`、`unsupported-value`、`bad-format`。
批量语义：单条失败只标该条，整批继续；订阅中非节点出站（selector 等）不算失败，以结果级警示说明。

其他工程约定：节点 id 由内容哈希确定性派生（订阅刷新不换 id）；同名覆盖、去重与 UI 默认推荐策略属外壳层，本包以警示码提供决策依据（弱加密节点带 `weak-encryption`，UI 据此不得默认推荐——裁定义务的执行点在 Step 9/10，解析侧义务已在本步落地）。

## 4. 样本集与测试结果

样本集位于 `core/parsers/parsers_test.go`（内嵌字面样本，含真实格式的 base64 串）：

| 类别 | 数量 | 内容 |
|---|---|---|
| 正例（分享链接） | 20 | 每格式至少 2 条含参数变体：SS×3（SIP002/明文+plugin/旧式）、VLESS×2（Reality+Vision / WS+TLS）、VMess×3（base64 WS / base64 gRPC / query 形态）、Trojan×2、Hysteria2×2、TUIC×2、WireGuard 链接×2、SOCKS5×2、HTTP(S)×2 |
| 正例（文件/订阅） | 12 组 | .conf 单 Peer / 多 Peer、.ovpn×2、VPN Gate CSV（2 行含 1 坏行）、V2Ray base64 订阅（3 节点 + Group/Subscription/Source 登记断言）、明文列表、sing-box JSON（11 出站：8 成 1 败 2 跳过）、Clash YAML（10 条：9 成 1 模型外类型报错） |
| 反例 | 23 | 空/空白、未知协议头、无协议头、坏 UUID、端口 0 与越界、Reality 缺 pbk、非法 flow、坏 base64、未知 SS 方法、VMess 坏 JSON/截断/缺 id、Trojan 空密码、TUIC 缺密码/非法拥塞值、HY2 缺 obfs 密码/非法 mport、WG 坏密钥/缺 address、socks5 有用户无密码、64KB+ 超长输入 |
| 健壮性 | 4 组种子 × 全长截断 + 符号变异 | 任意截断/变异输入不 panic（含订阅/文件入口与二进制垃圾） |

实测（2026-11-12，go 1.23，`go test -count=1 ./...` 于 core 模块）：

- `openproxy/core/parsers`：**全部通过**（20 正例 + 23 反例 + 14 个功能/健壮性测试函数）
- core 其余包（kernel、kernel/mock 及并行步骤的 specnode）同轮全过，无回归
- `go vet ./parsers/` 无告警

## 5. 产出过 spec schema 复验

`TestOutputsValidateAgainstSpecSchema` 把正例产出（链接节点 20 + sing-box/Clash 订阅节点与 Group/Subscription/Source 登记 + .conf/.ovpn/VPN Gate 节点与 Source 登记，共 **46 个对象**）逐一按 spec 的 Node/Group/Subscription/Source 定义校验（脚本 `core/parsers/testdata/validate_outputs.py`，与 `spec/tests/validate.py` 同口径构造子 schema 校验器）：**46/46 通过，0 失败**。spec/ 本体未改动，其自带 validate.py 复跑结果不变（正例 14/14、反例 9/9）。

## 6. 弱加密警示实测证据

输入（SIP002 形态，userinfo 为 base64url 的 `aes-256-cfb:legacypass`）：

```
ss://YWVzLTI1Ni1jZmI6bGVnYWN5cGFzcw@old-ss.example.com:8390#Old-Node
```

实际产出（节录，2026-11-12 本机实测）：

```json
{
  "node": {
    "schemaVersion": "1.0",
    "name": "Old-Node",
    "protocol": "shadowsocks",
    "server": "old-ss.example.com",
    "port": 8390,
    "credential": {"method": "aes-256-cfb", "password": "legacypass"},
    "source": {"kind": "manual", "ref": "link-import", "authorization": "user-provided"}
  },
  "warnings": [
    {"code": "weak-encryption", "field": "method",
     "message": "加密方法 aes-256-cfb 为老式弱加密（非 AEAD），仅为无损导入存量订阅而保留；不得默认推荐，应提示用户更换节点"}
  ]
}
```

旧式整体 base64 形态的同一节点另叠加 `deprecated-format` 警示；AEAD 方法经断言不误报（测试 `TestWeakEncryptionWarningEvidence`）。

## 7. 未覆盖项与边界（如实列明）

1. VPN Gate CSV 只做格式解析；7.3 插件规格（强制风险提示页、CSV 镜像轮换、测活分组呈现）属 Step 14。
2. 导入方式中的扫码/剪贴板/定时更新为外壳职责（Step 9/10），本步只提供解析入口。
3. 订阅响应头流量信息（subscription-userinfo）需 HTTP 拉取层配合，登记对象已预留 traffic 字段，本步不拉取网络。
4. Clash YAML 里模型外协议（ssr、snell 等）按裁定逐条报错不映射；sing-box 的 wireguard 多 Peer 仅取第一个（模型单 Peer 取舍，已警示）。
5. L2TP/IPsec、SSTP、SoftEther 为第二梯队（系统编排/插件），不在 4.2 链接格式内，无解析器。
6. schema 校验在 CI 的 core 作业中依赖运行环境是否装有 python jsonschema：缺失时该测试跳过并注明；本地环境已实测 46/46。spec 本体的持续校验由 CI 的 spec 作业（validate.py）独立保证。

## 8. 与 governing source 的出入

无。4.2 清单逐项均有实现或明确边界说明（第 1、7 节）；Step 5 冻结裁定的弱加密义务已按 spec/README「评审裁定」原文落地。
