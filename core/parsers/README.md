# parsers 包（Step 8 解析器全家桶）

把方案书 4.2 的全部链接与订阅格式解析为 spec/ 已冻结的统一节点模型
（Step 5）对象。设计与覆盖对照见 `docs/step8-解析器全家桶.md`。

## 落点说明

包放在 `core/parsers/`（模块 `openproxy/core` 内），理由：

- 与 Step 6/7 的内核适配同模块，Step 9/10 客户端外壳可直接 import；
- 自动纳入仓库 CI 的 `core` 作业（go build / vet / test）；
- 不修改 `core/kernel` 既有接口，不修改 `spec/` 任何文件。

## 入口速览

| 入口 | 用途 |
|---|---|
| `ParseLink(raw, opts)` | 单条分享链接（ss/vless/vmess/trojan/hysteria2/hy2/tuic/wg/wireguard/socks5/http/https） |
| `ParseLinkList(text, opts)` | 明文链接列表，逐条标注成败 |
| `ParseSubscription(content, sopt)` | 订阅内容自动识别：sing-box JSON / Clash YAML / V2Ray base64 / 链接列表；产出节点 + Group/Subscription/Source 登记 |
| `ParseWireGuardConf(content, opts)` | WireGuard .conf（多 Peer 逐个成节点） |
| `ParseOpenVPNConf(content, opts)` | .ovpn 全文无损映射（configContent 模式） |
| `ParseVPNGateCSV(content, opts)` | VPN Gate 官方 CSV（格式解析；7.3 插件行为属 Step 14） |
| `BuildSubscriptionRecord(...)` | 已知 URL 时构造订阅登记 |

## 约定

- 错误一律结构化（`ParseError{Code, Index, Segment, Detail}`），不 panic；
- 警示随产出携带（`Warning{Code, Field, Message}`）；其中
  `weak-encryption` 是 Step 5 评审冻结裁定的硬义务：SS 老式方法
  （cfb 系、chacha20 系、rc4-md5、none）导入时必带此警示，
  且 UI 层不得默认推荐此类节点；
- 节点 id 由内容哈希确定性派生，订阅刷新时同一节点不换 id；
- `testdata/validate_outputs.py` 可把测试产出再过一遍 spec schema 校验
  （Go 测试 `TestOutputsValidateAgainstSpecSchema` 自动调用，
  环境缺 python jsonschema 时跳过并注明）。
