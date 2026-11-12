# Step 14：VPN Gate 来源插件

- 日期：2026-11-12
- 交付物：`plugins/vpngate/`（独立插件目录 + `manifest.json`）、app 语言包新增 `risk.vpngate.*` 三语词条、CI 新增 plugins 作业
- 边界：Step 8 已交付 CSV 格式解析（`parsers.ParseVPNGateCSV`），本步只做其文档明确划归 Step 14 的插件行为（镜像轮换、拉取缓存、测活分组呈现、强制风险提示），解析器复用不重写；spec/ 冻结文件与 core/kernel 接口未改动。

## 1. 拉取层与端点可达性实测

**实测结论（2026-11-12，本沙箱，经 egress 代理）**：

| 端点 | 结果 |
|---|---|
| `https://www.vpngate.net/api/iphone/` | ❌ 失败（curl exit 52，代理层重置 TLS 连接） |
| `https://vpngate.net/api/iphone/`（裸域） | ❌ 同上 |
| `https://www.vpngate.net/en/`（站点首页） | ❌ 同上 |
| `http://www.vpngate.net/api/iphone/` | ✅ **HTTP 200，1,320,421 字节，真实 CSV** |

即：vpngate.net 的 HTTPS 在本沙箱被代理层拦截（同机其他 HTTPS 站点正常，属该域名特异），HTTP 经代理可达并取得真实列表。插件端点顺序仍为 **HTTPS 在前、HTTP 兜底**（真实用户网络下 HTTPS 应优先成功；HTTP 仅作镜像轮换的一环，且响应必须过防投毒校验）。沙箱内已用生产 Fetcher 完整跑通轮换：HTTPS 失败 → 自动切 HTTP → **98 节点 / 8 国家组 / 0 坏行 / 新鲜数据**。公网 HTTPS 首选路径列入待外网验收（第 7 节）。

**样本来源说明**：全量样本于 2026-11-12 经上述 HTTP 端点实拉（98 数据行）；`plugins/vpngate/testdata/vpngate-sample-2026-11-12.csv` 为其表头 + 前 10 数据行的字节保真摘录（全量 1.3 MB 不入库）。

**拉取层设计**（`fetch.go`）：

- 镜像轮换：按 manifest 端点顺序逐一尝试，每端点单次尝试（轮换即重试策略，避免死镜像拖长列表刷新），单次超时 20s；
- 防投毒：响应大小上限 8 MiB（真实列表约 1.3 MB）；内容须含官方 CSV 标记（`*vpn_servers` + `OpenVPN_ConfigData_Base64` 列），且经 Step 8 解析器真实解析出 ≥1 可用节点与 A 级 Source 登记，否则判 `ErrInvalidPayload` 切换下一端点，绝不入缓存；
- 缓存与新鲜度：文件缓存（数据 + 抓取时间/端点元数据），TTL 60 分钟（与 manifest 更新频率一致）；TTL 内直接用缓存并标注 `FromCache`；过期后刷新失败时可回退旧缓存，但 `ListInfo.Stale=true` 且带 `LastError` 与原始抓取时间——**旧缓存永不冒充新鲜数据**（单测 `TestCacheFreshnessSemantics` 固化此语义）；无缓存且全部端点失败才报错（`FetchError` 聚合各端点原因）；
- 拉取请求带自报身份的 User-Agent（`Relavia-VPNGate-Plugin/1.0`），不夹带任何用户数据。

## 2. 映射与成组口径

节点构造 100% 走 Step 8 解析器；插件层补三件事：Source 登记以 manifest 数据补全（termsUrl、homepage、updateIntervalMinutes=60；status/basis 不动，为 A / `vpngate-official-csv`）、逐行元数据扫描（与解析器同序 zip：国家、运营者、自报 Ping/速度/会话数、LogType）、按国家/地区成组并打 `volunteer` 标注。实测产物过 spec schema 复验：**1 Source + 98 Nodes + 8 Groups，0 错误**；分组实况：Japan 48、Korea Republic of 27、Russian Federation 11、Croatia 4、Thailand 4、United States 2、India 1、Romania 1。

协议逐项映射口径（对照 7.3「协议限其支持的 SoftEther / OpenVPN / L2TP / SSTP」）：

| 协议 | 处置 | 依据 |
|---|---|---|
| OpenVPN | ✅ 完整映射 | CSV 逐行内嵌 `.ovpn` 配置，经解析器产出 configContent 模式节点，配置全文挂在 `credential.configContent`，节点 server/port 取配置 remote 行 |
| L2TP/IPsec | ❌ 不产出节点 | (a) `api/iphone` CSV 无 L2TP 逐节点字段（无启用标志、无逐节点凭据列），只有 OpenVPN 配置列；(b) 方案书 4.1 将 L2TP 列为第二梯队（系统编排），统一模型 v1 无 L2TP 凭据 schema；(c) 其站点级通用凭据属站点说明而非逐节点数据，据此臆造节点违反诚实原则。待官方列表提供逐节点字段或二期系统编排时再议 |
| SSTP | ❌ 不产出节点 | CSV 无 SSTP 逐节点参数；SSTP 为第二梯队（SoftEther 客户端系统编排），同上 |
| SoftEther 原生（SSL-VPN） | ❌ 不产出节点 | 原生协议需 SoftEther 客户端编排（第二梯队）；同一批服务器的 OpenVPN 兼容端点已被 OpenVPN 映射覆盖，不重复产出 |

**测活口径**（`probe.go`）：插件自有 TCP 可达性探针（连 server:port，量时延），结果强制带级别字段 `Level="tcp-connect"` 与说明文案，**不冒充协议握手**；UDP 模式节点报 `Level="none"`、未探（未知而非宕机）。CSV 自报 Ping 仅作来源数据透传（Meta 中标注 Reported），不当作我方测量。真实握手一项与 7.3 存在出入，见第 6 节。

## 3. 强制风险提示（硬验收）

**放置裁定**：确认状态机放插件侧（`consent.go`，守 `Plugin.Enable()`/`Refresh()`，因为门守的是插件启用）；展示文案放 app 的 i18n 词条体系（新增 `risk.vpngate.*` 6 词条，与 Step 9 的 `risk.*` 同族，受 `tools/i18ncheck` 与 i18n 包单测的三语完整性门禁覆盖，本步实测三包各齐全、违规 0）。不改 Step 9 已交付接口，以新增词条 + 新包实现。首次启用整页的风险页 UI 渲染与节点详情常驻行由 app UI 后续接线（数据与状态机本步已备齐并可用，接线清单见第 7 节）。

**状态机**（`Consent`）：未确认（None）→ 确认（Acknowledged，绑定文案版本 `vpngate-risk-v1` 与时间戳，文件持久化）；确认可撤销（Revoked）→ 源立即不可用；风险文案版本升级使旧确认变 Stale、按未确认处理，必须重新确认。`Plugin.Disable()` = 撤销确认 + 删除拉取缓存 + 关源，重启用必须重走风险门。单测覆盖：未确认 `Enable`/`Refresh` 均以 `ErrConsentRequired` 拒绝、确认后放行、撤销后再拒绝、旧版本确认失效、停用后缓存与确认状态不残留。

**文案要点核对表**（应覆盖 8 项，实覆盖 **8/8**；zh-Hans 为源语言，`risk.vpngate.body` 首段逐字采用 7.3 固定句，其余要点按其官方反滥用政策补足，zh-Hant/en 为人工翻译）：

| # | 要点 | 出处 | 落点 |
|---|---|---|---|
| 1 | VPN Gate 为筑波大学学术实验项目 | 7.3 固定句 | body 首句逐字 |
| 2 | 节点由全球志愿者提供 | 7.3 固定句 | body 首句逐字；node_line 以「志愿者节点」打头 |
| 3 | 节点运行在志愿者个人电脑与网络上，非商业服务器 | 官方政策（任务口径） | body 第二段 |
| 4 | 连接日志保留三个月以上 | 7.3 固定句 | body 首段逐字 |
| 5 | 数据包日志保留两周以上 | 官方政策；且 CSV 逐节点 LogType 列为一手证据（实测 98/98 标注 `2weeks`，插件逐节点透传 Meta.LogType 供 UI 展示） | body 第二段 + Meta 字段 |
| 6 | 日志可依法披露，含警方/法院依法要求 | 7.3 固定句「可依法披露」+ 官方政策 | body 首段逐字 + 第二段明示警方/法院 |
| 7 | 节点运营者可接触经其转发的未加密流量 | 7.3 固定句 | body 首段逐字 |
| 8 | 定位：适合一般可达性、不适合高敏感用途；可达性工具而非隐私工具 | 7.3 固定句 + 任务口径 | body 首段逐字 + 第二段明示「不是隐私保护工具」并点名口令/财务信息 |

三语文案全文见 `app/locales/{zh-Hans,zh-Hant,en}/messages.json` 的 `risk.vpngate.body`；节点详情常驻一行（7.3）为 `risk.vpngate.node_line`（三语均含：志愿者属性、运营者可记录连接与流量日志并可依法披露、不适合高敏感用途）。

## 4. 插件规范自检（对照 7.2）

| 7.2 条款 | 状态 | 证据 |
|---|---|---|
| 独立仓库目录含 manifest（来源名、运营方、授权依据、条款 URL、数据格式、更新频率） | ✅ | `plugins/vpngate/manifest.json` 全字段齐备；`LoadManifest()` 启动校验，缺项/非 A 级/权限越界拒绝加载（单测覆盖等级与版本一致性） |
| 输出统一节点模型并打 `source.authorization` 标识，UI 可溯源 | ✅ | 节点 `source={kind:plugin, ref:vpngate, authorization:vpngate-official-csv}`（解析器产出）；Source 登记含 termsUrl/homepage/operator；schema 复验 107 对象 0 错误 |
| 只能拉取、解析、测活；不得执行任意代码；不上报用户数据 | ✅ | manifest 权限声明三项为 false 且加载时强制校验；代码面只有 HTTP GET 官方端点、解析与 TCP 探针，无 exec、无任何上报通道 |
| 来源方条款变更或撤销授权，插件须在一个版本内下线 | ⚠️ 流程义务 | 无技术手段自动感知条款变更：登记为发布流程义务（每次发版前复核官方条款页与本节登记；风险文案版本机制保证政策要点变更时旧确认失效、强制用户重读） |
| 停用即删缓存（自检项） | ✅ | `Disable()` 删除缓存数据与元数据并撤销确认，单测验证停用后同目录新实例读不到缓存与有效确认 |
| 无遥测（口径总表第 7 条） | ✅ | 插件不含任何统计/上报代码；唯一外发请求为拉列表本身 |

## 5. 测试结果（全绿）

| 套件 | 结果 |
|---|---|
| `plugins/vpngate` 单测 | **13/13 通过**：镜像轮换（500/HTML 冒牌/正常三级跳）、全端点失败聚合、超限响应拒绝、防投毒校验（HTML 与坏行 CSV 均拒、真实样本通过）、缓存新鲜度语义（TTL 内免网络、过期+断网回退带 Stale 标注、停用清除）、真实样本映射（10 行摘录：节点/分组/Source/志愿者标注/LogType 对齐）、manifest 等级与词条键集、启用门全生命周期、同意状态机（确认/撤销/版本失效/文件持久化）、探针（TCP 可达/拒绝/UDP 未探） |
| 生产 Fetcher 真实端点端到端（一次性验证，已删测试文件） | ✅ 轮换 HTTPS→HTTP 成功，98 节点 / 8 组 / 0 坏行 |
| 产物 spec schema 复验 | ✅ 1 Source + 98 Nodes + 8 Groups，0 错误 |
| app 模块 | ✅ `go test ./i18n/ ./service/` 通过；`tools/i18ncheck` 三包对齐、违规 0 |
| core 模块回归 | ✅ build/vet/test 全过（未改 core 任何文件，解析器为纯复用） |
| CI | 新增 `plugins` 作业（build/vet/test @ plugins/vpngate），待推送后实跑确认 |

## 6. 与 governing source 的出入

1. **测活与 7.3「以真实握手为准入」存在差距（如实登记）**：真实 OpenVPN 握手须以 OpenVPN 独立进程引擎执行（Step 2 许可证审计裁定的集成形态），该引擎尚未落地；Step 7 的 sing-box 适配器明确将 OpenVPN 报为不支持（`core/singbox/capabilities.go`）。本步的准入实现为「配置经解析器校验有效 + TCP 可达性探针」，且探针结果强制标注级别、绝不冒充握手。后续路径：OpenVPN 进程引擎落地后，准入改走 `kernel.Adapter.TestHandshake`，探针降为预筛。连接动作本身在引擎落地前同样不可用——VPN Gate 节点在 v1.0 内为「可导入、可测活（可达性）、待引擎接通连接」，UI 呈现须按此如实标注，不得宣称可连接。
2. 7.3 固定风险句未含「数据包日志两周以上」与「警方/法院」字样，此两点按任务口径与官方反滥用政策原文补入 body 第二段，固定句本身一字未改、仍为 body 首段。
3. 其余与 7.1/7.2/7.3/Step 14 原文无出入。

## 7. 待外网 / 待后续项

| # | 事项 | 说明 |
|---|---|---|
| 1 | 公网 HTTPS 端点复测 | 沙箱内 vpngate.net 的 HTTPS 被代理拦截（HTTP 已通）；需在真实网络验证 HTTPS 首选路径、证书校验与轮换顺序 |
| 2 | OpenVPN 真实握手准入与连接 | 待独立进程引擎（见第 6 节出入 1） |
| 3 | 风险页整页 UI 与节点详情常驻行接线 | 词条 `risk.vpngate.*` 与状态机已备齐；app UI 在后续界面步接线（首次启用拦截页、节点详情常驻 `node_line`、设置内 `revoke` 入口） |
| 4 | 官方镜像名录复核 | 当前端点为官方主站 HTTPS/HTTP 两形态；VPN Gate 另有镜像站，纳入 manifest 前须逐一核验运营归属，非官方转载站一律不列（防投毒口径） |
| 5 | 条款变更监测 | 发版前人工复核官方条款/反滥用政策页（第 4 节流程义务） |
