# VPN Gate 来源插件（plugins/vpngate）

Relavia 一期唯一的官方公共源插件（方案书 7.3）。数据源为日本筑波大学
VPN Gate 学术实验项目的官方服务器列表 CSV——其官方明确提供该列表
供第三方制作客户端接入（7.1 分级 A 级）。

## 它做什么

- **拉取**：按 manifest 端点顺序轮换拉取官方 CSV（主端点失败自动切
  下一个；每端点单次尝试、超时与 8 MiB 响应上限）；响应必须通过格
  式标记 + 真实解析双重校验才入缓存（防投毒）；缓存带抓取时间与来
  源端点，过期或刷新失败时以 `Stale` 明确标注，绝不冒充新鲜数据。
- **映射**：节点构造 100% 复用 Step 8 的 `parsers.ParseVPNGateCSV`
  （OpenVPN 配置全文挂在节点 `credential.configContent`）；本插件补
  上逐行元数据（国家、运营者、其自报 Ping/速度、逐节点 LogType）、
  国家/地区分组与志愿者标注。L2TP / SSTP / SoftEther 原生协议不产
  出节点（理由与处置见 docs/step14-VPNGate来源插件.md）。
- **测活（两级，级别强制标注）**：① 插件自有 TCP 可达性探针
  （`tcp-connect`，不是协议握手；UDP 节点报未探，未知非宕机）；
  ② 真实握手准入（`handshake-verified`）：OpenVPN 独立进程引擎
  落地后接入（`probe_handshake.go` 的 `HandshakeProber`）——经
  内核适配器 `TestHandshakeNode` 完成真实 OpenVPN 握手，TCP 探
  针降为预筛。握手由项目自有内核适配器执行，插件只经接口注入
  与编排；源数据永远只作数据、绝不作为代码执行（适配器侧亦会
  剥离配置中的脚本钩子）。公网实握属公网验收项，见
  docs/openvpn进程适配.md。
- **风险门（硬性）**：未确认 7.3 强制风险提示不得启用——`Consent`
  状态机守住 `Enable()`/`Refresh()`；确认绑定风险文案版本，文案更
  新即失效须重确认；停用即撤销确认并删除拉取缓存。文案三语词条在
  `app/locales` 的 `risk.vpngate.*`（与 Step 9 的 `risk.*` 同族、同
  受 i18n 完整性门禁覆盖）。

## 纪律（方案书 7.2）

插件只能拉取、解析、测活：不执行任意代码、不上报任何用户数据、
无遥测。`manifest.json` 为来源登记（运营方、授权依据、条款 URL、
数据格式、更新频率、权限声明），`LoadManifest()` 在启动时校验其
合规性（非 A 级或权限声明越界直接拒绝加载）。

## 测试

```sh
go test ./...   # 轮换/防投毒/新鲜度语义、真实样本映射、状态机、探针
```

`testdata/vpngate-sample-2026-11-12.csv` 为 2026-11-12 经官方端点
实拉列表的摘录（表头 + 前 10 行，字节保真；全量 98 行约 1.3 MB 未入库）。
