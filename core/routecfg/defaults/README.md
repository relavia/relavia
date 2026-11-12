# 默认安全配置（Step 11 交付物）

两份基线策略，与 `core/routecfg/defaults.go` 的构造函数逐字对应
（测试保证不漂移）。它们是「开箱即用的安全默认」，不是功能上限：
用户规则、远程解析器地址、fake-ip 开关都可以在策略层调整，
调整方式见 `docs/step11-路由与DNS.md`。

| 文件 | 适用 | 路由 | IPv6 | 说明 |
|---|---|---|---|---|
| `system-proxy.policy.json` | 系统代理模式（Windows v1.0） | 规则模式＋私有地址直连 | 开（prefer_ipv4） | 只有遵循系统代理的应用被接管 |
| `tun.policy.json` | TUN 模式（Windows Wintun / Android VpnService） | 规则模式＋私有地址直连 | **仅隧道** | 客户端接管整机流量，IPv6 不许走直连路径 |

两份默认的共同安全口径：

- **DNS 远程优先且无明文回落**：默认解析器是经隧道 detour 的远程
  DoT（1.1.1.1:853，可替换）；本地解析器只接收被用户明确直连的
  域名（镜像规则），其余域名没有任何路径落到本地运营商 DNS。
- **fake-ip 默认关**：裁定理由见 step11 文档第 4 节。
- **私有地址直连在用户规则之下**：用户显式规则永远压过内置旁路。

## WebRTC 泄露：产品侧告知要点（诚实口径）

客户端**不能**代管浏览器内部的 WebRTC 行为。任何宣称「客户端已
完全堵住 WebRTC 泄露」的说法都是不实的；产品内的告知文案必须按
下面口径写，设置页的「泄露检查入口」（方案书 8.1）链接到这份指引：

- **TUN 模式**：WebRTC 的 STUN/UDP 流量与其它流量一样进入隧道，
  由路由规则裁决；节点不支持 UDP 中继时 WebRTC 连接失败而不是
  直连（失败关闭的前提是 Step 12 断网保护就位）。此模式下仍建议
  在浏览器里复核一次（下方检查链接），因为浏览器可能缓存旧的
  局域网候选地址（mDNS 候选一般无害，但文案不得承诺为零）。
- **系统代理模式**：浏览器只把遵循代理的流量交给客户端，WebRTC
  的 UDP 探测**可能绕过代理**暴露真实出口 IP。此模式下要防
  WebRTC 泄露，只能改浏览器侧设置，客户端无权代劳：
  - Firefox：`about:config` 中 `media.peerconnection.enabled`
    设为 `false`（或使用 `disable_non_proxied_udp` 等价策略）；
  - Chrome / Edge：企业策略 `WebRtcIPHandlingPolicy` 设为
    `disable_non_proxied_udp`；个人用户可用浏览器商店的
    WebRTC 控制类扩展（只推荐类别，不背书具体产品）；
  - Safari：WebRTC 默认受限，仍建议以检查链接实测为准。
- **检查方法**：连接前后各打开一次 WebRTC 泄露检测页（社区通行
  的检测页即可，文档不绑定具体站点），对比显示的公网 IP 是否与
  隧道出口一致；`scripts/leak-check.sh` 第 5 节会打印这一步的
  操作指引。

英文版要点（供三语文案表落词条时参照，正式译文走人工翻译流程）：
"The client cannot control your browser's WebRTC behaviour. In
system-proxy mode, WebRTC may bypass the proxy and reveal your
real IP address; restrict it in your browser settings as
described here. In TUN mode WebRTC traffic is routed like all
other traffic."
