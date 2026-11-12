# Step 11 路由与 DNS — 交付记录

- 阶段：阶段 1（MVP 客户端）Step 11
- 验收依据：方案书第 14 章 Step 11 原文——「交付分流规则、DNS 策略与防泄露默认配置。验收：泄露检测用例（WebRTC/DNS/IPv6）通过并留记录」；口径来源为 5.4（DNS 内置防泄露、远程解析优先、禁止明文回落）与 8.1（路由分流：全局、规则、直连名单；IPv6 开关）。
- 结论：**本步交付完成**。路由规则引擎、DNS 策略编译、默认安全配置包均落地并有单测；泄露检测在本沙箱可自动化范围内全部通过（逐条记录见第 7 节）；WebRTC 与真公网项如实列为待真机验收并附一键脚本（第 8 节）。

## 1. 交付物与架构选择

| 交付物 | 位置 |
|---|---|
| 策略类型与校验（Policy / Rule / RuleSetRef / DNSPolicy / IPv6Policy） | `core/routecfg/routecfg.go` |
| 编译器（Policy → sing-box route + dns 片段） | `core/routecfg/compile.go` |
| 默认策略构造函数 | `core/routecfg/defaults.go` |
| 默认安全配置包（JSON + 说明） | `core/routecfg/defaults/system-proxy.policy.json`、`tun.policy.json`、`README.md` |
| 与 Step 7 的衔接 | `core/singbox/compile.go`（compileOptions 增加 fragment 输入）、`core/singbox/singbox.go`（Options 增加 `Routing *routecfg.Policy`，校验期编译、启动期合并） |
| 泄露检测 rig | `core/singbox/step11_leak_test.go` |
| 真机泄露自查脚本 | `scripts/leak-check.sh` |

**架构选择：新包旁置，不改 kernel 接口、不改 spec 冻结文件。** 理由：Step 7 的节点编译器以「一个节点」为单位，路由/DNS 策略与节点无关（同一策略配任何节点）；策略独立成包后，Step 9/10 的双端 UI、Step 13 的存储都以 Policy JSON 为共同契约。singbox 侧改动限于加法：无 Routing 时行为与 Step 7 逐字一致（其全部既有测试保持全过，见第 9 节）；策略编译失败在 Validate 阶段即以 `invalid_config` 暴露，不拖到启动期。对 `core/singbox` 的改动与并行 Step 9 的文件面不重叠（未动其 UI/平台文件；compile.go/singbox.go 的改动均为可选字段与可选分支）。

## 2. 规则语义与优先级（规范口径）

sing-box 按序求值、首命中裁决、route.final 兜底。编译器把用户规则重排为固定类别序，使裁决不依赖用户书写无关规则的先后：

| 类 | 内容 | 理由 |
|---|---|---|
| A 不变式 | IPv6=off 时 `{ip_version:6 → reject}` 置于一切规则之前 | 「关」必须是绝对的，任何后续规则不得复活 IPv6 |
| B 用户 block | 全部 block 规则，按声明序 | 显式拒绝是硬否决，压过同目标的 direct/proxy，无论用户写在列表何处 |
| C IPv6 仅隧道 | IPv6=tunnel 时 `{ip_version:6 → out}` | IPv6 永不命中其下的直连规则；节点不支持 v6 时失败关闭而非直连泄露 |
| D 用户规则 | 其余 direct/proxy 规则，按声明序 | 类内以用户声明序为优先级，首命中裁决 |
| E 内置旁路 | `{ip_is_private → direct}`（规则/直连名单模式且开启时） | 在一切用户规则之下：用户对私有目标的显式规则永远压过旁路 |
| final | `out`（节点），三模式一致 | 未命中即走代理——防泄露的兜底方向 |

模式语义（8.1「全局、规则、直连名单」）：

- **全局**：不生成 D/E 类；含 direct/proxy 规则的策略在该模式下**编译报错**而非静默忽略；block 仍生效。
- **规则**：全类别。
- **直连名单**：仅 direct 与 block（proxy 规则报错——未列名流量本就走 final=out，写 proxy 规则必是笔误）；final=out 不变。

匹配字段：域名（精确）、域名后缀、域名关键词、域名正则、IP 网段（裸 IP 归一化为宿主前缀）、端口、端口范围、协议（嗅探名）、进程名、规则集引用。字段间 AND、字段内 OR（sing-box 默认规则语义，编译器原样保留）。**进程名为 Windows 预留**：编译器在所有平台都生成 process_name 条件，但进程归属依赖平台层（sing-box find_process），无平台支持的环境下该规则永不命中——不报错、不假装生效，待 Step 9 平台层接通。GeoIP/GeoSite 类别以**规则集引用**表达（本地/远程/inline 三型；sing-box 1.14 已删除 legacy geosite/geoip 字段）；本步只发引用不发类别数据，远程集可声明经代理下载（download_detour=out）。

单测以「语义求值器」验证行为而非仅查 JSON 形状：对编译产物重放 sing-box 求值语义，逐条断言目标的裁决出口（见第 9 节用例名）。

## 3. DNS 策略

**两条解析路径，策略各管一条**（这是本步最重要的事实认定，来自 rig 实测而非文档推测）：

1. **客户端亲自解析的名字**——直连连接的目标名、TUN 模式下被劫持的系统查询——由客户端 DNS router 按 DNS 规则裁决：直连名 → 本地解析器；其余 → 远程解析器（经隧道）。
2. **随隧道携带的名字**——socks/shadowsocks/trojan/vmess 等出站原生支持把域名交给远端解析，名字在隧道内传输、由节点在出口处解析。它**永不触碰任何本地解析器**，无本地泄露面；其解析质量由实际出口决定，对 CDN 反而更正确。

**镜像规则**：DNS 规则由同一份 Policy 规则派生，杜绝两套规则漂移。仅「纯域名类」规则（域名/后缀/关键词/正则/域名类规则集）镜像：direct→local、proxy→remote、block→DNS reject；带 IP/端口/协议/进程条件的**混合规则不镜像**——DNS 查询没有那些事实，其名字按默认（远程）解析，连接时路由层再执行完整规则。镜像顺序与路由类别序一致（block 在前）。

**远程与本地的形态**：

- 远程服务器编译恒带 `detour: out`——远程解析器若不经隧道，它本身即泄露点，此不变量不可配置关闭。默认 DoT 1.1.1.1:853（可替换字段，非产品背书）；udp/tcp/tls/https 四型均可编译。
- 本地服务器默认 `type: local`（系统解析器），亦可显式指定 udp/tcp 地址；恒不带 detour。它只会收到镜像给它的直连名——这些名字的流量本就直连，本地解析反而避免「远程解析出异地 CDN 地址再直连」的错位。
- `dns.final` 恒为远程：**不存在任何从未列名域名回落本地解析器的路径**（5.4「禁止明文回落」的落地形态）。
- strategy 随 IPv6 策略联动：off → `ipv4_only`；其余 → `prefer_ipv4`。

## 4. fake-ip 裁定：默认关（可按策略开启）

**裁定：默认 OFF。** 理由与泄露面分析：

- fake-ip 的收益在 TUN 模式：应用拿假地址先建连、真实解析推迟到连接时由远端完成，可防「应用先用系统 DNS 问一遍真地址」的预解析泄露。但本设计的 TUN 口径是全量劫持系统查询进客户端 DNS router（由平台层 Step 9/10 落地），被劫持的查询直接按规则裁决，预解析泄露面已被劫持本身覆盖，fake-ip 的增量收益收窄。
- fake-ip 的代价是全局性的：一切应用的解析语义被改写（拿到假地址），与实地址假设的应用（部分游戏、局域网发现、按 IP 做校验的服务）存在兼容风险；直连名的 CDN 就近性、故障排查的直观性（日志里全是假地址）都变差。而本项目的默认姿态是「真实解析 + 远程默认」，行为确定、可测（rig 的令牌证据法依赖真实解析）。
- 泄露面对比：开 fake-ip 后，非 A/AAAA 查询仍走真实解析（本编译器的 catch-all 只覆盖 A/AAAA）；关 fake-ip 时 TUN 外场景的预解析风险来自应用绕过代理自查 DNS——那是系统代理模式的固有边界（见第 6 节 WebRTC 同类口径），不是 fake-ip 能补的（fake-ip 只在客户端 DNS 被查询时才工作，绕过代理的应用同样绕过它）。

开启形态（Policy.DNS.FakeIP=true）：编译增 fakeip 服务器（默认池 198.18.0.0/15、fc00::/18；IPv6=off 时不发 v6 池）与一条置于镜像规则**之后**的 `{query_type:[A,AAAA] → fake}` catch-all；`dns.final` 仍为远程（sing-box 1.14 明文禁止 fakeip 作默认服务器，原文报错 `default server cannot be fakeip`，rig 实测确认），连接时由远程完成真实解析；镜像的直连名仍走本地真实解析，保住直连 CDN 就近性。

## 5. IPv6 三态

| 策略 | route 形态 | DNS strategy | 语义 |
|---|---|---|---|
| on | 无额外规则 | prefer_ipv4 | v6 与 v4 同规则裁决 |
| off | 类 A reject 一切 v6 | ipv4_only | v6 流量拒绝、AAAA 答案永不使用，双通道关闭 |
| tunnel | 类 C：v6 只许命中 out | prefer_ipv4 | v6 可解析可用，但永不直连；节点无 v6 则失败关闭 |

## 6. 默认安全配置包

两份 JSON 与构造函数逐字对应（测试防漂移），共同口径：规则模式、私有旁路开、远程 DoT 默认、本地仅镜像、fake-ip 关。差异只有一处且有据：**系统代理版 IPv6=on**（该模式不接管系统网络栈，声称更强的 v6 控制是不实的）；**TUN 版 IPv6=tunnel**（该模式接管整机流量，v6 旁路是 TUN 的经典泄露口，必须在配置层关死；平台层还欠「TUN 接口本身捕获 v6」一半，属 Step 9/10，断网保护属 Step 12——文档不代为宣称）。

**WebRTC 告知（诚实口径，全文在 defaults/README.md）**：客户端不能代管浏览器 WebRTC。TUN 模式下 WebRTC 流量随隧道裁决（节点无 UDP 中继则失败而非直连，前提 Step 12 就位）；系统代理模式下 WebRTC 的 UDP 探测可能绕过代理，**只能由用户改浏览器设置**（Firefox `media.peerconnection.enabled=false`；Chrome/Edge 策略 `WebRtcIPHandlingPolicy=disable_non_proxied_udp`），客户端仅提供检查入口与指引，任何「已完全堵住」的产品文案均属不实、禁止。

## 7. 泄露检测用例实测记录（本沙箱）

环境与方法：客户端 = 真实 sing-box 实例（SOCKS5 节点 + 本步策略片段）；服务端 = 回环 relay 实例（Step 7 harness 同法）；两个假 DNS 服务器（本地替身 / 隧道侧替身）记录全部查询并分别应答 127.0.0.1 与 127.0.0.2，两地址后各置一个回声服务器、令牌不同——**连接去向以令牌为据、解析归属以查询日志为据**，双证据。relay 的解析器即隧道侧假 DNS：随隧道以 FQDN 携带的名字在出口处由它解析，与生产环境节点解析同构。

**沙箱限制如实记录**：本沙箱在 syscall 层禁止一切 UDP 发送（Step 7 已验，本步复测仍然），故假 DNS 以 **DNS-over-TCP** 运行；其走的是与 UDP/DoT/DoH 相同的 sing-box DNS 路由求值路径，规则裁决证据有效；UDP 传输特有行为不在本 rig 覆盖内，由第 8 节脚本在真实环境补验。IPv6 回环 TCP 在本沙箱可用，v6 用例为真跑非跳过。

| # | 用例 | 断言 | 结果 |
|---|---|---|---|
| L1 | `TestStep11RuleModeDNSSeparation`（规则模式 DNS 分离） | 直连名单名：本地日志有查询、远程日志无、令牌=直连侧；未列名：远程日志有查询、本地日志无、令牌=隧道侧 | **PASS** |
| L2 | `TestStep11GlobalModeNoDirectNoLocalDNS`（全局模式） | 同一直连名单名在全局模式下：令牌=隧道侧、本地解析器查询总数=0、远程日志有查询 | **PASS** |
| L3 | `TestStep11IPv6OffBlocksLiteralV6`（IPv6 关） | `[::1]` 字面目标在 off 时连接失败；对照组 on 时成功达回声服务器（证明拒绝来自策略而非环境） | **PASS** |
| L4 | `TestStep11FragmentsAcceptedByKernel`（片段内核验收，2 子例） | 含 inline 规则集 + block + process_name 规则的策略、含 fake-ip 的策略，编译产物均被 sing-box 本体解析并成功启动 | **PASS** |

过程中两条实测修正（已回写代码注释，防后人重蹈）：

1. `route.default_domain_resolver` 的两种形态都与本设计相斥：点名服务器形态使出站解析**绕过 DNS 规则求值**（rig 实测：直连名单名被远程解析器应答，镜像失效）；无服务器对象形态被 1.14 解析器拒绝（`empty domain_resolver.server`）。结论：1.14 下保持不设置，其默认语义恰为第 3 节两条路径。**内核升级监视项**：未来 sing-box 若移除未设置形态，升级内核前必须先重评此点，不得顺手「补上」该字段。
2. fakeip 不得为 dns.final（上游明文拒绝），故 fake 形态以尾随 query_type catch-all 实现（第 4 节）。另：上游对 `dns.independent_cache` 已发弃用警告（1.16 移除），本编译器不生成该字段。

## 8. 待真机 / 公网验收项（不在本沙箱宣称通过）

| 项 | 原因 | 补验方式 |
|---|---|---|
| WebRTC 真实浏览器泄露 | 需真实浏览器 RTCPeerConnection + 公网 STUN | `scripts/leak-check.sh` 第 5 节人工指引（脚本无法代查，设计上只打印步骤、不假装自动通过） |
| 公网 DNS 解析器身份（出口侧解析器是否为预期） | 需真实节点与公网 | 脚本第 2 节（TUN 模式下 whoami 查询比对）；第 1 节出口 IP 双路对比、第 3 节公网 IPv6、第 4 节直连名单抽查 |
| UDP 传输的 DNS 行为（DoT/DoH/UDP 远程服务器实连） | 沙箱封 UDP 发送 | 真实环境跑脚本 + 以真实节点各传输至少连一次（Step 15 发布前真机清单承接） |
| TUN 模式系统查询全量劫持、v6 捕获 | 平台层未落地（Step 9/10） | 各端 MVP 验收时以脚本第 2/3 节实测 |
| 节点服务器为域名时的引导解析 | rig 节点为 IP 字面量 | 客户端组装后以域名节点实测一次：观察节点名解析走 DNS router（final=remote 的 detour 引导由 sing-box 直连远程解析器完成，为生态通行形态），记录于 Step 15 真机清单 |

脚本 `scripts/leak-check.sh` 已入库（bash 语法校验过），在有网环境按 README 注释一键运行；其自动项有明确 PASS/FAIL，人工项只给指引。

## 9. 测试统计

- `core/routecfg`：14 个测试函数全过（优先级求值 6、DNS 编译 3、校验拒例 1 函数 12 例、默认值与文件一致性 2、裸 IP 归一化 1、fake-ip 形态含于 DNS 编译组）。`go vet` 干净。
- `core/singbox` 泄露用例：4 个测试函数（含 2 子例）全过（第 7 节 L1–L4）。
- 回归：`go build ./...`、`go vet ./...`、`go test ./...`（全模块无标签）全过；带官方 tags 的 `./singbox/` 全套（含 Step 7 回环握手套件）全过——Step 7/8 既有行为零回归。
- 本步未改：`core/kernel` 接口、`spec/` 冻结文件、Step 8 解析器。

## 10. 未完成项（明确边界）

- 类别数据（GeoSite/GeoIP 规则集文件本身）不在本步交付：只发引用与下载口径，数据分发归 Step 15/20 发布工程。
- 进程名规则的平台生效（find_process 接线）归 Step 9；TUN 的 DNS 劫持与 v6 捕获归 Step 9/10；断网保护归 Step 12。本步配置层与它们的接口即 Policy JSON，不另设私有格式。
- WebRTC 与公网项未在本沙箱通过——是「待真机」，不是「已通过」（第 8 节）。
