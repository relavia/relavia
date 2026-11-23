# 自研协议路线 01 · Shadowsocks 二期（数据面）跑批记录

日期：2026-11-23。承接一期差分跑批记录（同目录），对象为规格
§7 二期条目：自备转发层接线（Start 路径）、缓冲池与封包优化
后 G6 复测、数据面差分（G1/G2 复跑 + G4 数据面部分，含一期
挂账 NEG-04 / NEG-07）。G5 长时 fuzz 配额属发布候选阶段事项，
不在本包（规格与一期记录口径不变）。

环境：Linux amd64 本机跑批（Go 1.25.5 工具链）；参考服务端与
一期同：shadowsocks-rust ssserver v1.25.0（本机二进制）与
sing-box 1.14.0-alpha.34 的 SS 入站（进程内）；对照组与一期同：
sing-box 适配层数据面（Start → mixed 入站 → SS 出站）。本机
沙箱的 UDP 环回被环境拦截（探针实测超时），全部 UDP 腿在本机
如实 Skip、由 CI 实跑（CI 作业装有同版 ssserver 且 UDP 可达；
一期 UDP G1/G2 已在 CI run 45125369812 实跑通过）。CI 判决由
主会话拾取，本机结论不冒充 CI 结论。

提交（main，英文 + Signed-off-by）：
dc1e312（引擎封包优化）、202ac0e（转发层与接线）、
6599bdf（数据面差分台架 + 中继快路径）、172abbe（半关闭缺陷
修复）。gofmt / vet 净；无标签全量与带标签
（with_quic/with_utls/with_wireguard/with_gvisor）
selfdev + singbox 套件本机全绿。

## 1. 转发层语义对照表（逐项验收）

转发层在 core/selfdev/forward.go（本地 mixed 入站：SOCKS5
CONNECT / UDP ASSOCIATE + HTTP CONNECT / 绝对形式）、
policy.go（路由求值与 DNS 镜像）、dns.go（本地/远端解析）、
adapter.go（Start 分发）。对照基准为 routecfg 编译出的
sing-box 语义（Step 11）与 killswitch 就绪门（Step 12）。

### Step 11 路由

| 项 | sing-box 语义 | 自研 plane | 判定 |
|---|---|---|---|
| 规则类 B 域名（keyword/suffix/exact/regex） | 逐规则首中即决 | 同定义求值（policy.go 与 routecfg 逐项对齐），单测覆盖 | 对齐 |
| 规则类 C 端口（单值/区间） | 同上 | 同上 | 对齐 |
| 规则类 D IP（ip_cidr） | 域名目标先经路由 DNS 解析再判定 | 同：触发 IP 阶段时经隧道内远端解析判定（见 DNS 行）；IP 字面量直接判定 | 对齐（rig 实测） |
| 规则类 A 协议嗅探（protocol） | 对流量嗅探后判定 | **拒绝求值**：Start 时返回分类错误（KindUnsupported），不静默近似 | 差异（如实）：含嗅探规则的策略在自研档下不可启动 |
| 规则类 E 进程（process_name 等） | 桌面端按连接进程判定 | **拒绝求值**：同上（进程归属不在 core 层可得） | 差异（如实）：同上 |
| 远程规则集（非 inline） | 拉取后求值 | **拒绝求值**；inline 规则集可展开求值（含其内嵌规则递归） | 部分差异：inline 对齐，非 inline 拒绝 |
| 规则集内 sniff/process 字段 | 求值 | 展开时同样拒绝 | 差异（如实） |
| 默认动作 / rule 模式回落 | default → proxy；global → 全 proxy；direct 模式全直连 | 同 | 对齐 |
| bypass 私有地址段 | 编译为首条 ip_cidr direct 规则 | 求值器同序注入（类 D 首条） | 对齐 |
| IPv6 关闭 | v6 目标在路由层被拒 | 同：IP 字面量与解析结果的 v6 均拒绝（rig 实测字面量） | 对齐 |
| block 动作的可观察形态 | SOCKS 回复码 1（general failure）后断开 | 回复码 2（not allowed by ruleset）后断开 | **裁决性差异**：两边都拒绝连接，仅回复码不同；按 G4 分类同属「策略拒绝」。plane 取 RFC 语义码，对照取其粗粒度码，记录在案不强行抹平 |
| 代理目标的连接拒绝形态 | SS 无连接响应：隧道建立即 SOCKS 成功，拒绝发生在数据阶段 | 同（rig 双面实测：回复码 0 + 首读失败、零交付） | 对齐（协议固有形态，钉为可观察行为） |

### Step 11 DNS

| 项 | sing-box 语义 | 自研 plane | 判定 |
|---|---|---|---|
| remote/local 分流 | 直连域名走 local、代理域名走 remote（detour 经隧道在出口侧解析，客户端不预解析代理名） | 同（dns.go 镜像 routecfg 的策略形态；决策顺序：域名规则直判 → 需 IP 阶段才解析且走 remote → 直连走 local） | 对齐（rig 分离验收通过，见 §3） |
| 远端解析传输 | udp/tcp/tls(DoT)/https(DoH)，detour=节点 | 同四种，均经引擎隧道（DoH 走隧道 TCP） | 对齐 |
| 本地解析传输 | udp/tcp 或系统 | udp/tcp 显式服务器或系统解析器 | 对齐 |
| fake-ip | 编译默认关（Step 11 既定）；开时由入站返回伪地址段 | plane 不提供 fake-ip 服务；默认关口径下 manual 模式以真实解析等价承接 | 默认口径对齐；fake-ip 手动开启场景**未覆盖**（差异如实） |
| DNS 缓存 | sing-box 侧有缓存 | plane 无缓存，每次决策实时解析 | 已知差异：正确性无影响；重复查询的时延与指纹面不同，记录在案 |
| DNS 规则（dns.rules） | routecfg 编译为空（无此配置面） | 同（镜像函数对空规则直通） | 对齐 |

### Step 12 kill switch 与形态覆盖

| 项 | 语义 | plane 落实 | 判定 |
|---|---|---|---|
| kill switch 就绪门 | 开关开启且后端未就绪 → Start 拒绝（Step 12） | 与 sing-box 共用同一 KillSwitchReadiness() 函数源（adapter.startRouted），verdict 必然一致；rig 纪律测试断言两后端同 verdict 同错误分类 | 对齐（本机走构造性 unsupported 分支；真 nftables/真机验证是 Step 12 既有挂账，非本包新增） |
| TUN 模式 | 归 sing-box（本构建 caps.TUN=false 时在其侧如实拒绝） | route() 在 TUN 下回 sing-box 并记录原因，plane 不接 | 如实维持 sing-box，不假装覆盖 |
| system-proxy 模式 | 归 sing-box | 同上（manual 模式才进 plane） | 如实维持 |
| 非 SS / plugin / 链式节点 | 归 sing-box | route() 逐项判定并在日志写明不合资格原因（如 plugin 名）；rig 断言 plugin 节点在自研档下仍走 sing-box 且原因入日志 | 如实维持 |
| 档位与回退 | 三档策略不变；回退只在连接建立决策点；自研 Start 失败如实上报 | Start 路径不做会话中途切换；plane 自身装配失败（KindInternal）绝不偷偷改走 sing-box；默认档仍为 singbox | 对齐（规格 §3.2 纪律） |
| 流量统计 | 适配层 QueryTraffic | 双后端聚合（plane 原子计数 + sing-box 侧原有来源）；rig 断言自研 Start 后计数随真实流量增长 | 对齐 |

## 2. G6 复测（同口径环回对照，门线 0.70 不变）

一期未达线根因（按块两次 Seal + 无缓冲复用）的处置：
chunkWriter 增加零拷贝快路径（输入 ≥ 块上限时直接在调用方
缓冲上封包）与池化单次写出；chunkReader 缓冲池化复用；
nonce 计数器热路径零分配（stream.go / aead.go）。哨兵改为
3 次采样取中位数（共享 CPU 环境单样本噪声过大，一期记录的
区间波动即此故；口径其余部分与一期完全一致：同回环、同
4 MiB、同 echo 目标、同对照）。

| 口径 | 一期 | 二期本机（中位数口径，两轮） |
|---|---|---|
| 引擎级（一期原口径：DialTCP 直连 vs 对照 mixed） | 0.51–0.57 | **1.20**（441.1 vs 368.9 MiB/s）、**0.89**（403.0 vs 451.2） |
| 数据面级（二期新增更严口径：plane Start 全路径 vs 对照 Start 全路径） | —（优化前单样本 0.44） | **0.95**（333.5 vs 352.4）、**1.60**（419.9 vs 262.2） |

数据面级口径曾测得 0.44，定位为中继层 io.Copy 32 KiB 默认
缓冲 + 计数包装层，换池化 64 KiB 计数拷贝后达线。
结论：**G6 在两个口径上均过 0.70 门线**（本机跑批；CI 复核
待主会话拾取）。剩余说明：绝对值随共享 CPU 波动，判定以
同轮比值中位数为准；真实网络下的长肥管道表现不在环回口径
内，属后续真机事项。

## 3. 数据面差分逐项（diffrig/phase2_test.go）

- G1/G2 数据面复跑（TestRigDataPlaneTCP）：7 方法 × sing-box
  服务端全量、多轮回声 / 4 MiB 大载荷 / 半关闭后完整响应 /
  32 并发连接，另 rust 服务端 × 3 代表方法同集；自研 plane 与
  对照逐字节一致，全过。半关闭语义：客户端 CloseWrite 后
  响应完整到达（依赖 §4 的修复才成立于服务端先结束方向）。
- 路由行为（TestRigDataPlaneRouting）：block 双面拒绝（回复码
  差异见 §1 裁决）；direct 规则绕开已死节点直连成功（同目标
  走代理则失败，反证路由真实生效）；IPv6 关闭拒 v6 字面量。
- DNS 分离验收（TestRigDataPlaneDNSSeparation）：假 DNS 双路
  计数实测——直连域名只出现在本地解析器、代理域名只出现在
  出口侧解析器、IP 阶段域名只经隧道远端解析；三类抓取均成功
  且解析器串话为零。此即 Step 11 泄漏验收在自研面的等价复跑。
- UDP 数据面（TestRigDataPlaneUDP）：SOCKS ASSOCIATE 经
  plane 转发，512 B 与 32 KiB 数据报、3 方法，与对照同集；
  本机 UDP 环回被拦 Skip，CI 实跑。
- G4 错误与终止（TestRigDataPlaneErrors）：目标拒绝 = 数据
  阶段失败双面对齐；错密码双面零交付（自研面本地引擎拒绝、
  对照面其内部超时，分类同为失败）。
- 服务端中途死亡（TestRigDataPlaneMidStreamDeath）：杀真实
  ssserver 进程后，同一连接上双面均立即以 EOF 呈现（修复后
  plane ≈17µs、对照 ≈20µs；引擎单独 ≈10µs）。本项抓到并修复
  了一个真实缺陷，见 §4。
- NEG-04 时间戳行为级（TestRigTimestampWindow）：自研客户端
  时钟偏移 +2h 后，TCP 与 UDP 均被双参考服务端拒绝（TCP 腿
  本机通过；UDP 腿本机 Skip、CI 实跑）。一期「只验字段不验
  行为」的挂账就此销账（UDP 以 CI 为准）。
- NEG-07 UDP 重放（TestRigUDPReplay2022）：中继抓包后原样
  重放，自研客户端与对照客户端各一腿，断言服务端窗口丢弃
  重放包（无回声、后续正常包不受影响）。本机 Skip，CI 实跑。
- Start 纪律（TestRigDataPlaneStartDiscipline）：状态机
  （Running / ActiveBackend=selfdev / 节点 ID / 混合入站地址）、
  流量计数增长、TUN 回 sing-box 且在本构建如实拒绝、
  kill switch 门双后端同 verdict、plugin 节点不进 plane，
  全过。

## 4. 本期抓到的真实缺陷（已修复）

bufferedConn 半关闭委托缺失：plane 中继靠对入站连接调用
CloseWrite 传播结束信号；bufferedConn 内嵌的是 net.Conn
**接口**，接口内嵌不提升接口外的方法，CloseWrite 类型断言
在每条入站连接上静默失败——响应方向结束时 FIN 永不发出，
对端只能等自己的读超时（实测挂满 15 s）。客户端先半关闭的
方向因断言对象是引擎连接而正常，故一期与本期半关闭场景
未能暴露，反向（服务端先结束 / 中途死亡）才现形。修复：
bufferedConn 显式 CloseWrite/CloseRead 委托 + 包级回归
单测钉住。教训与一期 append-only 向量同类：**静默 no-op 的
类型断言是本代码库的复发风险点**，后续审查应专项扫
`.(interface{ ... })` 的失败路径是否可观测。

诊断副产物（如实记录）：进程内 sing-box 服务端的 Close 是
软停——已建立 socket 在 Close 后数秒内仍开着，不能充当
「服务端死亡」的测试替身；死亡场景必须用真实进程
（ssserver）击杀。此为台架知识，非产品缺陷。

## 4.5 CI 首跑红灯定性（2026-11-23，run 45130226476）

二期 CI 首跑：九项中仅 core 作业红，失败步为
「Test selfdev differential rig」，其余八项全绿。失败测试
只有一个：`TestRigDataPlaneUDP` 的三个方法子测试
（aes-256-gcm / 2022-blake3-aes-256-gcm /
2022-blake3-chacha20-poly1305），签名完全一致：
`udp echo mismatch … from=<回声服务器> bytes=4090`
（32 KiB 交换，512 B 交换通过）。本机 UDP 环回被沙箱
拦截、二期 UDP 腿在本机 Skip，此为该批测试第一次实跑。

**定性：引擎真缺陷（自研转发层），非台架、非环境。**

根因（`core/selfdev/forward.go` 的 `handleUDPPacket`）：
载荷偏移由 `bufio.Reader.Buffered()` 推导——bufio 默认
缓冲 4096 字节，IPv4 地址占 6 字节，4096−6=**4090**，
与失败字节数逐字吻合。超过 4096 字节的数据报，其载荷
被静默切成报文的最后 4090 字节；地址解析本身正确
（from 与目标一致），512 B 交换因全包小于缓冲而无恙，
三种加密方法同签名（缺陷在明文 SOCKS 层，与密码学
无关）。修复：新增 `parseSocksAddrBytes` 在原始报文上
按地址长度显式解析，偏移只由地址长度决定；回归单测
`TestParseSocksAddrBytesPayloadOffset`（32 KiB 载荷 ×
IPv4/IPv6/域名三形态 + 短包拒绝）钉住。

取证过程留档：为定位失败腿与尺寸阈值，台架先行仪表化
（commit 484bc64：分 direct/plane/control 三腿、尺寸
阶梯 512–32768、每尺寸独立关联、失配报共同前缀长；
判定标准未放宽）。该次运行（45133109765）的 core 作业
在第 6 步被既有 flake `TestAuthFailureClassification`
（openvpn 进程台时序，基线约 1/10，与本缺陷无关，
openvpn 包对 selfdev 零依赖已核）打断，未跑到差分步；
但根因由日志签名 + 代码算术已闭合确证，修复后的 CI
复跑即为确认（仪表化保留为常设诊断）。

回填（2026-11-23）：修复提交的 CI 复跑未全绿——同一步
再次红灯，但签名已变（4090 截断消失），定性见 §4.6。

## 4.6 CI 第二次红灯定性（2026-11-23，run 45133519326）

修复提交 e92ea38 的复跑：九项中仍仅 core 作业红，失败步
仍是「Test selfdev differential rig」，失败测试仍只有
`TestRigDataPlaneUDP` 三个方法子测试——但**签名与首跑
完全不同**，不许沿用 §4.5 结论，逐项对比如下：

| | 首跑（99b25cf） | 复跑（e92ea38） |
|---|---|---|
| 尺寸集 | {512, 32768}，plane/control 两腿，Fatalf | 阶梯 {512…32768}，direct/plane/control 三腿，Errorf |
| 签名 | 回声失配：32 KiB 回声只回 4090 字节 | 16384 与 32768 两档在**三腿全部** i/o timeout；服务端逐包记 `cipher: message authentication failed` |
| 根因层 | 自研转发层（明文 SOCKS 偏移） | 对照实现（sing-box）的 UDP 接收包络 |
| 4090 签名 | 有 | **无**（e92ea38 修复已生效的直接证据） |

**定性：台架包络问题——测试把单数据报尺寸推过了对照
实现的接收上限，非引擎缺陷、非环境噪声。** 证据链：

1. **纯对照腿同签名失败**：control 腿是 sing-box 客户端
   栈对 sing-box 服务端，自研代码不在路径上，同样在
   16384 起 timeout。若是自研缺陷，对照腿不应同病。
2. **服务端日志逐包对应**：sing-box 服务端对每个超限
   数据报记一条 AEAD 认证失败（2017 为 `serve UDP …
   cipher: message authentication failed`，2022-AES 为
   `decrypt packet`，2022-ChaCha 为 `decrypt packet
   header`），即包已到达、但在解密前已被截断。
3. **源码常量吻合**：sing-box v1.14.4 的全部 UDP 监听器
   （shadowsocks 入站与 mixed 入站共用
   `common/listener/listener_udp.go`）把数据报读入
   `buf.NewPacket()`，其容量为 sing 的 `UDPBufferSize =
   16 * 1024`（`sing/common/buf/buffer_standard.go`；
   CI 标签不含 low_memory，该变体为 8 KiB）。16384 字节
   载荷的线上数据报（加盐/地址/标签 ≥16439 字节）必然
   超限被截断后 AEAD 失败被丢弃；8192 档线上约 8.3 KiB，
   在限内——阈值与实测逐档吻合。
4. **自研侧无此上限**：自研 PacketConn 与转发层各跳读
   缓冲均为 65535/64 KiB（packet.go、forward.go），echo
   服务器为 64 KiB；G6 吞吐哨兵不在本步日志内出现，
   已排除。
5. 首跑之所以只见 4090 签名：缺陷转发层在加密前先把
   载荷切到 4090 字节，发出的是合法小包，服务端包络
   从未被触及；且 Fatalf 在 plane 腿先行终止，control
   腿的大尺寸档未及运行。本轮仪表化（484bc64）保留，
   其分腿/分档输出正是本次定性的取证基础——诊断价值
   已兑现，常设成本仅为失败时的日志量，裁决保留。

**修复（台架侧，判定不放宽）**：`TestRigDataPlaneUDP`
重构为服务器 × 腿矩阵，常量 `singboxUDPRefWireCap =
16 * 1024` 连同源码出处写入测试注释：

- 小尺寸 {512, 4096, 8192}：两台服务器（sing-box 与
  shadowsocks-rust）× 三腿，逐字节一致要求不变；
- 大尺寸 {16384, 32768} 对 rust 服务器：direct 与
  plane 两腿（自研所拥有的腿）逐字节一致——自研栈的大
  数据报能力改由能接收全尺寸数据报的独立实现作证；
  control 腿对大尺寸无定义域（其 mixed 入站用同一
  16 KiB 缓冲读 SOCKS 数据报，16384 载荷 = 16394 字节
  在对照内部先被截断），理由写入测试注释；
- 大尺寸对 sing-box 服务器：direct 腿改为**边界探针**——
  断言服务端丢弃（读超时且必须是 timeout 类错误）。
  这不是跳过：它把对照包络钉成可失败的断言，未来
  sing-box 若放大缓冲，本探针会红，迫使矩阵被有意
  更新，而不是悄悄放宽；
- 顺带修掉 direct 腿的既有台架瑕疵：一腿一律改为每
  次交换独立 deadline（旧形状全程共用一个 15 秒
  deadline，首个 timeout 会让后续 write 直接吃过期
  deadline 报错，复跑日志中 32768 档的 write timeout
  即此伪影）。

本机验证：编译/vet/gofmt 净；本机 UDP 环回被沙箱拦截，
UDP 腿按既有口径 Skip，实跑结论待 CI（主会话拾取后
回填）。另记：本机全包跑批中 `TestRigDataPlaneDNSSeparation`
曾出现一次 0.00s 瞬时红，隔离重跑与基线对照均绿，
与本次改动无涉（改动不触 DNS 路径），按既有 flake
口径观察。

## 4.7 CI 第三次红灯定性（2026-11-23，run 45136593588）

010a7ce 的复跑：`TestRigDataPlaneUDP` 已通过（§4.6 的
16 KiB 包络矩阵重构生效），其余套件全过；新红两条，
签名互不相同，逐项定性如下。两条均为**台架缺陷**，
引擎与判定口径均未动。

### (a) TestRigDataPlaneDNSSeparation：端口冲突（0.00s）

签名：`phase2_test.go:451: listen tcp 127.0.0.1:33564:
bind: address already in use`，测试在 setup 阶段瞬时
失败。§4.6 末尾记录的本机同测试 0.00s 瞬时红即同一
缺陷——两度出现，按本节裁决销掉「flake 观察」。

**根因**：`startFakeDNS` 需要 UDP/TCP 同端口，先以
UDP `:0` 抽端口、再在同号绑 TCP。但两个传输的临时
端口空间彼此独立：UDP 抽到的号可能已被本进程内其他
TCP 监听或尚未释放完的连接占用（台架进程长寿、套接
字 churn 高），此时 TCP bind 直接 EADDRINUSE。与前序
测试监听是否释放干净无关——占用者可以是任意时刻的
任意 TCP 套接字。

**修复（台架侧）**：改为「抽到双传输同号都绑上为止」：
UDP 抽号后试绑 TCP，失败即关掉 UDP 另抽，上限 50 次；
绑成的端口对在服务器整个生命周期内由本测试持有，
返回地址不可能再与任何套接字相撞。本机证明：该测试
隔离连跑 ×20 全过，diffrig 整包实跑两遍全过。

### (b) TestRigStructural2022：抓包短 134 字节

签名：`rig_test.go:643: structural mismatch: captured
16505 bytes, vector 16639 bytes`。按差分纪律先逐块做
chunk map 对比，证据链：

1. **向量 chunk map**（解密解析）：盐 32 + 固定头
   （varLen=13）+ 变长头 13 B + 载荷块 [16383][100]
   = 16639；拼接载荷 16483 B 与输入载荷逐字节一致。
2. **引擎字节生产无责**：当前代码的单元向量测试
   `TestVectorsWire2022TCP/W22-05a` 逐字节复现该流；
   以哑上游（沉默/读完即关/先回话）替换真实服务端的
   隔离抓包实验 9/9 与向量逐字节一致。
3. **截断形状钉死**：换上真实 ssserver 后，同一隔
   离实验 6 跑中 1 跑精确复现 CI 签名 16505（−134）；
   本机原测试另见 88 字节（只有序言）的截断。所有截
   断抓包都是向量的**前缀**、且恰停在块边界——16505
   = 序言 + 第一块，缺的 134 字节恰是尾块的线上长度。
   引擎若丢载荷，截断点不会随服务端拆连接时机在块
   边界间漂移；同轮 G1/G2 回声（含 4 MiB）逐字节全
   过，亦证载荷无丢失/重复/错位。
4. **缺陷本体**：抓包中继 `io.Copy(MultiWriter(up,
   &buf), c)` 把记录与转发耦合：先写上游、后记账，
   且任一写错误即终止整条复制。ssserver 因目标侧关
   闭而中途拆连接时，正在转发的那一批字节绕过抓包
   缓冲被丢弃，复制随即结束——客户端发出的字节，是
   记录器没记下来。

**修复（台架侧，断言不放宽）**：中继改为记录优先：
从客户端读到的字节先入抓包缓冲，再尽力转发；转发
写失败只标记上游已死、继续排空客户端至 EOF，
`done` 以客户端 EOF 为准。结构层判定**维持原始逐字
节相等**——证据表明引擎在记录器可靠时确定性地满足
它，没有理由把 G3 降为解析后比对。本机证明：结构
测试（2017+2022）连跑 ×20 全过（修复前本机约 2/5
概率红），selfdev 全套两遍全绿。

## 5. 一期挂账销账表

| 挂账 | 状态 |
|---|---|
| G6 未达线 0.51–0.57 | **销账**：双口径过线（§2），CI 复核待拾取 |
| UDP G1/G2 本机未跑 | 一期已由 CI run 45125369812 销账；二期 UDP 数据面腿已由 CI run 45130226476 首跑：抓到引擎真缺陷（§4.5）；复跑（run 45133519326）证实修复生效（4090 签名消失），同时暴露对照实现 16 KiB 接收包络，台架矩阵已按 §4.6 重构，大尺寸改对 rust 服务器作证 + sing-box 边界探针，CI 确认待拾取 |
| NEG-04 只验字段 | **销账**：TCP 本机 + UDP 由 CI run 45130226476 行为级拒绝实测 |
| NEG-07 UDP 重放 | **销账**：CI run 45130226476 实跑通过（服务端日志见预期的 packet id not unique 拒绝） |
| G5 长时 fuzz（≥8h/目标） | 不在本包（发布候选阶段），继续挂账 |
| 默认化（auto 成默认） | 不在本包：仍须全门禁 + 一个 Beta 周期灰度；默认档保持 singbox |

## 6. 剩余风险与未覆盖面（如实列）

1. **TUN 形态未与自研面组合**：TUN 下全部流量仍走 sing-box，
   自研档在 TUN 场景等于未启用（route 决策 + 日志原因如实）。
   TUN 组合（TUN 入站接 plane 转发）是后续独立工作包。
2. **system-proxy 模式**同上，留 sing-box。
3. **策略面缺口**：含 protocol 嗅探 / process 匹配 / 非 inline
   规则集的策略在自研档下 Start 即拒绝（分类错误、不静默）。
   覆盖这三类需在 core 层补嗅探与进程归属能力，另行立项。
4. **fake-ip 手动开启场景未覆盖**（默认关口径对齐）。
5. **plane 无 DNS 缓存**：与对照的重复查询行为不同（§1）。
6. **移动端（libbox/Android）未与 selfdev 组合**：本包接线在
   桌面 core 的 kernel.Component 路径；Android 侧 Start 路径
   未动，自研档在移动端暂不生效，需单独接线与真机验证。
7. **UDP 关联生命周期差异**：plane 以（源地址 + 空闲超时
   2 分钟）管理关联，对照（sing-box）以 SOCKS 控制连接存续
   为准；控制连接断开后 plane 的关联最迟在空闲超时回收，
   期间仍可收发。行为差异如实记录，是否对齐待后续裁决。
8. **长连接/长肥管道未测**：数据面差分最长为 4 MiB 回声与
   并发短连接；小时级长连接的稳定性不在本包证据内（与 G5
   同属发布候选阶段的长稳口径）。
9. CI 判决（含全部 UDP 腿、NEG-07、G6 的 CI 复测）由主会话
   拾取后回填本记录；在 CI 结论落地前，本机绿不等于门禁
   全关。
