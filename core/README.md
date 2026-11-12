# core — 内核适配层（Step 6 交付，待评审）

本目录是《开源全协议代理客户端》方案书（`docs/项目方案书-v0.1.md`）阶段 0
**Step 6「内核适配层接口定版」**的交付物：接口定义 + 假实现（mock）。
状态为**待评审**：接口在 Step 6 评审通过前不算冻结。

模块路径 `openproxy/core` 是**中性占位**：项目名尚未定版（方案书
Step 1 待拍板），正式路径在 Step 4 建仓时随组织名定版后统一替换。

工具链实测（2026-11-12，本机 `~/tools/go`，go1.23.12 linux/amd64）：

```
go vet ./...    # 无告警
go build ./...  # 通过
go test ./...   # ok openproxy/core/kernel; ok openproxy/core/kernel/mock（全过）
```

## 目录

| 路径 | 内容 |
|---|---|
| `kernel/adapter.go` | `Adapter` 接口（本步核心交付） |
| `kernel/config.go` | 占位节点模型 `Node`、`Config`、`PlatformOptions`（见下方 Step 5 对接说明） |
| `kernel/capabilities.go` | `Capabilities` 能力矩阵与平台能力 |
| `kernel/status.go` | 生命周期状态 `State`、`Status`、`TrafficStats`、`HandshakeResult`、`ExitInfo` |
| `kernel/errors.go` | 结构化错误 `Error` / `Kind` 与 `IsKind` / `KindOf` |
| `kernel/validate.go` | 共享校验语义 `ValidateNode` / `ValidateAgainst` |
| `kernel/mock/` | 内存假内核 `mock.Mock`，实现全部接口方法，行为可配置 |
| `kernel/*_test.go`、`kernel/mock/*_test.go` | 单元测试 |

## 与方案书 5.3 的对应表

| 方案书 5.3 最小集 | 本接口 | 变化 |
|---|---|---|
| `ValidateConfig(model) → errors` | `Adapter.ValidateConfig(ctx, *Config) error` | 加 context；多错误聚合改为单个结构化 `*Error`（分类见错误约定），UI 展示首个错误即可 |
| `Start(model, platformOptions)` | `Adapter.Start(ctx, *Config, PlatformOptions) error` | 加 context |
| `Stop()` / `Status()` | `Adapter.Stop(ctx) error` / `Adapter.Status() Status` | Stop 加 context 且幂等；Status 返回结构化快照而非裸状态 |
| `TestHandshake(node) → latency, error` | `Adapter.TestHandshake(ctx, *Node) (*HandshakeResult, error)` | latency 扩展为结果结构（延迟、成败、错误分类、可选出口信息）；握手失败是结果而非 Go error（见方法语义） |
| `QueryTraffic() → up, down` | `Adapter.QueryTraffic(ctx) (*TrafficStats, error)` | 扩展为累计字节 + 采样时间 + 会话起始时间 |
| `Capabilities() → protocolMatrix` | `Adapter.Capabilities() Capabilities` | 矩阵结构化为 协议×传输×安全层，并增加平台能力与特性集 |

接口不引用任何具体内核（sing-box、Xray、SoftEther 等）的类型；具体内核
只能出现在适配层**之后**的实现包里（Step 7 起）。方案书第 6 章的自研替换
也必须经本接口逐个替换，且保留回退——接口即替换面。

## 方法语义

- **Capabilities()**：永不失败、必须廉价。未列入矩阵的组合即不支持；
  UI 据此灰化，禁止静默失败（5.3 原文要求）。
- **ValidateConfig(ctx, cfg)**：两层校验——先结构校验（必填、范围、
  Reality 必须带 publicKey 等，见 `ValidateNode`），再按本适配器
  Capabilities 做支持性校验。前者失败为 `invalid_config`，后者为
  `unsupported`。返回 nil 表示结构合法且本内核支持。
- **Start(ctx, cfg, opts)**：先做与 ValidateConfig 相同的校验；校验不过
  状态不变。当前状态为 running/starting/stopping 时返回 `wrong_state`。
  选项要求的平台能力不可用时（TUN 不可用、kill switch 不可强制）返回
  `platform_unavailable`，**不允许**降级静默运行。成功返回时状态为
  running。
- **Stop(ctx)**：幂等。idle/stopped 时调用是无操作；running/failed 时
  落到 stopped。stopped/failed 之后可再次 Start（重启/重试）。
- **Status()**：不阻塞、不失败的快照，含状态、进入时间、当前节点 ID、
  运行模式、最近一次致 failed 的错误。
- **TestHandshake(ctx, node)**：必须是**真实协议握手**，禁止以 ICMP
  ping 冒充（5.3、15 章原文）。握手失败返回
  `HandshakeResult{OK:false, Error: handshake_failed}` 且 Go error 为
  nil；Go error 只用于「测试本身无法进行」：节点结构非法
  （`invalid_config`）、组合不支持（`unsupported`）、context 取消
  （`canceled`/`timeout`）。
- **QueryTraffic(ctx)**：返回当前会话（运行中）或最近会话（已停止）
  的累计计数；从未运行过返回零值，上述情况均不返回 error。

## 错误约定

错误统一为 `kernel.Error{Kind, Op, Message, Err}`，调用方用
`kernel.IsKind(err, kernel.KindX)` 或 `kernel.KindOf(err)` 分类，
**不得**解析错误文案做逻辑判断（文案只供日志与诊断）。

| Kind | 含义 | 典型触发 |
|---|---|---|
| `invalid_config` | 配置结构非法，用户可改 | 空 server、端口越界、未知协议、Reality 缺公钥 |
| `unsupported` | 结构合法但本内核不支持该组合 | 矩阵外 协议×传输×安全层 |
| `platform_unavailable` | 所需平台能力缺失 | TUN 不可用、kill switch 不可强制、VPN 权限缺失 |
| `handshake_failed` | 真实握手失败 | 节点不可达、拒绝、凭据错误（出现在 HandshakeResult 内） |
| `network` | 本地网络操作失败 | 监听绑定失败、控制面拨号失败 |
| `wrong_state` | 当前状态不允许该操作 | running 时再次 Start |
| `timeout` / `canceled` | 超时 / context 取消 | 与 context 原生错误互通 |
| `internal` | 内核内部错误 | 视为缺陷，细节在包裹的 cause 中 |

裸 `context.Canceled` / `context.DeadlineExceeded` 会被 `KindOf`
自动归类为 `canceled` / `timeout`。

## 生命周期状态机

```
idle ──Start──▶ starting ──ok──▶ running ──Stop──▶ stopping ──▶ stopped
                  │                                  ▲
                  └──fail──▶ failed ─────Stop────────┘
stopped ──Start──▶ starting（允许重启）
failed  ──Start──▶ starting（允许重试）
```

Stop 对 idle/stopped 为无操作。同步实现（如 mock）可以瞬间经过
starting/stopping，这两个状态不保证能被 Status 观察到。

## mock 假内核

`kernel/mock.Mock` 全内存实现，无任何网络 I/O，行为由 `mock.Options`
决定，面向 UI 并行开发与后续差分测试脚手架：

- `HandshakeLatency`：模拟握手耗时，同时作为上报延迟；等待尊重
  context 取消。
- `FailNodeIDs` / `FailProtocols`：指定必失败的握手（失败进结果，
  不进 Go error）。
- `HandshakeExit`：成功握手时附带的出口信息（IP/国家/ASN）。
- `StartError`：每次 Start 模拟内部失败 → 状态 failed、
  `Status().LastError` 可见。
- `UploadRateBps` / `DownloadRateBps`：运行期间流量按速率累积，
  Stop 后冻结。
- `Capabilities`：不填则用 `mock.DefaultCapabilities()`——方案书 4.1
  第一梯队全矩阵 + SoftEther；**故意不含 L2TP/SSTP**（系统编排类），
  方便 UI 演练不支持组合的灰化。

## UI 侧接入示例（基于 mock）

```go
package main

import (
	"context"
	"fmt"
	"time"

	"openproxy/core/kernel"
	"openproxy/core/kernel/mock"
)

func main() {
	ctx := context.Background()

	// 1. 开发期用 mock；Step 7 起换成真实适配器，UI 代码不动。
	var adapter kernel.Adapter = mock.New(mock.Options{
		HandshakeLatency: 80 * time.Millisecond,
		HandshakeExit:    &kernel.ExitInfo{IP: "203.0.113.7", Country: "JP"},
	})

	// 2. 用能力矩阵渲染节点编辑界面：不支持的组合直接灰化。
	caps := adapter.Capabilities()
	fmt.Println("vless+tcp+reality 可选:",
		caps.Supports(kernel.ProtocolVLESS, kernel.TransportTCP, kernel.SecurityReality))

	node := &kernel.Node{
		ID: "n1", Name: "示例", Protocol: kernel.ProtocolVLESS,
		Server: "example.com", Port: 443,
		Credential: kernel.Credential{UUID: "…", Flow: "xtls-rprx-vision"},
		Transport:  kernel.Transport{Type: kernel.TransportTCP},
		Security:   kernel.Security{Type: kernel.SecurityReality, PublicKey: "…"},
	}

	// 3. 测活：失败看结果，不看 Go error。
	res, err := adapter.TestHandshake(ctx, node)
	if err != nil {
		// 测试本身没跑起来：按 kernel.KindOf(err) 分类提示
		fmt.Println("测活未执行:", kernel.KindOf(err))
	} else if res.OK {
		fmt.Printf("可用，延迟 %v，出口 %s\n", res.Latency, res.Exit.Country)
	} else {
		fmt.Println("不可用:", res.Error.Kind) // handshake_failed
	}

	// 4. 连接与状态、流量。
	cfg := &kernel.Config{Node: node}
	if err := adapter.ValidateConfig(ctx, cfg); err != nil {
		fmt.Println("配置有误:", err)
		return
	}
	if err := adapter.Start(ctx, cfg,
		kernel.PlatformOptions{Mode: kernel.ModeTUN, KillSwitch: true}); err != nil {
		fmt.Println("启动失败:", kernel.KindOf(err))
		return
	}
	fmt.Println("状态:", adapter.Status().State) // running
	ts, _ := adapter.QueryTraffic(ctx)
	fmt.Printf("流量 up=%d down=%d\n", ts.UploadBytes, ts.DownloadBytes)
	_ = adapter.Stop(ctx)
}
```

## Step 5 模型对接说明（重要）

`kernel/config.go` 中的 `Node` 等类型是**最小占位**：字段取自方案书
5.2 示意模型的子集。统一节点模型的权威定义是 Step 5 的 `spec/`
JSON Schema（与本步并行进行，落盘后为准）。Step 5 定版后的对接
替换点：

1. `kernel/config.go`：`Node` 及嵌套的 `Credential` / `Transport` /
   `Security` / `Source` 整体替换为（或由）spec 模型生成；JSON 字段
   名以 Schema 为准；
2. `kernel/validate.go`：`ValidateNode` 的字段规则按 Schema 重导；
3. 接口方法签名（`Adapter`）不因模型对接而变——变的只是模型类型
   本身。这正是占位类型集中放在单一文件的原因。

在对接完成前，**不得**在本包自行新增节点字段；字段增减走 Step 5
Schema / RFC 流程（方案书 5.2）。

## 相对方案书 5.3 的扩展清单（评审时请逐项确认）

1. 全部阻塞方法加 `context.Context`——取消与超时是 UI 并行开发的
   刚需，5.3 未写不等于禁止。
2. 结构化错误分类 `Kind`——5.3 只写「errors」，UI 需要可编程分类
   才能做分级提示与多语言。
3. `Capabilities` 增加平台能力与特性集——5.4 的平台要点（TUN、
   kill switch、VPN 权限）必须有自报出口，否则 Start 只能静默降级，
   与 5.3「禁止静默失败」冲突。
4. 握手失败归结果、执行失败归 Go error——便于 UI 批量测活时把
   「节点不行」与「程序不行」分开呈现。
5. `Status` 增加 `LastError` 与 `Mode`、`TrafficStats` 增加会话
   元数据——连接页与诊断页的最低需求，不增加适配器实现负担
   （mock 已证明）。
6. 生命周期增加 `failed` 状态与「Stop 幂等、stopped/failed 可再
   Start」语义——5.3 未定义失败后状态，UI 无法据此画状态机，故在本
   步补齐并写入状态机图，待评审追认。
